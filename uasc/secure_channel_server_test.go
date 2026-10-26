// Copyright 2018-2020 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package uasc

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	"github.com/gopcua/opcua/id"
	uatest "github.com/gopcua/opcua/tests/python"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uacp"
	"github.com/gopcua/opcua/uapolicy"
	"github.com/stretchr/testify/require"
)

type testIdentity struct {
	cert []byte
	key  *rsa.PrivateKey
}

func newTestIdentity(t *testing.T) testIdentity {
	t.Helper()
	certPEM, keyPEM, err := uatest.GenerateCert("localhost", 2048, 24*time.Hour)
	require.NoError(t, err)
	kb, _ := pem.Decode(keyPEM)
	key, err := x509.ParsePKCS1PrivateKey(kb.Bytes)
	require.NoError(t, err)
	cb, _ := pem.Decode(certPEM)
	return testIdentity{cert: cb.Bytes, key: key}
}

func (i testIdentity) public(t *testing.T) *rsa.PublicKey {
	t.Helper()
	c, err := x509.ParseCertificate(i.cert)
	require.NoError(t, err)
	return c.PublicKey.(*rsa.PublicKey)
}

// A server decrypts the first OpenSecureChannel chunk before it has read
// the channel's security mode out of it, so its channel config still says
// None. The chunk's own asymmetric header is what says whether it is
// secured.
func TestVerifyAndDecryptSecuredOPNOnUnconfiguredServerChannel(t *testing.T) {
	client, server := newTestIdentity(t), newTestIdentity(t)

	for _, uri := range ua.SecurityPolicyURIs {
		if uri == ua.SecurityPolicyURINone {
			continue
		}
		t.Run(uri, func(t *testing.T) {
			clientAlgo, err := uapolicy.Asymmetric(uri, client.key, server.public(t))
			require.NoError(t, err)
			serverAlgo, err := uapolicy.Asymmetric(uri, server.key, client.public(t))
			require.NoError(t, err)

			sender := &channelInstance{
				sc:   &SecureChannel{cfg: &Config{SecurityPolicyURI: uri, SecurityMode: ua.MessageSecurityModeSignAndEncrypt}},
				algo: clientAlgo,
			}
			// The server's config before the handshake: the defaults a
			// server channel is created with.
			receiver := &channelInstance{
				sc:   &SecureChannel{cfg: &Config{SecurityPolicyURI: ua.SecurityPolicyURINone, SecurityMode: ua.MessageSecurityModeNone}},
				algo: serverAlgo,
			}

			m := &Message{
				MessageHeader: &MessageHeader{
					Header:                   &Header{MessageType: MessageTypeOpenSecureChannel, ChunkType: ChunkTypeFinal},
					AsymmetricSecurityHeader: NewAsymmetricSecurityHeader(uri, client.cert, uapolicy.Thumbprint(server.cert)),
					SequenceHeader:           NewSequenceHeader(1, 1),
				},
				TypeID: ua.NewFourByteExpandedNodeID(0, id.OpenSecureChannelRequest_Encoding_DefaultBinary),
				Service: &ua.OpenSecureChannelRequest{
					RequestHeader:     &ua.RequestHeader{AuthenticationToken: ua.NewTwoByteNodeID(0), AdditionalHeader: ua.NewExtensionObject(nil)},
					SecurityMode:      ua.MessageSecurityModeSignAndEncrypt,
					ClientNonce:       bytes.Repeat([]byte{0xab}, 32),
					RequestedLifetime: 3600000,
				},
			}
			plain, err := m.Encode()
			require.NoError(t, err)
			cipher, err := sender.signAndEncrypt(m, plain)
			require.NoError(t, err)

			chunk := new(MessageChunk)
			_, err = chunk.Decode(cipher)
			require.NoError(t, err)

			got, err := receiver.verifyAndDecrypt(chunk, cipher)
			require.NoError(t, err)
			headerLength := 12 + chunk.AsymmetricSecurityHeader.Len()
			require.Equal(t, plain[headerLength:], got, "a secured OPN must decrypt on a server channel still configured as None")
		})
	}

	t.Run("an OPN under policy None is handed over untouched", func(t *testing.T) {
		receiver := &channelInstance{
			sc: &SecureChannel{cfg: &Config{SecurityPolicyURI: ua.SecurityPolicyURINone, SecurityMode: ua.MessageSecurityModeNone}},
		}
		m := &Message{
			MessageHeader: &MessageHeader{
				Header:                   &Header{MessageType: MessageTypeOpenSecureChannel, ChunkType: ChunkTypeFinal},
				AsymmetricSecurityHeader: NewAsymmetricSecurityHeader(ua.SecurityPolicyURINone, nil, nil),
				SequenceHeader:           NewSequenceHeader(1, 1),
			},
			TypeID: ua.NewFourByteExpandedNodeID(0, id.OpenSecureChannelRequest_Encoding_DefaultBinary),
			Service: &ua.OpenSecureChannelRequest{
				RequestHeader:     &ua.RequestHeader{AuthenticationToken: ua.NewTwoByteNodeID(0), AdditionalHeader: ua.NewExtensionObject(nil)},
				SecurityMode:      ua.MessageSecurityModeNone,
				RequestedLifetime: 3600000,
			},
		}
		b, err := m.Encode()
		require.NoError(t, err)
		chunk := new(MessageChunk)
		_, err = chunk.Decode(b)
		require.NoError(t, err)
		got, err := receiver.verifyAndDecrypt(chunk, b)
		require.NoError(t, err)
		require.Equal(t, chunk.Data, got)
	})
}

// loopback is a client and a server secure channel over one TCP connection
// on the loopback interface. The server's Receive loop runs until the
// context ends; every request it reads that is not the OPN is handed to
// requests.
type loopback struct {
	client, server *SecureChannel
	requests       chan ua.Request
}

func newLoopback(t *testing.T, ctx context.Context, clientCfg, serverCfg *Config) *loopback {
	t.Helper()
	l, err := uacp.Listen(ctx, "opc.tcp://127.0.0.1:0", nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	endpoint := fmt.Sprintf("opc.tcp://%s", l.Addr())

	lb := &loopback{requests: make(chan ua.Request, 8)}
	accepted := make(chan *SecureChannel, 1)
	go func() {
		conn, err := l.Accept(ctx)
		if err != nil {
			close(accepted)
			return
		}
		sc, err := NewServerSecureChannel(endpoint, conn, serverCfg, make(chan error, 1), 7, 1, 11)
		if err != nil {
			close(accepted)
			return
		}
		accepted <- sc
		for {
			msg := sc.Receive(ctx)
			if msg.Err != nil {
				return
			}
			if req := msg.Request(); req != nil {
				lb.requests <- req
			}
		}
	}()

	conn, err := uacp.Dial(ctx, endpoint)
	require.NoError(t, err)
	lb.client, err = NewSecureChannel(endpoint, conn, clientCfg, make(chan error, 1))
	require.NoError(t, err)
	t.Cleanup(func() { _ = lb.client.Close() })

	select {
	case lb.server = <-accepted:
		require.NotNil(t, lb.server, "the server did not accept the connection")
	case <-time.After(5 * time.Second):
		t.Fatal("the server did not accept the connection")
	}
	return lb
}

// A server opens a signed and encrypted channel from the defaults it is
// created with, takes the mode and the client's certificate from the
// request, answers encrypted for that certificate, and reads the symmetric
// traffic that follows.
func TestServerSecureChannelOpensSignAndEncrypt(t *testing.T) {
	client, server := newTestIdentity(t), newTestIdentity(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverCfg := &Config{
		SecurityPolicyURI: ua.SecurityPolicyURINone,
		SecurityMode:      ua.MessageSecurityModeNone,
		Certificate:       server.cert,
		LocalKey:          server.key,
		Lifetime:          3600000,
	}
	clientCfg := &Config{
		SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
		SecurityMode:      ua.MessageSecurityModeSignAndEncrypt,
		Certificate:       client.cert,
		LocalKey:          client.key,
		RemoteCertificate: server.cert,
		Thumbprint:        uapolicy.Thumbprint(server.cert),
		Lifetime:          3600000,
		RequestTimeout:    5 * time.Second,
	}
	lb := newLoopback(t, ctx, clientCfg, serverCfg)

	require.NoError(t, lb.client.Open(ctx), "the secured handshake")

	require.Equal(t, ua.MessageSecurityModeSignAndEncrypt, lb.server.cfg.SecurityMode, "the server took the mode from the request")
	require.Equal(t, ua.SecurityPolicyURIBasic256Sha256, lb.server.cfg.SecurityPolicyURI)
	require.Equal(t, client.cert, lb.server.cfg.RemoteCertificate, "the server holds the client's certificate")
	require.Equal(t, uapolicy.Thumbprint(client.cert), lb.server.cfg.Thumbprint,
		"the server's OPN response is addressed to the client's certificate")

	// The symmetric keys agree: a request sent over the opened channel
	// decodes on the server.
	req := &ua.GetEndpointsRequest{EndpointURL: lb.client.endpointURL}
	require.NoError(t, lb.client.SendRequest(ctx, req, nil, nil))
	select {
	case got := <-lb.requests:
		ep, ok := got.(*ua.GetEndpointsRequest)
		require.True(t, ok, "server decoded %T", got)
		require.Equal(t, lb.client.endpointURL, ep.EndpointURL)
	case <-time.After(5 * time.Second):
		t.Fatal("the server did not decode the request sent over the opened channel")
	}
}
