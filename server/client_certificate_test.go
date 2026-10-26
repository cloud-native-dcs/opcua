// Copyright 2018-2020 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package server_test

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server"
	uatest "github.com/gopcua/opcua/tests/python"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uacp"
)

type identity struct {
	cert []byte
	key  *rsa.PrivateKey
}

func newIdentity(t *testing.T) identity {
	t.Helper()
	certPEM, keyPEM, err := uatest.GenerateCert("localhost", 2048, 24*time.Hour)
	require.NoError(t, err)
	kb, _ := pem.Decode(keyPEM)
	key, err := x509.ParsePKCS1PrivateKey(kb.Bytes)
	require.NoError(t, err)
	cb, _ := pem.Decode(certPEM)
	return identity{cert: cb.Bytes, key: key}
}

// recorder is a verifier that remembers every certificate it was asked
// about and refuses them all while refuse is set.
type recorder struct {
	mu     sync.Mutex
	seen   [][]byte
	refuse bool
}

func (r *recorder) verify(cert []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, append([]byte(nil), cert...))
	if r.refuse {
		return errors.New("not in the trusted list")
	}
	return nil
}

func (r *recorder) asked() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]byte(nil), r.seen...)
}

func (r *recorder) setRefuse(v bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refuse = v
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

type policy struct {
	uri  string
	mode ua.MessageSecurityMode
}

func startServer(t *testing.T, srvID identity, verify server.ClientCertificateVerifier, policies ...policy) (*server.Server, string) {
	t.Helper()
	port := freePort(t)
	opts := []server.Option{
		server.EndPoint("127.0.0.1", port),
		server.Certificate(srvID.cert),
		server.PrivateKey(srvID.key),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
	}
	for _, p := range policies {
		opts = append(opts, server.EnableSecurity(p.uri, p.mode))
	}
	if verify != nil {
		opts = append(opts, server.VerifyClientCertificate(verify))
	}
	s := server.New(opts...)
	require.NoError(t, s.Start(context.Background()))
	t.Cleanup(func() { _ = s.Close() })
	return s, fmt.Sprintf("opc.tcp://127.0.0.1:%d", port)
}

// connect opens a client under the given policy, presenting cl's
// certificate when it has one, and returns the client or the error Connect
// gave.
func connect(t *testing.T, endpoint string, p policy, cl *identity) (*opcua.Client, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	eps, err := opcua.GetEndpoints(ctx, endpoint)
	require.NoError(t, err)
	ep, err := opcua.SelectEndpoint(eps, p.uri, p.mode)
	require.NoError(t, err)
	opts := []opcua.Option{
		opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous),
		opcua.AuthAnonymous(),
		opcua.RequestTimeout(3 * time.Second),
		opcua.AutoReconnect(false),
	}
	if cl != nil {
		opts = append(opts, opcua.Certificate(cl.cert), opcua.PrivateKey(cl.key))
	}
	c, err := opcua.NewClient(endpoint, opts...)
	require.NoError(t, err)
	if err := c.Connect(ctx); err != nil {
		return nil, err
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer ccancel()
		_ = c.Close(cctx)
	})
	return c, nil
}

var (
	secured   = policy{"Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt}
	plaintext = policy{"None", ua.MessageSecurityModeNone}
)

// On a secured channel the verifier is asked at OpenSecureChannel, before
// any session exists. A refusal reaches the client as the ERR message the
// server sent before closing the connection, carrying
// Bad_CertificateUntrusted, and the server holds no session for it. A
// certificate the verifier accepts opens a session the server can name.
func TestVerifyClientCertificateAtOpenSecureChannel(t *testing.T) {
	srvID, clID := newIdentity(t), newIdentity(t)
	rec := &recorder{refuse: true}
	srv, endpoint := startServer(t, srvID, rec.verify, secured)

	_, err := connect(t, endpoint, secured, &clID)
	require.Error(t, err, "a refused certificate opened a channel")
	require.True(t, errors.Is(err, ua.StatusBadCertificateUntrusted), "refused with %v", err)
	var uacpErr *uacp.Error
	require.True(t, errors.As(err, &uacpErr), "the refusal was an ERR message at the channel, got %T: %v", err, err)
	require.Equal(t, [][]byte{clID.cert}, rec.asked(), "the verifier was asked once, about the client's certificate")
	require.Empty(t, srv.Sessions(), "a refused client holds no session")

	rec.setRefuse(false)
	before := time.Now()
	c, err := connect(t, endpoint, secured, &clID)
	require.NoError(t, err, "an accepted certificate connects")

	// The channel works: a read over it answers.
	resp, err := c.Read(context.Background(), &ua.ReadRequest{
		NodesToRead: []*ua.ReadValueID{{NodeID: ua.NewNumericNodeID(0, id.Server_ServerStatus_CurrentTime), AttributeID: ua.AttributeIDValue}},
	})
	require.NoError(t, err)
	require.Len(t, resp.Results, 1)
	require.Equal(t, ua.StatusOK, resp.Results[0].Status)

	sessions := srv.Sessions()
	require.Len(t, sessions, 1, "one session is held")
	require.NotNil(t, sessions[0].ID)
	require.Equal(t, clID.cert, sessions[0].ClientCertificate, "the session names the certificate behind it")
	require.False(t, sessions[0].Created.Before(before), "created at %v, connected after %v", sessions[0].Created, before)
	require.False(t, sessions[0].Created.After(time.Now()))

	cctx, ccancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer ccancel()
	require.NoError(t, c.Close(cctx))
	require.Empty(t, srv.Sessions(), "a closed session is gone")
}

// On a channel under policy None nothing is asked at OpenSecureChannel,
// so the verifier's one question is at CreateSession, about the
// ClientCertificate the request carries, which may be empty. A refusal is a
// ServiceFault with Bad_CertificateUntrusted, and the session is never
// created.
func TestVerifyClientCertificateAtCreateSession(t *testing.T) {
	srvID, clID := newIdentity(t), newIdentity(t)
	rec := &recorder{refuse: true}
	srv, endpoint := startServer(t, srvID, rec.verify, plaintext)

	_, err := connect(t, endpoint, plaintext, &clID)
	require.Error(t, err, "a refused certificate created a session")
	require.True(t, errors.Is(err, ua.StatusBadCertificateUntrusted), "refused with %v", err)
	var uacpErr *uacp.Error
	require.False(t, errors.As(err, &uacpErr), "the refusal was a service fault, not an ERR message: %v", err)
	require.Equal(t, [][]byte{clID.cert}, rec.asked())
	require.Empty(t, srv.Sessions(), "a refused session was never created")

	// A client presenting no certificate is asked about none.
	_, err = connect(t, endpoint, plaintext, nil)
	require.True(t, errors.Is(err, ua.StatusBadCertificateUntrusted), "refused with %v", err)
	asked := rec.asked()
	require.Len(t, asked, 2)
	require.Empty(t, asked[1], "the verifier was asked about the absent certificate")

	rec.setRefuse(false)
	_, err = connect(t, endpoint, plaintext, &clID)
	require.NoError(t, err)
	sessions := srv.Sessions()
	require.Len(t, sessions, 1)
	require.Equal(t, clID.cert, sessions[0].ClientCertificate)
}

// Without a verifier every certificate is accepted, which is what the
// server did before the option existed.
func TestNoVerifierAcceptsEveryCertificate(t *testing.T) {
	srvID, clID := newIdentity(t), newIdentity(t)
	srv, endpoint := startServer(t, srvID, nil, secured)
	_, err := connect(t, endpoint, secured, &clID)
	require.NoError(t, err)
	require.Len(t, srv.Sessions(), 1)
}
