package socks5

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestClientDialContextCancelsTCPDial(t *testing.T) {
	oldDialTCPContext := DialTCPContext
	defer func() { DialTCPContext = oldDialTCPContext }()

	started := make(chan struct{})
	DialTCPContext = func(ctx context.Context, network string, laddr, raddr string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c, err := NewClient("127.0.0.1:1080", "", "", 0, 0)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	errCh := make(chan error, 1)
	go func() {
		_, err := c.DialContext(ctx, "tcp", "example.com:80")
		errCh <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("DialContext did not start TCP dial")
	}
	cancel()
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("DialContext err = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("DialContext did not unblock after context cancellation")
	}
}

func TestDialTCPContextReturnsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := DialTCPContext(ctx, "tcp", "", "example.com:80"); !errors.Is(err, context.Canceled) {
		t.Fatalf("DialTCPContext err = %v, want context.Canceled", err)
	}
}

func TestDialUDPContextReturnsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := DialUDPContext(ctx, "udp", "", "example.com:53"); !errors.Is(err, context.Canceled) {
		t.Fatalf("DialUDPContext err = %v, want context.Canceled", err)
	}
}

func TestClientDialContextCancelsNegotiation(t *testing.T) {
	oldDialTCPContext := DialTCPContext
	defer func() { DialTCPContext = oldDialTCPContext }()

	client, server := net.Pipe()
	defer server.Close()
	DialTCPContext = func(ctx context.Context, network string, laddr, raddr string) (net.Conn, error) {
		return client, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		c, err := NewClient("127.0.0.1:1080", "", "", 0, 0)
		if err != nil {
			errCh <- err
			return
		}
		_, err = c.DialContext(ctx, "tcp", "example.com:80")
		errCh <- err
	}()

	cancel()
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("DialContext err = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("DialContext did not unblock after context cancellation")
	}
}

func TestClientDialUsesLegacyTCPDialHook(t *testing.T) {
	oldDialTCP := DialTCP
	oldDialTCPContext := DialTCPContext
	defer func() {
		DialTCP = oldDialTCP
		DialTCPContext = oldDialTCPContext
	}()

	client, server := net.Pipe()
	defer server.Close()
	serveErr := serveSocksRequest(server, CmdConnect, true)

	called := false
	DialTCP = func(network string, laddr, raddr string) (net.Conn, error) {
		called = true
		return client, nil
	}
	DialTCPContext = func(ctx context.Context, network string, laddr, raddr string) (net.Conn, error) {
		return nil, errors.New("DialContext should not be used")
	}

	c, err := NewClient("127.0.0.1:1080", "", "", 0, 0)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	conn, err := c.Dial("tcp", "example.com:80")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	if !called {
		t.Fatal("Dial did not use DialTCP hook")
	}
	if err := <-serveErr; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestClientDialUsesLegacyUDPDialHook(t *testing.T) {
	oldDialTCP := DialTCP
	oldDialUDP := DialUDP
	oldDialUDPContext := DialUDPContext
	defer func() {
		DialTCP = oldDialTCP
		DialUDP = oldDialUDP
		DialUDPContext = oldDialUDPContext
	}()

	client, server := net.Pipe()
	defer server.Close()
	serveErr := serveSocksRequest(server, CmdUDP, true)

	DialTCP = func(network string, laddr, raddr string) (net.Conn, error) {
		return client, nil
	}
	called := false
	udpClient, udpServer := net.Pipe()
	defer udpServer.Close()
	DialUDP = func(network string, laddr, raddr string) (net.Conn, error) {
		called = true
		return udpClient, nil
	}
	DialUDPContext = func(ctx context.Context, network string, laddr, raddr string) (net.Conn, error) {
		return nil, errors.New("DialContext should not be used")
	}

	c, err := NewClient("127.0.0.1:1080", "", "", 0, 0)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	conn, err := c.Dial("udp", "example.com:53")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	if !called {
		t.Fatal("Dial did not use DialUDP hook")
	}
	if err := <-serveErr; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestClientDialContextCancelsRequest(t *testing.T) {
	oldDialTCPContext := DialTCPContext
	defer func() { DialTCPContext = oldDialTCPContext }()

	client, server := net.Pipe()
	defer server.Close()
	requestRead := make(chan struct{})
	serveErr := serveSocksRequestWithoutReply(server, CmdConnect, requestRead)
	DialTCPContext = func(ctx context.Context, network string, laddr, raddr string) (net.Conn, error) {
		return client, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		c, err := NewClient("127.0.0.1:1080", "", "", 0, 0)
		if err != nil {
			errCh <- err
			return
		}
		_, err = c.DialContext(ctx, "tcp", "example.com:80")
		errCh <- err
	}()

	select {
	case <-requestRead:
	case <-time.After(time.Second):
		t.Fatal("server did not receive SOCKS request")
	}
	cancel()
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("DialContext err = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("DialContext did not unblock after request cancellation")
	}
	if err := <-serveErr; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestClientDialClosesControlConnOnRequestError(t *testing.T) {
	oldDialTCP := DialTCP
	defer func() { DialTCP = oldDialTCP }()

	client, server := net.Pipe()
	trackedClient := &trackedConn{Conn: client, closed: make(chan struct{})}
	go func() {
		defer server.Close()
		if _, err := NewNegotiationRequestFrom(server); err != nil {
			return
		}
		if _, err := NewNegotiationReply(MethodNone).WriteTo(server); err != nil {
			return
		}
		_, _ = NewRequestFrom(server)
	}()

	DialTCP = func(network string, laddr, raddr string) (net.Conn, error) {
		return trackedClient, nil
	}

	c, err := NewClient("127.0.0.1:1080", "", "", 0, 0)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.Dial("tcp", "example.com:80"); err == nil {
		t.Fatal("expected dial error")
	}
	select {
	case <-trackedClient.closed:
	case <-time.After(time.Second):
		t.Fatal("control connection was not closed after request error")
	}
}

func TestClientDialClosesControlConnOnNegotiationError(t *testing.T) {
	oldDialTCP := DialTCP
	defer func() { DialTCP = oldDialTCP }()

	client, server := net.Pipe()
	trackedClient := &trackedConn{Conn: client, closed: make(chan struct{})}
	go func() {
		defer server.Close()
		if _, err := NewNegotiationRequestFrom(server); err != nil {
			return
		}
		_, _ = NewNegotiationReply(MethodUsernamePassword).WriteTo(server)
	}()

	DialTCP = func(network string, laddr, raddr string) (net.Conn, error) {
		return trackedClient, nil
	}

	c, err := NewClient("127.0.0.1:1080", "", "", 0, 0)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.Dial("tcp", "example.com:80"); err == nil {
		t.Fatal("expected dial error")
	}
	select {
	case <-trackedClient.closed:
	case <-time.After(time.Second):
		t.Fatal("control connection was not closed after negotiation error")
	}
}

func serveSocksRequestWithoutReply(conn net.Conn, wantCmd byte, afterRequest chan<- struct{}) <-chan error {
	errCh := make(chan error, 1)
	go func() {
		defer close(errCh)
		defer conn.Close()
		if _, err := NewNegotiationRequestFrom(conn); err != nil {
			errCh <- err
			return
		}
		if _, err := NewNegotiationReply(MethodNone).WriteTo(conn); err != nil {
			errCh <- err
			return
		}
		r, err := NewRequestFrom(conn)
		if err != nil {
			errCh <- err
			return
		}
		if r.Cmd != wantCmd {
			errCh <- errors.New("unexpected SOCKS command")
			return
		}
		close(afterRequest)
		var b [1]byte
		if _, err := conn.Read(b[:]); err != nil {
			errCh <- nil
			return
		}
		errCh <- errors.New("unexpected data after SOCKS request")
	}()
	return errCh
}

type trackedConn struct {
	net.Conn
	closed chan struct{}
}

func (c *trackedConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return c.Conn.Close()
}

func serveSocksRequest(conn net.Conn, wantCmd byte, reply bool, afterRequest ...chan<- struct{}) <-chan error {
	errCh := make(chan error, 1)
	go func() {
		defer close(errCh)
		defer conn.Close()
		if _, err := NewNegotiationRequestFrom(conn); err != nil {
			errCh <- err
			return
		}
		if _, err := NewNegotiationReply(MethodNone).WriteTo(conn); err != nil {
			errCh <- err
			return
		}
		r, err := NewRequestFrom(conn)
		if err != nil {
			errCh <- err
			return
		}
		if r.Cmd != wantCmd {
			errCh <- errors.New("unexpected SOCKS command")
			return
		}
		for _, ch := range afterRequest {
			close(ch)
		}
		if !reply {
			errCh <- nil
			return
		}
		_, err = NewReply(RepSuccess, ATYPIPv4, []byte{127, 0, 0, 1}, []byte{0x27, 0x0f}).WriteTo(conn)
		errCh <- err
	}()
	return errCh
}
