package socks5

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestClientUDPReadUsesHeadroomForSocks5Header(t *testing.T) {
	payload := []byte{0x84, 0x01, 0x02, 0x03}
	raw := NewDatagram(
		ATYPIPv4,
		[]byte{127, 0, 0, 1},
		[]byte{0x4a, 0xbc},
		payload,
	).Bytes()
	client := &Client{UDPConn: stubPacketConn{readData: raw}}

	buf := make([]byte, len(payload))
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("Read error = %v", err)
	}
	if n != len(payload) {
		t.Fatalf("Read n = %d, want %d", n, len(payload))
	}
	if string(buf) != string(payload) {
		t.Fatalf("Read payload = %v, want %v", buf, payload)
	}
}

func TestClientUDPReadReportsShortBufferAfterUnwrapping(t *testing.T) {
	payload := []byte{0x84, 0x01, 0x02, 0x03}
	raw := NewDatagram(
		ATYPIPv4,
		[]byte{127, 0, 0, 1},
		[]byte{0x4a, 0xbc},
		payload,
	).Bytes()
	client := &Client{UDPConn: stubPacketConn{readData: raw}}

	buf := make([]byte, len(payload)-1)
	n, err := client.Read(buf)
	if !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("Read error = %v, want %v", err, io.ErrShortBuffer)
	}
	if n != len(buf) {
		t.Fatalf("Read n = %d, want %d", n, len(buf))
	}
	if string(buf) != string(payload[:len(buf)]) {
		t.Fatalf("Read payload prefix = %v, want %v", buf, payload[:len(buf)])
	}
}

func TestClientRemoteAddrDefaultsToTargetAddress(t *testing.T) {
	oldDialTCP := DialTCP
	oldDialUDP := DialUDP
	defer func() {
		DialTCP = oldDialTCP
		DialUDP = oldDialUDP
	}()

	client, server := net.Pipe()
	defer server.Close()
	serveErr := serveSocksRequest(server, CmdUDP, true)

	DialTCP = func(network string, laddr, raddr string) (net.Conn, error) {
		return client, nil
	}
	DialUDP = func(network string, laddr, raddr string) (net.Conn, error) {
		return stubPacketConn{remoteAddr: stringAddr{network: "udp", address: "127.0.0.1:9999"}}, nil
	}

	c, err := NewClient("127.0.0.1:1080", "", "", 0, 0)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	conn, err := c.Dial("udp", "127.0.0.1:19132")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	if got := conn.RemoteAddr().String(); got != "127.0.0.1:19132" {
		t.Fatalf("RemoteAddr() = %q, want target address", got)
	}
	if err := <-serveErr; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestResolveClientRemoteAddr(t *testing.T) {
	addr := resolveClientRemoteAddr("udp", "127.0.0.1:19132")
	if got := addr.String(); got != "127.0.0.1:19132" {
		t.Fatalf("addr.String() = %q, want 127.0.0.1:19132", got)
	}
	if got := addr.Network(); got != "udp" {
		t.Fatalf("addr.Network() = %q, want udp", got)
	}

	domain := resolveClientRemoteAddr("udp", "example.com:19132")
	if got := domain.String(); got != "example.com:19132" {
		t.Fatalf("domain addr.String() = %q, want example.com:19132", got)
	}
}

type stubPacketConn struct {
	remoteAddr net.Addr
	readData   []byte
}

func (s stubPacketConn) Read(b []byte) (int, error) {
	return copy(b, s.readData), nil
}

func (s stubPacketConn) Write([]byte) (int, error) {
	return 0, nil
}

func (s stubPacketConn) Close() error {
	return nil
}

func (s stubPacketConn) LocalAddr() net.Addr {
	return nil
}

func (s stubPacketConn) RemoteAddr() net.Addr {
	return s.remoteAddr
}

func (s stubPacketConn) SetDeadline(time.Time) error {
	return nil
}

func (s stubPacketConn) SetReadDeadline(time.Time) error {
	return nil
}

func (s stubPacketConn) SetWriteDeadline(time.Time) error {
	return nil
}
