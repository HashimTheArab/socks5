package socks5

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

const maxUDPDatagramSize = 65535

// Client is socks5 client wrapper
type Client struct {
	Server   string
	UserName string
	Password string
	// On cmd UDP, let server control the tcp and udp connection relationship
	TCPConn       net.Conn
	UDPConn       net.Conn
	RemoteAddress net.Addr
	TCPTimeout    int
	UDPTimeout    int
	Dst           string
	addrMu        sync.RWMutex
}

// This is just create a client, you need to use Dial to create conn
func NewClient(addr, username, password string, tcpTimeout, udpTimeout int) (*Client, error) {
	c := &Client{
		Server:     addr,
		UserName:   username,
		Password:   password,
		TCPTimeout: tcpTimeout,
		UDPTimeout: udpTimeout,
	}
	return c, nil
}

func (c *Client) Dial(network, addr string) (net.Conn, error) {
	return c.DialWithLocalAddr(network, "", addr, nil)
}

func (c *Client) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return c.DialWithLocalAddrContext(ctx, network, "", addr, nil)
}

// If you want to send address that expects to use to send UDP, just assign it to src, otherwise it will send zero address.
// Recommend specifying the src address in a non-NAT environment, and leave it blank in other cases.
func (c *Client) DialWithLocalAddr(network, src, dst string, remoteAddr net.Addr) (net.Conn, error) {
	return c.dialWithLocalAddr(context.Background(), network, src, dst, remoteAddr, false)
}

func (c *Client) DialWithLocalAddrContext(ctx context.Context, network, src, dst string, remoteAddr net.Addr) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	return c.dialWithLocalAddr(ctx, network, src, dst, remoteAddr, true)
}

func (c *Client) dialWithLocalAddr(ctx context.Context, network, src, dst string, remoteAddr net.Addr, useContext bool) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if useContext {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	c = &Client{
		Server:        c.Server,
		UserName:      c.UserName,
		Password:      c.Password,
		TCPTimeout:    c.TCPTimeout,
		UDPTimeout:    c.UDPTimeout,
		Dst:           dst,
		RemoteAddress: remoteAddr,
	}
	if c.RemoteAddress == nil {
		c.RemoteAddress = resolveClientRemoteAddr(network, dst)
	}
	var err error
	if network == "tcp" {
		var laddr net.Addr
		if src != "" {
			laddr, err = net.ResolveTCPAddr("tcp", src)
			if err != nil {
				return nil, err
			}
		}
		if err := c.negotiateForDial(ctx, laddr, useContext); err != nil {
			return nil, err
		}
		dialSucceeded := false
		defer func() {
			if !dialSucceeded {
				_ = c.Close()
			}
		}()
		a, h, p, err := ParseAddress(dst)
		if err != nil {
			return nil, err
		}
		if a == ATYPDomain {
			h = h[1:]
		}
		if _, err := c.requestForDial(ctx, useContext, NewRequest(CmdConnect, a, h, p)); err != nil {
			return nil, err
		}
		dialSucceeded = true
		return c, nil
	}
	if network == "udp" {
		var laddr net.Addr
		if src != "" {
			laddr, err = net.ResolveTCPAddr("tcp", src)
			if err != nil {
				return nil, err
			}
		}
		if err := c.negotiateForDial(ctx, laddr, useContext); err != nil {
			return nil, err
		}
		dialSucceeded := false
		defer func() {
			if !dialSucceeded {
				_ = c.Close()
			}
		}()

		a, h, p := ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00}
		if src != "" {
			a, h, p, err = ParseAddress(src)
			if err != nil {
				return nil, err
			}
			if a == ATYPDomain {
				h = h[1:]
			}
		}
		rp, err := c.requestForDial(ctx, useContext, NewRequest(CmdUDP, a, h, p))
		if err != nil {
			return nil, err
		}
		if useContext {
			c.UDPConn, err = DialUDPContext(ctx, "udp", src, rp.Address())
		} else {
			c.UDPConn, err = DialUDP("udp", src, rp.Address())
		}
		if err != nil {
			return nil, contextError(ctx, err)
		}
		if useContext {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		if c.UDPTimeout != 0 {
			if err := c.UDPConn.SetDeadline(time.Now().Add(time.Duration(c.UDPTimeout) * time.Second)); err != nil {
				return nil, err
			}
		}
		dialSucceeded = true
		return c, nil
	}
	return nil, errors.New("unsupport network")
}

func (c *Client) negotiateForDial(ctx context.Context, laddr net.Addr, useContext bool) error {
	if useContext {
		return c.NegotiateContext(ctx, laddr)
	}
	return c.Negotiate(laddr)
}

func (c *Client) requestForDial(ctx context.Context, useContext bool, r *Request) (*Reply, error) {
	if !useContext {
		return c.Request(r)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stopCancel := closeOnContextCancel(ctx, c.TCPConn)
	rp, err := c.Request(r)
	canceled := stopCancel()
	if err != nil {
		return nil, contextError(ctx, err)
	}
	if canceled {
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return rp, nil
}

func (c *Client) Read(b []byte) (int, error) {
	if c.UDPConn == nil {
		return c.TCPConn.Read(b)
	}
	raw := make([]byte, maxUDPDatagramSize)
	n, err := c.UDPConn.Read(raw)
	if err != nil {
		return 0, err
	}
	d, err := NewDatagramFromBytes(raw[0:n])
	if err != nil {
		return 0, err
	}
	c.pinUDPDestination(d)
	if len(d.Data) > len(b) {
		copy(b, d.Data[:len(b)])
		return len(b), io.ErrShortBuffer
	}
	return copy(b, d.Data), nil
}

func (c *Client) Write(b []byte) (int, error) {
	if c.UDPConn == nil {
		return c.TCPConn.Write(b)
	}
	a, h, p, err := ParseAddress(c.udpDestination())
	if err != nil {
		return 0, err
	}
	if a == ATYPDomain {
		h = h[1:]
	}
	d := NewDatagram(a, h, p, b)
	b1 := d.Bytes()
	n, err := c.UDPConn.Write(b1)
	if err != nil {
		return 0, err
	}
	if len(b1) != n {
		return 0, errors.New("not write full")
	}
	return len(b), nil
}

func (c *Client) Close() error {
	if c.UDPConn == nil {
		if c.TCPConn == nil {
			return nil
		}
		return c.TCPConn.Close()
	}
	if c.TCPConn != nil {
		c.TCPConn.Close()
	}
	return c.UDPConn.Close()
}

func (c *Client) LocalAddr() net.Addr {
	if c.UDPConn == nil {
		return c.TCPConn.LocalAddr()
	}
	return c.UDPConn.LocalAddr()
}

func (c *Client) RemoteAddr() net.Addr {
	c.addrMu.RLock()
	remoteAddress := c.RemoteAddress
	c.addrMu.RUnlock()
	if remoteAddress != nil {
		return remoteAddress
	}
	if c.UDPConn != nil {
		return c.UDPConn.RemoteAddr()
	}
	if c.TCPConn != nil {
		return c.TCPConn.RemoteAddr()
	}
	return nil
}

func (c *Client) udpDestination() string {
	c.addrMu.RLock()
	dst := c.Dst
	c.addrMu.RUnlock()
	return dst
}

func (c *Client) pinUDPDestination(d *Datagram) {
	dst := d.Address()
	if dst == "" {
		return
	}
	c.addrMu.Lock()
	defer c.addrMu.Unlock()
	if !shouldPinUDPDestination(c.Dst, dst) {
		return
	}
	c.Dst = dst
	network := "udp"
	if c.RemoteAddress != nil {
		network = c.RemoteAddress.Network()
	}
	c.RemoteAddress = resolveClientRemoteAddr(network, dst)
}

func shouldPinUDPDestination(current, received string) bool {
	if current == "" || received == "" {
		return false
	}
	host, _, err := net.SplitHostPort(current)
	if err != nil {
		return false
	}
	return net.ParseIP(host) == nil
}

func (c *Client) SetDeadline(t time.Time) error {
	if c.UDPConn == nil {
		return c.TCPConn.SetDeadline(t)
	}
	return c.UDPConn.SetDeadline(t)
}

func (c *Client) SetReadDeadline(t time.Time) error {
	if c.UDPConn == nil {
		return c.TCPConn.SetReadDeadline(t)
	}
	return c.UDPConn.SetReadDeadline(t)
}

func (c *Client) SetWriteDeadline(t time.Time) error {
	if c.UDPConn == nil {
		return c.TCPConn.SetWriteDeadline(t)
	}
	return c.UDPConn.SetWriteDeadline(t)
}

func (c *Client) Negotiate(laddr net.Addr) error {
	src := ""
	if laddr != nil {
		src = laddr.String()
	}
	var err error
	c.TCPConn, err = DialTCP("tcp", src, c.Server)
	if err != nil {
		return err
	}
	if err := c.negotiate(); err != nil {
		_ = c.TCPConn.Close()
		return err
	}
	return nil
}

func (c *Client) NegotiateContext(ctx context.Context, laddr net.Addr) error {
	if ctx == nil {
		ctx = context.Background()
	}
	src := ""
	if laddr != nil {
		src = laddr.String()
	}
	var err error
	c.TCPConn, err = DialTCPContext(ctx, "tcp", src, c.Server)
	if err != nil {
		return contextError(ctx, err)
	}
	stopCancel := closeOnContextCancel(ctx, c.TCPConn)
	err = c.negotiate()
	canceled := stopCancel()
	if err != nil {
		_ = c.TCPConn.Close()
		return contextError(ctx, err)
	}
	if canceled {
		_ = c.TCPConn.Close()
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		_ = c.TCPConn.Close()
		return err
	}
	return nil
}

func (c *Client) negotiate() error {
	if c.TCPTimeout != 0 {
		if err := c.TCPConn.SetDeadline(time.Now().Add(time.Duration(c.TCPTimeout) * time.Second)); err != nil {
			return err
		}
	}
	m := MethodNone
	if c.UserName != "" && c.Password != "" {
		m = MethodUsernamePassword
	}
	rq := NewNegotiationRequest([]byte{m})
	if _, err := rq.WriteTo(c.TCPConn); err != nil {
		return err
	}
	rp, err := NewNegotiationReplyFrom(c.TCPConn)
	if err != nil {
		return err
	}
	if rp.Method != m {
		return errors.New("Unsupport method")
	}
	if m == MethodUsernamePassword {
		urq := NewUserPassNegotiationRequest([]byte(c.UserName), []byte(c.Password))
		if _, err := urq.WriteTo(c.TCPConn); err != nil {
			return err
		}
		urp, err := NewUserPassNegotiationReplyFrom(c.TCPConn)
		if err != nil {
			return err
		}
		if urp.Status != UserPassStatusSuccess {
			return ErrUserPassAuth
		}
	}
	return nil
}

func closeOnContextCancel(ctx context.Context, c io.Closer) func() bool {
	if ctx == nil || ctx.Done() == nil || c == nil {
		return func() bool { return false }
	}
	done := make(chan struct{})
	stopped := make(chan struct{})
	closed := make(chan struct{}, 1)
	go func() {
		defer close(stopped)
		select {
		case <-ctx.Done():
			_ = c.Close()
			closed <- struct{}{}
		case <-done:
		}
	}()
	return func() bool {
		close(done)
		<-stopped
		select {
		case <-closed:
			return true
		default:
			return false
		}
	}
}

func contextError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
	}
	return err
}

func resolveClientRemoteAddr(network, address string) net.Addr {
	host, portRaw, err := net.SplitHostPort(address)
	if err != nil {
		return stringAddr{network: network, address: address}
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return stringAddr{network: network, address: address}
	}
	port, err := strconv.Atoi(portRaw)
	if err != nil {
		return stringAddr{network: network, address: address}
	}
	switch network {
	case "udp", "udp4", "udp6":
		return &net.UDPAddr{IP: ip, Port: port}
	case "tcp", "tcp4", "tcp6":
		return &net.TCPAddr{IP: ip, Port: port}
	default:
		return stringAddr{network: network, address: address}
	}
}

type stringAddr struct {
	network string
	address string
}

func (a stringAddr) Network() string {
	return a.network
}

func (a stringAddr) String() string {
	return a.address
}

func (c *Client) Request(r *Request) (*Reply, error) {
	if _, err := r.WriteTo(c.TCPConn); err != nil {
		return nil, err
	}
	rp, err := NewReplyFrom(c.TCPConn)
	if err != nil {
		return nil, err
	}
	if rp.Rep != RepSuccess {
		return nil, errors.New("Host unreachable")
	}
	return rp, nil
}
