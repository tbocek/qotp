package tomtp

import (
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"
)

type NetworkConn interface {
	ReadFromUDPAddrPort(p []byte, timeout time.Duration) (n int, remoteAddr netip.AddrPort, err error)
	CancelRead() error
	CanWriteUDP() (bool, error)
	WriteToUDPAddrPort(p []byte, remoteAddr netip.AddrPort) (n int, err error)
	Close() error
	LocalAddrString() string
}

type UDPNetworkConn struct {
	conn *net.UDPConn
	mu   sync.Mutex
}

func NewUDPNetworkConn(conn *net.UDPConn) NetworkConn {
	return &UDPNetworkConn{
		conn: conn,
		mu:   sync.Mutex{},
	}
}

func (c *UDPNetworkConn) ReadFromUDPAddrPort(p []byte, timeout time.Duration) (int, netip.AddrPort, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	deadline := time.Time{}
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	err := c.conn.SetReadDeadline(deadline)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	n, a, err := c.conn.ReadFromUDPAddrPort(p)

	return n, a, err
}

func (c *UDPNetworkConn) CancelRead() error {
	return c.conn.SetReadDeadline(time.Time{})
}

func (c *UDPNetworkConn) CanWriteUDP() (bool, error) {
	// Get the underlying file descriptor
	file, err := c.conn.File()
	if err != nil {
		return false, err
	}
	defer file.Close()

	fd := int(file.Fd())

	// Use select() to check if socket is ready for writing
	fdSet := &syscall.FdSet{}
	fdSet.Bits[fd/64] |= 1 << (uint(fd) % 64)

	timeout := &syscall.Timeval{Sec: 0, Usec: 0} // Non-blocking

	n, err := syscall.Select(fd+1, nil, fdSet, nil, timeout)
	if err != nil {
		return false, err
	}

	return n > 0, nil
}

func (c *UDPNetworkConn) WriteToUDPAddrPort(p []byte, remoteAddr netip.AddrPort) (int, error) {
	return c.conn.WriteToUDPAddrPort(p, remoteAddr)
}

func (c *UDPNetworkConn) Close() error {
	return c.conn.Close()
}

func (c *UDPNetworkConn) LocalAddrString() string {
	return c.conn.LocalAddr().String()
}
