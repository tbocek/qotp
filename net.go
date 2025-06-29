package tomtp

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

type NetworkConn interface {
	ReadFromUDPAddrPort(p []byte, timeoutMicros uint64, nowMicros uint64) (n int, remoteAddr netip.AddrPort, err error)
	TimeoutReadNow() error
	WriteToUDPAddrPort(p []byte, remoteAddr netip.AddrPort, nowMicros uint64) (n int, err error)
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

func (c *UDPNetworkConn) ReadFromUDPAddrPort(p []byte, timeoutMicros uint64, nowMicros uint64) (int, netip.AddrPort, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	deadline := time.Time{}
	if timeoutMicros > 0 {
		deadline = time.UnixMicro(int64(nowMicros + timeoutMicros))
	}
	err := c.conn.SetReadDeadline(deadline)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	n, a, err := c.conn.ReadFromUDPAddrPort(p)

	return n, a, err
}

func (c *UDPNetworkConn) TimeoutReadNow() error {
	return c.conn.SetReadDeadline(time.Time{})
}

func (c *UDPNetworkConn) WriteToUDPAddrPort(p []byte, remoteAddr netip.AddrPort, _ uint64) (int, error) {
	return c.conn.WriteToUDPAddrPort(p, remoteAddr)
}

func (c *UDPNetworkConn) Close() error {
	return c.conn.Close()
}

func (c *UDPNetworkConn) LocalAddrString() string {
	return c.conn.LocalAddr().String()
}
