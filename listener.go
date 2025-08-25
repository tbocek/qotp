package qotp

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/netip"

	"sync"
	"sync/atomic"
)

// Wrapper for your original use case
type ConnStreamIterator struct {
	*NestedIterator[uint64, uint32, *Connection, *Stream]
}

func NewConnStreamIterator(connMap *LinkedMap[uint64, *Connection]) *ConnStreamIterator {
	return &ConnStreamIterator{NewNestedIterator(
		connMap,
		func(conn *Connection) *LinkedMap[uint32, *Stream] {
			return conn.streams
		},
	)}
}

type Listener struct {
	// this is the port we are listening to
	localConn NetworkConn
	prvKeyId  *ecdh.PrivateKey                //never nil
	connMap   *LinkedMap[uint64, *Connection] // here we store the connection to remote peers, we can have up to
	iter      *ConnStreamIterator
	closed    bool
	mu        sync.Mutex
}

type ListenOption struct {
	seed      *[32]byte
	prvKeyId  *ecdh.PrivateKey
	localConn NetworkConn
}

type ListenFunc func(*ListenOption) error

func WithSeed(seed [32]byte) ListenFunc {
	return func(o *ListenOption) error {
		if o.seed != nil {
			return errors.New("seed already set")
		}
		o.seed = &seed
		return nil
	}
}

func WithNetworkConn(localConn NetworkConn) ListenFunc {
	return func(o *ListenOption) error {
		o.localConn = localConn
		return nil
	}
}

func WithPrvKeyId(prvKeyId *ecdh.PrivateKey) ListenFunc {
	return func(o *ListenOption) error {
		if o.prvKeyId != nil {
			return errors.New("prvKeyId already set")
		}
		if prvKeyId == nil {
			return errors.New("prvKeyId not set")
		}

		o.prvKeyId = prvKeyId
		return nil
	}
}

func WithSeedStrHex(seedStrHex string) ListenFunc {
	return func(o *ListenOption) error {
		if o.seed != nil {
			return errors.New("seed already set")
		}

		seed, err := decodeHex(seedStrHex)
		if len(seed) != 32 {
			return errors.New("seed must be exactly 32 bytes")
		}
		if err != nil {
			return err
		}
		copy(o.seed[:], seed)
		return nil
	}
}

func WithSeedStr(seedStr string) ListenFunc {
	return func(o *ListenOption) error {
		if o.seed != nil {
			return errors.New("seed already set")
		}

		hashSum := sha256.Sum256([]byte(seedStr))
		o.seed = &hashSum
		return nil
	}
}

func ListenString(listenAddrStr string, options ...ListenFunc) (*Listener, error) {
	listenAddr, err := net.ResolveUDPAddr("udp", listenAddrStr)
	if err != nil {
		return nil, err
	}
	return Listen(listenAddr, options...)
}

func fillListenOpts(listenAddr *net.UDPAddr, options ...ListenFunc) (*ListenOption, error) {
	lOpts := &ListenOption{
		seed:     nil,
		prvKeyId: nil,
	}
	for _, opt := range options {
		err := opt(lOpts)
		if err != nil {
			return nil, err
		}
	}

	if lOpts.seed != nil {
		prvKeyId, err := ecdh.X25519().NewPrivateKey(lOpts.seed[:])
		if err != nil {
			return nil, err
		}
		lOpts.prvKeyId = prvKeyId
	}
	if lOpts.prvKeyId == nil {
		prvKeyId, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		lOpts.prvKeyId = prvKeyId
	}
	if lOpts.localConn == nil {
		conn, err := net.ListenUDP("udp", listenAddr)
		if err != nil {
			return nil, err
		}

		err = setDontFragment(conn)
		if err != nil {
			return nil, err
		}

		lOpts.localConn = NewUDPNetworkConn(conn)
	}

	return lOpts, nil
}

func Listen(listenAddr *net.UDPAddr, options ...ListenFunc) (*Listener, error) {
	lOpts, err := fillListenOpts(listenAddr, options...)
	if err != nil {
		return nil, err
	}

	l := &Listener{
		localConn: lOpts.localConn,
		prvKeyId:  lOpts.prvKeyId,
		connMap:   NewLinkedMap[uint64, *Connection](),
		mu:        sync.Mutex{},
	}

	slog.Info(
		"Listen",
		slog.Any("listenAddr", lOpts.localConn.LocalAddrString()),
		slog.String("pubKeyId", "0x"+hex.EncodeToString(l.prvKeyId.PublicKey().Bytes()[:3])+"…"))

	return l, nil
}

func (l *Listener) Close() error {
	slog.Debug("ListenerClose", getGoroutineID())
	l.mu.Lock()
	defer l.mu.Unlock()

	l.closed = true

	for _, conn := range l.connMap.items {
		conn.value.Close()
	}

	err := l.localConn.TimeoutReadNow()
	if err != nil {
		return err
	}
	return l.localConn.Close()
}

func (l *Listener) Listen(timeoutNano uint64, nowNano uint64) (s *Stream, err error) {
	data := make([]byte, startMtu)
	n, remoteAddr, err := l.localConn.ReadFromUDPAddrPort(data, timeoutNano, nowNano)

	if err != nil {
		var netErr net.Error
		ok := errors.As(err, &netErr)

		if ok && netErr.Timeout() {
			slog.Debug("   Listen/Timeout")
			return nil, nil // Timeout is normal, return no dataToSend/error
		} else {
			slog.Error("   Listen/Error", slog.Any("error", err))
			return nil, err
		}
	}
	if n == 0 {
		slog.Debug("   Listen/NoData")
		return nil, nil
	}

	slog.Debug("   Listen/Data", getGoroutineID(), l.debug(), slog.Any("len(data)", n), slog.Uint64("now:ms", nowNano/msNano))

	conn, m, err := l.decode(data[:n], remoteAddr)
	if err != nil {
		return nil, err
	}

	s, err = conn.decode(m.PayloadRaw, n, nowNano)
	if err != nil {
		return nil, err
	}

	//Set state
	if !conn.state.isHandshakeComplete {
		if conn.state.isSender {
			if m.MsgType == InitRcv || m.MsgType == InitCryptoRcv {
				conn.state.isHandshakeComplete = true
			}
		} else {
			if m.MsgType == Data || m.MsgType == DataRoll {
				conn.state.isHandshakeComplete = true
			}
		}
	}

	return s, nil
}

// Flush sends pending data for all connections using round-robin
func (l *Listener) Flush(nowNano uint64) (minPacing uint64, err error) {
	minPacing = MinDeadLine
	if l.connMap.Size() == 0 {
		//if we do not have at least one connection, exit
		return minPacing, nil
	}

	if l.iter == nil {
		l.iter = NewConnStreamIterator(l.connMap)
	}

	var startK1 *uint64
	var startK2 *uint32
	closeStream := []connStreamKey{}

	for {
		conn, stream := l.iter.Next()
		if conn == nil {
			break
		}

		if startK1 == nil && startK2 == nil {
			startK1 = l.iter.currentOuterKey
			startK2 = l.iter.currentInnerKey //startK2 can be null
		}

		if stream != nil {
			_, dataSent, pacingNano, err := conn.Flush(stream, nowNano)
			if err != nil {
				conn.cleanupConn(conn.connId)
				return 0, err
			}

			if stream.state == StreamStateClosed {
				// stream closed, mark for cleaning up, do not clean up yet, otherwise the iterator will become
				// much more complex
				closeStream = append(closeStream, createConnStreamKey(conn.connId, stream.streamID))
			}

			if dataSent > 0 {
				// data sent, returning early
				minPacing = 0
				break
			}

			if pacingNano < minPacing {
				minPacing = pacingNano
			}
		}

		if *startK1 == *l.iter.nextOuterKey && *startK2 == *l.iter.nextInnerKey {
			break
		}
	}

	for _, connStreamKey := range closeStream {
		conn := l.connMap.Get(connStreamKey.connID())
		conn.cleanupStream(connStreamKey.streamID())
	}
	return minPacing, nil
}

func (l *Listener) newConn(
	remoteAddr netip.AddrPort,
	prvKeyEpSnd *ecdh.PrivateKey,
	prvKeyEpSndRollover *ecdh.PrivateKey,
	pubKeyIdRcv *ecdh.PublicKey,
	pubKeyEdRcv *ecdh.PublicKey,
	pubKeyEpRcvRollover *ecdh.PublicKey,
	isSender bool,
	withCrypto bool) (*Connection, error) {

	connId := binary.LittleEndian.Uint64(prvKeyEpSnd.PublicKey().Bytes())                 // prvKeyEpSnd is never nil
	connIdRollover := binary.LittleEndian.Uint64(prvKeyEpSndRollover.PublicKey().Bytes()) // prvKeyEpSndRoll is never nil
	if pubKeyEdRcv != nil {
		connId = connId ^ binary.LittleEndian.Uint64(pubKeyEdRcv.Bytes()) //this is the id for regular data flow
	}
	if pubKeyEpRcvRollover != nil {
		connIdRollover = connIdRollover ^ binary.LittleEndian.Uint64(pubKeyEpRcvRollover.Bytes()) //this is the id for regular data flow
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.connMap.Contains(connId) {
		slog.Warn("conn already exists", slog.Any("connId", connId))
		return nil, errors.New("conn already exists")
	}

	conn := &Connection{
		connId:     connId,
		connIdRoll: connIdRollover,
		streams:    NewLinkedMap[uint32, *Stream](),
		remoteAddr: remoteAddr,
		keys: ConnectionKeys{
			pubKeyIdRcv:     pubKeyIdRcv,
			prvKeyEpSnd:     prvKeyEpSnd,
			prvKeyEpSndRoll: prvKeyEpSndRollover,
			pubKeyEpRcvRoll: pubKeyEpRcvRollover,
			pubKeyEpRcv:     pubKeyEdRcv,
		},
		mu:       sync.Mutex{},
		listener: l,
		state: ConnectionState{
			isSender:   isSender,
			withCrypto: withCrypto,
		},
		mtu:        startMtu,
		snd:        NewSendBuffer(sndBufferCapacity, nil),
		rcv:        NewReceiveBuffer(rcvBufferCapacity),
		BBR:        NewBBR(),
		rcvWndSize: rcvBufferCapacity, //initially our capacity, correct value will be sent to us in the 1st handshake
	}

	l.connMap.Put(connId, conn)
	return conn, nil
}

func (l *Listener) Loop(callback func(s *Stream)) func() {
	running := new(atomic.Bool)
	running.Store(true)

	go func() {
		waitNextNano := MinDeadLine
		for running.Load() {
			//Listen
			s, err := l.Listen(waitNextNano, timeNowNano())
			if err != nil {
				slog.Error("Error in loop listen", slog.Any("error", err))
			}
			if s != nil {
				callback(s) // Process received stream
			}

			//Flush
			waitNextNano, err = l.Flush(timeNowNano())

			if err != nil {
				slog.Error("Error in loop flush", slog.Any("error", err))
			}
		}
	}()

	return func() {
		running.Store(false)
	}
}

func (l *Listener) debug() slog.Attr {
	if l.localConn == nil {
		return slog.String("net", "n/a")
	}
	return slog.String("net", l.localConn.LocalAddrString())
}

func (l *Listener) ForceClose(c *Connection) {
	c.cleanupConn(c.connId)
}
