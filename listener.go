package tomtp

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

type Listener struct {
	// this is the port we are listening to
	localConn         NetworkConn
	prvKeyId          *ecdh.PrivateKey               //never nil
	connMap           *SortedMap[*uint64, *Connection] // here we store the connection to remote peers, we can have up to
	currentConnection *uint64
	closed            bool
	mu                sync.Mutex
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

		err = setDF(conn)
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
		connMap:   newConnHashMap(),
		mu:        sync.Mutex{},
	}

	slog.Info(
		"Listen",
		slog.Any("listenAddr", lOpts.localConn.LocalAddrString()),
		slog.String("pubKeyId", "0x"+hex.EncodeToString(l.prvKeyId.PublicKey().Bytes()[:3])+"…"))

	return l, nil
}

func (l *Listener) Close() error {
	slog.Debug("ListenerClose", debugGId())
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

	slog.Debug("   Listen/Data", debugGId(), l.debug(), slog.Any("len(data)", n), slog.Uint64("now:ms", nowNano/msNano))

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
			if m.MsgType == Data || m.MsgType == DataRot {
				conn.state.isHandshakeComplete = true
			}
		}
	}

	return s, nil
}

// Flush sends pending data for all connections using round-robin
func (l *Listener) Flush(nowNano uint64) (minPacing uint64, err error) {
	minPacing = MinDeadLine
	
	if l.currentConnection == nil {
		l.currentConnection, _ = l.connMap.Min()
	}
	// If no connections, return immediately
	if l.currentConnection == nil {
		return minPacing, nil
	}
	// Remember where we started
	startConn := l.currentConnection
	
	// Process each connection once
	for {
		// Process streams for current connection
		pacing, err := l.flushConnectionStreams(nowNano)
		if err != nil {
			return 0, err
		}

		if pacing < minPacing {
			minPacing = pacing
		}

		// If we sent data, return immediately for responsiveness
		if pacing == 0 {
			return 0, nil
		}
		
		// Move to next connection
		l.currentConnection, _ = l.connMap.Next(l.currentConnection)
		if l.currentConnection == nil {
			// Wrap around to beginning
			l.currentConnection, _ = l.connMap.Min()
			if l.currentConnection == nil {
				return minPacing, nil
			}
		}
		
		// Check if we've completed a full round
		if l.currentConnection == startConn {
			return minPacing, nil
		}
	}
}

// flushConnectionStreams processes all streams for the current connection
func (l *Listener) flushConnectionStreams(nowNano uint64) (uint64, error) {
	conn := l.connMap.Get(l.currentConnection)
	minPacing := MinDeadLine
	
	debug("flushX", "conn", conn, "l.currentConnection", l.currentConnection)
	
	// Initialize stream pointer if needed
	if conn.currentStream == nil {
		conn.currentStream, _ = conn.streams.Min()
	}
	if conn.currentStream == nil {
		return minPacing, nil
	}
	
	startStream := conn.currentStream
	// Process each stream once
	for {
		stream := conn.streams.Get(conn.currentStream)
		
		// Flush the current stream
		_, dataSent, pacingNano, err := conn.Flush(stream, nowNano)
		if err != nil {
			conn.cleanup2(conn.connId)
			return 0, err
		}

		// Clean up closed streams
		if stream.state == StreamStateClosed {
			conn.cleanup(stream.streamId)
		}

		if pacingNano < minPacing {
			minPacing = pacingNano
		}

		// If we sent data, return immediately
		if dataSent > 0 {
			return 0, nil
		}
		
		// Move to next stream
		conn.currentStream, _ = conn.streams.Next(conn.currentStream)
		if conn.currentStream == nil {
			// Wrap around to beginning
			conn.currentStream, _ = conn.streams.Min()
			if conn.currentStream == nil  {
				return minPacing, nil
			}
		}
		
		// Check if we've completed a full round
		if conn.currentStream == startStream {
			break
		}
	}

	return minPacing, nil
}


func newStreamHashMap() *SortedMap[*uint32, *Stream] {
	return NewSortedMap[*uint32, *Stream](func(a, b *uint32) bool {
		return *a < *b
	})
}

func newConnHashMap() *SortedMap[*uint64, *Connection] {
	return NewSortedMap[*uint64, *Connection](func(a, b *uint64) bool {
		return *a < *b
	})
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

	if l.connMap.Contains(&connId) {
		slog.Warn("conn already exists", slog.Any("connId", connId))
		return nil, errors.New("conn already exists")
	}

	conn := &Connection{
		connId:     connId,
		connIdRoll: connIdRollover,
		streams:    newStreamHashMap(),
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
		sndBuf:     NewSendBuffer(sndBufferCapacity),
		rcvBuf:     NewReceiveBuffer(rcvBufferCapacity),
		BBR:        NewBBR(),
		rcvWndSize: rcvBufferCapacity, //initially our capacity, correct value will be sent to us in the 1st handshake
	}

	l.connMap.Put(&connId, conn)
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
	c.cleanup2(c.connId)
}
