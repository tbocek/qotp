package tomtp

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

const ReadDeadLine uint64 = 200

type Listener struct {
	// this is the port we are listening to
	localConn NetworkConn
	prvKeyId  *ecdh.PrivateKey               //never nil
	connMap   *skipList[uint64, *Connection] // here we store the connection to remote peers, we can have up to
	stateConn *shmPair[uint64, *Connection]
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
		slog.String("privKeyId", "0x"+hex.EncodeToString(l.prvKeyId.Bytes()[:3])+"…"),
		slog.String("pubKeyId", "0x"+hex.EncodeToString(l.prvKeyId.PublicKey().Bytes()[:3])+"…"))

	return l, nil
}

func (l *Listener) Close() error {
	slog.Debug("ListenerClose", debugGoroutineID())
	l.mu.Lock()
	defer l.mu.Unlock()

	l.closed = true

	for _, conn := range l.connMap.items {
		conn.value.Close()
	}

	err := l.localConn.CancelRead()
	if err != nil {
		return err
	}
	return l.localConn.Close()
}

func (l *Listener) Listen(timeout time.Duration, nowMicros uint64) (s *Stream, err error) {
	buffer, remoteAddr, err := l.readUDP(timeout)
	if err != nil {
		return nil, err
	}

	if buffer == nil || len(buffer) == 0 {
		return nil, nil
	}
	slog.Debug("RcvUDP", debugGoroutineID(), l.debug(remoteAddr), slog.Any("read len", len(buffer)))

	conn, m, err := l.decode(buffer, remoteAddr)
	if err != nil {
		return nil, err
	}

	s, err = conn.decode(m.PayloadRaw, len(buffer), nowMicros)
	if err != nil {
		return nil, err
	}

	if !conn.state.isHandshakeComplete {
		if conn.state.isSender {
			if m.MsgType == InitHandshakeR0MsgType || m.MsgType == InitWithCryptoR0MsgType {
				conn.state.isHandshakeComplete = true
			}
		} else {
			if m.MsgType == DataMsgType || m.MsgType == Data0MsgType {
				conn.state.isHandshakeComplete = true
			}
		}
	}

	return s, nil
}

func (l *Listener) Flush(nowMicros uint64) (waitNextMicros uint64, err error) {
	minPacing := uint64(100 * 1000)
	startConnection := l.stateConn
	firstIterationConn := true

	for {
		if !firstIterationConn && l.stateConn == startConnection {
			//we made the full round, we have nothing more to write, return minPacing
			return minPacing, nil
		}
		firstIterationConn = false

		if l.stateConn == nil {
			l.stateConn = l.connMap.Min()
		} else {
			l.stateConn = l.stateConn.Next()
			if l.stateConn == nil {
				continue
			}
		}
		if l.stateConn == nil {
			//no connections
			return minPacing, nil
		}

		startStream := l.stateConn.Value().stateStream

		firstIterationStream := true
		for {
			if l.stateConn == nil || (!firstIterationStream && l.stateConn.Value().stateStream == startStream) {
				//we made the full round, go to next connection
				break
			}
			firstIterationStream = false

			if l.stateConn.Value().stateStream == nil {
				l.stateConn.Value().stateStream = l.stateConn.Value().streams.Min()
			} else {
				l.stateConn.Value().stateStream = l.stateConn.Value().stateStream.Next()
				if l.stateConn.Value().stateStream == nil {
					continue
				}
			}
			if l.stateConn.Value().stateStream == nil {
				//no streams, go to next connection
				break
			}

			_, data, pacingMicros, err := l.stateConn.value.Flush(l.stateConn.Value().stateStream.Value(), nowMicros)
			if err != nil {
				l.stateConn.Value().cleanup2(l.stateConn.Value().connId)
				return 0, err
			}

			if l.stateConn.Value().stateStream.Value().state == StreamStateClosed {
				l.stateConn.value.cleanup(l.stateConn.Value().stateStream.Value().streamId)
			}

			if pacingMicros < minPacing {
				minPacing = pacingMicros
			}

			if data > 0 {
				//we do not return minpacing, as we may have more to write
				return 0, nil
			}
		}
	}
}

func newStreamHashMap() *skipList[uint32, *Stream] {
	return newSortedHashMap[uint32, *Stream](func(a, b uint32, c, d *Stream) bool {
		return a < b
	})
}

func newConnHashMap() *skipList[uint64, *Connection] {
	return newSortedHashMap[uint64, *Connection](func(a, b uint64, c, d *Connection) bool {
		return a < b
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

	if l.connMap.Contains(connId) {
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
		rbSnd:      NewSendBuffer(rcvBufferCapacity),
		rbRcv:      NewReceiveBuffer(rcvBufferCapacity),
		BBR:        NewBBR(),
		rcvWndSize: 0, //initially 0, will be sent to us in the 1st handshake
	}

	l.connMap.Put(connId, conn)

	return conn, nil
}

func (l *Listener) readUDP(timeout time.Duration) ([]byte, netip.AddrPort, error) {
	buffer := make([]byte, maxMtu)

	numRead, remoteAddr, err := l.localConn.ReadFromUDPAddrPort(buffer, timeout)

	if err != nil {
		var netErr net.Error
		ok := errors.As(err, &netErr)

		if ok && netErr.Timeout() {
			slog.Debug("readUDP - net.Timeout")
			return nil, netip.AddrPort{}, nil // Timeout is normal, return no dataToSend/error
		} else {
			slog.Error("readUDP - error during read", slog.Any("error", err))
			return nil, netip.AddrPort{}, err
		}
	}
	if numRead == 0 {
		slog.Debug("readUDP - no dataAvailable")
		return nil, remoteAddr, nil
	}

	slog.Debug("readUDP - dataAvailable")
	return buffer[:numRead], remoteAddr, nil
}

func (l *Listener) Loop(ctx context.Context, callback func(s *Stream)) {
	go func() {
		waitNextMicros := uint64(100 * 1000)
		for {
			// Check if context is cancelled
			if ctx != nil {
				select {
				case <-ctx.Done():
					slog.Debug("loop - context cancelled, exiting")
					return
				default:
					// Continue with normal operation
				}
			}

			//Listen
			nowMicros := uint64(time.Now().UnixMicro())
			timeout := time.Duration(waitNextMicros) * time.Microsecond
			s, err := l.Listen(timeout, nowMicros)
			if err != nil {
				slog.Error("Error in loop listen", slog.Any("error", err))
			}
			if s != nil {
				callback(s) // Process received stream
			}

			//Flush
			nowMicros = uint64(time.Now().UnixMicro())
			waitNextMicros, err = l.Flush(nowMicros)

			if err != nil {
				slog.Error("Error in loop flush", slog.Any("error", err))
			}
		}
	}()
}

func (l *Listener) debug(addr netip.AddrPort) slog.Attr {
	if l.localConn == nil {
		return slog.String("net", "nil->"+addr.String())
	}

	localAddrString := l.localConn.LocalAddrString()
	lastColonIndex := strings.LastIndex(localAddrString, ":")

	return slog.String("net", strconv.Itoa(int(addr.Port()))+"->"+localAddrString[lastColonIndex+1:])
}

func (l *Listener) ForceClose(c *Connection) {
	c.cleanup2(c.connId)
}
