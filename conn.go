package tomtp

import (
	"crypto/ecdh"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
)

// tmpRollover is used during rollover to temporarily store new rollover material. In case of perfect rollover,
// this is not needed. If you still have packets to send before the rollover and after, we need to temporarily store
// the new values, until all packets from the before rollover are sent.
type tmpRollover struct {
	connIdRollover       uint64
	prvKeyEpSndRollover  *ecdh.PrivateKey
	sharedSecretRollover []byte
}

type Connection struct {
	connId                uint64
	connIdRollover        uint64
	remoteAddr            netip.AddrPort
	streams               *skipList[uint32, *Stream]
	listener              *Listener
	pubKeyIdRcv           *ecdh.PublicKey
	prvKeyEpSnd           *ecdh.PrivateKey
	prvKeyEpSndRollover   *ecdh.PrivateKey
	pubKeyEpRcv           *ecdh.PublicKey
	pubKeyEpRcvRollover   *ecdh.PublicKey
	sharedSecret          []byte
	sharedSecretRollover  []byte
	rbSnd                 *SendBuffer // Send buffer for outgoing dataToSend, handles the global sn
	rbRcv                 *ReceiveBuffer
	dataInFlight          int
	mtu                   uint64
	isSender              bool
	isRollover            bool
	isHandshakeComplete   bool
	isFirstPacketProduced bool
	withCrypto            bool
	snCrypto              uint64 //this is 48bit
	tmpRollover           *tmpRollover
	rcvWndSize            uint64 // Flow control - receive window Size
	BBR
	RTT
	mu sync.Mutex
}

func (c *Connection) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	next := c.streams.Min()
	for next != nil {
		next.value.Close()
		next = next.Next()
	}
}

func (c *Connection) Stream(streamId uint32) (s *Stream) {
	c.mu.Lock()
	defer c.mu.Unlock()

	p := c.streams.Get(streamId)
	if p != nil {
		s = p.value
		if s != nil {
			return s
		}
	}

	s = &Stream{
		streamId: streamId,
		conn:     c,
		mu:       sync.Mutex{},
		state:    StreamStateOpen,
	}
	c.streams.Put(streamId, s)
	return s
}

func (c *Connection) decode(decryptedData []byte, rawLen int, nowMicros uint64) (s *Stream, err error) {
	p, _, payloadData, err := DecodePayload(decryptedData)
	if err != nil {
		slog.Info("error in decoding payload from new connection", slog.Any("error", err))
		return nil, err
	}

	c.rcvWndSize = p.RcvWndSize

	// Get or create stream using StreamId from Data
	s = c.Stream(p.StreamId)

	if p.Ack != nil {
		ackStatus, sentTimeMicros := c.rbSnd.AcknowledgeRange(p.Ack) //remove data from rbSnd if we got the ack
		if ackStatus == AckStatusOk {
			c.dataInFlight -= rawLen
		} else if ackStatus == AckDup {
			c.OnDuplicateAck()
		}
		if nowMicros > sentTimeMicros {
			rttMicros := nowMicros - sentTimeMicros
			c.UpdateRTT(rttMicros)
			if ackStatus == AckStatusOk {
				c.UpdateBBR(rttMicros, uint64(p.Ack.len), nowMicros)
			} else {
				return nil, errors.New("stream does not exist")
			}
		}
	}

	if len(payloadData) > 0 || p.IsClose {
		c.rbRcv.Insert(s.streamId, p.StreamOffset, payloadData, p.IsClose)
	}

	return s, nil
}

func (c *Connection) updateState(s *Stream, isClose bool) {
	//update state
	if s.state == StreamStateOpen && isClose {
		s.state = StreamStateCloseReceived
	}
	if s.state == StreamStateCloseRequest && isClose {
		s.state = StreamStateClosed
	}
}

func (c *Connection) Flush(stream *Stream, nowMicros uint64) (n int, pacingMicros uint64, err error) {

	//update state for receiver
	if stream.state == StreamStateCloseReceived {
		stream.state = StreamStateClosed
	}

	ack := c.rbRcv.GetSndAck()

	overhead := &Overhead{
		msgType:    stream.msgType(),
		ack:        ack,
		dataOffset: 0,
		currentMtu: startMtu,
	}

	// Retransmission case
	splitData, m, err := c.rbSnd.ReadyToRetransmit(stream.streamId, overhead, c.rtoMicros(), nowMicros)
	if err != nil {
		return 0, 0, err
	}

	switch {
	case m != nil && splitData != nil:
		c.OnPacketLoss()
		encData, msgType, err := stream.encode(splitData, m.offset, ack, m.msgType)
		if msgType != m.msgType {
			panic("cryptoType changed")
		}
		if err != nil {
			return 0, 0, err
		}
		slog.Debug("UpdateSnd/ReadyToRetransmit", debugGoroutineID(), slog.Any("len(dataToSend)", len(encData)))
		_, err = c.listener.localConn.WriteToUDPAddrPort(encData, c.remoteAddr)
		if err != nil {
			return 0, 0, err
		}

		packetLen := len(encData)
		pacingMicros = c.GetPacingInterval(uint64(packetLen))
		return packetLen, pacingMicros, nil

	case !c.isHandshakeComplete && c.isFirstPacketProduced:
		// Handshake mode - already sent first packet, can only retransmit or ack
		switch {
		case ack != nil:
			encData, _, err := stream.encode([]byte{}, stream.currentOffset(), ack, -1)
			if err != nil {
				return 0, 0, err
			}
			slog.Debug("UpdateSnd/Acks1", debugGoroutineID(), slog.Any("len(dataToSend)", len(encData)))
			_, err = c.listener.localConn.WriteToUDPAddrPort(encData, c.remoteAddr)
			if err != nil {
				return 0, 0, err
			}

			packetLen := len(encData)
			return packetLen, 0, nil
		default:
			return 0, 100 * 1000, nil // need to wait, go to next connection
		}

	}

	// Normal operation - try to send new data
	splitData, m = c.rbSnd.ReadyToSend(stream.streamId, overhead, nowMicros)
	switch {
	case m != nil && splitData != nil:
		encData, msgType, err := stream.encode(splitData, m.offset, ack, -1)
		if err != nil {
			return 0, 0, err
		}
		m.msgType = msgType
		c.isFirstPacketProduced = true
		slog.Debug("UpdateSnd/ReadyToSend/splitData", debugGoroutineID(), slog.Any("len(dataToSend)", len(encData)))
		n, err := c.listener.localConn.WriteToUDPAddrPort(encData, c.remoteAddr)
		if err != nil {
			return 0, 0, err
		}

		c.dataInFlight += n
		packetLen := len(encData)
		pacingMicros = c.GetPacingInterval(uint64(packetLen))
		return packetLen, pacingMicros, nil
	case ack != nil:
		// Only have acks to send
		encData, _, err := stream.encode([]byte{}, stream.currentOffset(), ack, -1)
		if err != nil {
			return 0, 0, err
		}
		slog.Debug("UpdateSnd/Acks2", debugGoroutineID(), slog.Any("len(dataToSend)", len(encData)))
		_, err = c.listener.localConn.WriteToUDPAddrPort(encData, c.remoteAddr)
		if err != nil {
			return 0, 0, err
		}
		packetLen := len(encData)
		return packetLen, 0, nil

	default:
		return 0, 0, nil // need to wait, go to next stream
	}
}
