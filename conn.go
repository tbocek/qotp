package qotp

import (
	"crypto/ecdh"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
)

type ConnectionKeys struct {
	pubKeyIdRcv     *ecdh.PublicKey
	prvKeyEpSnd     *ecdh.PrivateKey
	prvKeyEpSndRoll *ecdh.PrivateKey
	pubKeyEpRcv     *ecdh.PublicKey
	pubKeyEpRcvRoll *ecdh.PublicKey
}

type ConnectionState struct {
	isSender              bool
	isRoll                bool
	isHandshakeComplete   bool
	isFirstPacketProduced bool
	withCrypto            bool
}

type Connection struct {
	// Connection identification
	connId     uint64
	connIdRoll uint64
	remoteAddr netip.AddrPort

	// Core components
	listener *Listener
	streams  *LinkedMap[uint32, *Stream]

	// Cryptographic keys
	keys ConnectionKeys

	// Shared secrets
	sharedSecret     []byte
	sharedSecretRoll []byte

	// Buffers and flow control
	sndBuf       *SendBuffer
	rcvBuf       *ReceiveBuffer
	dataInFlight int
	rcvWndSize   uint64
	mtu          uint64

	// Connection state
	state         ConnectionState
	nextWriteTime uint64

	// Crypto and performance
	snCrypto    uint64 //this is 48bit
	tmpRollover *tmpRollover
	BBR
	RTT

	mu sync.Mutex
}

// tmpRollover is used during rollover to temporarily store new rollover material. In case of perfect rollover,
// this is not needed. If you still have packets to send before the rollover and after, we need to temporarily store
// the new values, until all packets from the before rollover are sent.
type tmpRollover struct {
	connIdRollover       uint64
	prvKeyEpSndRollover  *ecdh.PrivateKey
	sharedSecretRollover []byte
}

func (c *Connection) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	iter := c.streams.Iterator()
	for {
		_, s, ok := iter.Next()
		if !ok {
			break
		}
		if s != nil {
			s.Close()
		}
	}
}

func (c *Connection) Stream(streamId uint32) (s *Stream) {
	c.mu.Lock()
	defer c.mu.Unlock()

	v := c.streams.Get(streamId)
	if v != nil {
		return v
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

func (c *Connection) decode(decryptedData []byte, rawLen int, nowNano uint64) (s *Stream, err error) {
	p, _, payloadData, err := DecodePayload(decryptedData)
	if err != nil {
		slog.Info("error in decoding payload from new connection", slog.Any("error", err))
		return nil, err
	}

	c.rcvWndSize = p.RcvWndSize
	s = c.Stream(p.StreamId)

	if p.Ack != nil {
		ackStatus, sentTimeNano := c.sndBuf.AcknowledgeRange(p.Ack) //remove data from rbSnd if we got the ack
		if ackStatus == AckStatusOk {
			c.dataInFlight -= rawLen
		} else if ackStatus == AckDup {
			c.OnDuplicateAck()
		}
		if nowNano > sentTimeNano {
			rttNano := nowNano - sentTimeNano
			c.UpdateRTT(rttNano)
			if ackStatus == AckStatusOk {
				c.UpdateBBR(rttNano, uint64(p.Ack.len), nowNano)
			} else {
				return nil, errors.New("stream does not exist")
			}
		}
	}

	if len(payloadData) > 0 {
		c.rcvBuf.Insert(s.streamId, p.StreamOffset, payloadData)
	}
	if p.IsClose {
		c.rcvBuf.CloseAt(s.streamId, p.StreamOffset)
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
		c.cleanupStream(s.streamId)
	}
}

// We need to check if we remove the current state, if yes, then move the state to the previous stream
func (c *Connection) cleanupStream(streamId uint32) {
	slog.Debug("Cleanup/Stream", debugGId(), c.debug(), slog.Uint64("streamId", uint64(streamId)))
	v, _ := c.streams.Remove(streamId)
	if v != nil && c.streams.Size() == 0 {
		c.cleanupConn(v.conn.connId)
	}
}

func (c *Connection) cleanupConn(connId uint64) {
	slog.Debug("Cleanup/Stream", debugGId(), c.debug(), slog.Uint64("connId", connId))
	c.listener.connMap.Remove(connId)
}

func (c *Connection) Flush(s *Stream, nowNano uint64) (raw int, data int, pacingNano uint64, err error) {
	//update state for receiver
	ack := c.rcvBuf.GetSndAck()

	// If close requested, do not send any data, just send ack
	if s.state == StreamStateCloseReceived {
		s.state = StreamStateClosed
		slog.Debug(" Flush/Close", debugGId(), s.debug(), c.debug(), slog.Bool("ack?", ack != nil))
		if ack == nil {
			return 0, 0, MinDeadLine, nil
		}
		return c.writeAck(s, ack, nowNano)
	}

	// Respect pacing
	if c.nextWriteTime > nowNano {
		slog.Debug(" Flush/Pacing", debugGId(), s.debug(), c.debug(),
			slog.Uint64("waitTime:ms", (c.nextWriteTime-nowNano)/msNano),
			slog.Bool("ack?", ack != nil))
		if ack == nil {
			return 0, 0, MinDeadLine, nil
		}
		return c.writeAck(s, ack, nowNano)
	}
	//Respect rwnd
	if c.dataInFlight+startMtu > int(c.rcvWndSize) {
		slog.Debug(" Flush/Rwnd/Rcv", debugGId(), s.debug(), c.debug(), slog.Bool("ack?", ack != nil))
		if ack == nil {
			return 0, 0, MinDeadLine, nil
		}
		return c.writeAck(s, ack, nowNano)
	}

	overhead := &Overhead{
		msgType:    s.msgType(),
		ack:        ack,
		dataOffset: 0,
		currentMtu: startMtu,
	}

	// Retransmission case
	splitData, m, err := c.sndBuf.ReadyToRetransmit(s.streamId, overhead, c.rtoNano(), nowNano)
	if err != nil {
		return 0, 0, 0, err
	}

	//during handshake, if we have something to retransmit, it will always be the first packet
	//otherwise go ahead
	if m != nil && splitData != nil {
		c.OnPacketLoss()
		slog.Debug(" Flush/Retransmit", debugGId(), s.debug(), m.debug(), c.debug())

		encData, err := s.encode(splitData, m.offset, ack, m.msgType)
		if err != nil {
			return 0, 0, 0, err
		}

		raw, err = c.listener.localConn.WriteToUDPAddrPort(encData, c.remoteAddr, nowNano)
		if err != nil {
			return 0, 0, 0, err
		}

		if raw != len(encData) {
			return 0, 0, 0, fmt.Errorf("could not send all data. This should not happen")
		}

		packetLen := len(splitData)
		pacingNano = c.GetPacingInterval(uint64(packetLen))

		c.nextWriteTime = nowNano + pacingNano
		return raw, packetLen, pacingNano, nil
	}

	//next check if we can send packets, during handshake we can only send 1 packet
	if !c.state.isHandshakeComplete && !c.state.isFirstPacketProduced || c.state.isHandshakeComplete {
		splitData, m = c.sndBuf.ReadyToSend(s.streamId, overhead, nowNano)
		if m != nil && splitData != nil {
			slog.Debug(" Flush/Send", debugGId(), s.debug(), m.debug(), c.debug())
			encData, err := s.encode(splitData, m.offset, ack, s.msgType())
			if err != nil {
				return 0, 0, 0, err
			}
			m.msgType = s.msgType()
			c.state.isFirstPacketProduced = true

			raw, err := c.listener.localConn.WriteToUDPAddrPort(encData, c.remoteAddr, nowNano)
			if err != nil {
				return 0, 0, 0, err
			}
			if raw != len(encData) {
				return 0, 0, 0, fmt.Errorf("could not send all data. This should not happen")
			}

			packetLen := len(splitData)
			c.dataInFlight += packetLen
			pacingNano = c.GetPacingInterval(uint64(packetLen))
			c.nextWriteTime = nowNano + pacingNano
			return raw, packetLen, pacingNano, nil
		}
	}

	if ack == nil {
		return 0, 0, MinDeadLine, nil
	}
	slog.Debug(" Flush/Ack", debugGId(), s.debug(), m.debug(), c.debug())
	return c.writeAck(s, ack, nowNano)
}

func (c *Connection) writeAck(stream *Stream, ack *Ack, nowNano uint64) (raw int, data int, pacingNano uint64, err error) {
	encData, err := stream.encode([]byte{}, stream.currentOffset(), ack, stream.msgType())
	if err != nil {
		return 0, 0, 0, err
	}
	raw, err = c.listener.localConn.WriteToUDPAddrPort(encData, c.remoteAddr, nowNano)
	if err != nil {
		return 0, 0, 0, err
	}
	if raw != len(encData) {
		return 0, 0, 0, fmt.Errorf("could not send all data. This should not happen.")
	}
	return raw, 0, MinDeadLine, nil
}

func (c *Connection) debug() slog.Attr {
	return slog.Group("connection",
		slog.Uint64("nextWrt:ms", c.nextWriteTime/msNano),
		//slog.Uint64("nextWrt:ns", c.nextWriteTime),
		slog.Int("inFlight", c.dataInFlight+startMtu),
		slog.Int("rcvBuf", c.rcvBuf.capacity-c.rcvBuf.size),
		slog.Uint64("rcvWnd", c.rcvWndSize))
}
