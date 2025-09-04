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
	isSenderOnInit       bool
	isWithCryptoOnInit   bool
	isHandshakeDoneOnRcv bool
	isInitSentOnSnd      bool
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
	sharedSecret []byte

	// Buffers and flow control
	snd          *SendBuffer
	rcv          *ReceiveBuffer
	dataInFlight int
	rcvWndSize   uint64
	mtu          uint64

	// Connection state
	state         ConnectionState
	nextWriteTime uint64

	// Crypto and performance
	snCrypto    uint64 //this is 48bit
	epochCrypto uint64 //this is 48bit
	BBR
	RTT

	mu sync.Mutex
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

func (c *Connection) Stream(streamID uint32) (s *Stream) {
	c.mu.Lock()
	defer c.mu.Unlock()

	v := c.streams.Get(streamID)
	if v != nil {
		return v
	}

	s = &Stream{
		streamID: streamID,
		conn:     c,
		mu:       sync.Mutex{},
		state:    StreamStateOpen,
	}
	c.streams.Put(streamID, s)
	return s
}

func (c *Connection) decode(packetData []byte, rawLen int, nowNano uint64) (s *Stream, err error) {
	p, _, userData, err := DecodePayload(packetData)
	if err != nil {
		slog.Info("error in decoding payload from new connection", slog.Any("error", err))
		return nil, err
	}

	c.rcvWndSize = p.RcvWndSize
	s = c.Stream(p.StreamID)

	if p.Ack != nil {
		ackStatus, sentTimeNano := c.snd.AcknowledgeRange(p.Ack) //remove data from rbSnd if we got the ack
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

	if len(userData) > 0 {
		c.rcv.Insert(s.streamID, p.StreamOffset, userData)
	}
	if p.IsClose {
		c.rcv.CloseAt(s.streamID, p.StreamOffset)
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
		c.cleanupStream(s.streamID)
	}
}

// We need to check if we remove the current state, if yes, then move the state to the previous stream
func (c *Connection) cleanupStream(streamID uint32) {
	slog.Debug("Cleanup/Stream", getGoroutineID(), c.debug(), slog.Uint64("streamID", uint64(streamID)))

	if c.listener.iter.nextInnerKey != nil && streamID == *c.listener.iter.nextInnerKey {
		var ok bool
		*c.listener.iter.nextInnerKey, _, ok = c.streams.Next(streamID)
		if !ok {
			*c.listener.iter.nextInnerKey, _, _ = c.streams.First()
		}
	}

	c.streams.Remove(streamID)
	//even if the stream size is 0, do not remove the connection yet, only after a certain timeout,
	// so that BBR, RTT, is preserved for a bit
}

func (c *Connection) cleanupConn(connID uint64) {
	slog.Debug("Cleanup/Stream", getGoroutineID(), c.debug(), slog.Uint64("connID", connID))

	if c.listener.iter.nextOuterKey != nil && connID == *c.listener.iter.nextOuterKey {
		var ok bool
		*c.listener.iter.nextOuterKey, _, ok = c.listener.connMap.Next(connID)
		if !ok {
			*c.listener.iter.nextOuterKey, _, _ = c.listener.connMap.First()
		}
	}

	c.listener.connMap.Remove(connID)
}

func (c *Connection) Flush(s *Stream, nowNano uint64) (raw int, data int, pacingIntervalNano uint64, err error) {
	//update state for receiver
	ack := c.rcv.GetSndAck()

	// If close requested, do not send any data, just send ack
	if s.state == StreamStateCloseReceived {
		s.state = StreamStateClosed
		slog.Debug(" Flush/Close", getGoroutineID(), s.debug(), c.debug(), slog.Bool("ack?", ack != nil))
		if ack == nil {
			return 0, 0, MinDeadLine, nil
		}
		return c.writeAck(s, ack, nowNano)
	}

	// Respect pacing
	if c.nextWriteTime > nowNano {
		slog.Debug(" Flush/Pacing", getGoroutineID(), s.debug(), c.debug(),
			slog.Uint64("waitTime:ms", (c.nextWriteTime-nowNano)/msNano),
			slog.Bool("ack?", ack != nil))
		if ack == nil {
			return 0, 0, MinDeadLine, nil
		}
		return c.writeAck(s, ack, nowNano)
	}
	//Respect rwnd
	if c.dataInFlight+startMtu > int(c.rcvWndSize) {
		slog.Debug(" Flush/Rwnd/Rcv", getGoroutineID(), s.debug(), c.debug(), slog.Bool("ack?", ack != nil))
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
	splitData, m, err := c.snd.ReadyToRetransmit(s.streamID, overhead, c.rtoNano(), nowNano)
	if err != nil {
		return 0, 0, 0, err
	}

	//during handshake, if we have something to retransmit, it will always be the first packet
	//otherwise go ahead
	if m != nil && splitData != nil {
		c.OnPacketLoss()
		slog.Debug(" Flush/Retransmit", getGoroutineID(), s.debug(), m.debug(), c.debug())

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
		pacingIntervalNano = c.CalcPacingInterval(uint64(packetLen))

		c.nextWriteTime = nowNano + pacingIntervalNano
		return raw, packetLen, pacingIntervalNano, nil
	}

	//next check if we can send packets, during handshake we can only send 1 packet
	if c.state.isHandshakeDoneOnRcv || (!c.state.isHandshakeDoneOnRcv && !c.state.isInitSentOnSnd) {
		splitData, m = c.snd.ReadyToSend(s.streamID, overhead, nowNano)
		if m != nil && splitData != nil {
			slog.Debug(" Flush/Send", getGoroutineID(), s.debug(), m.debug(), c.debug())
			encData, err := s.encode(splitData, m.offset, ack, s.msgType())
			if err != nil {
				return 0, 0, 0, err
			}

			//TODO: this is important to set the type, but make this more explicit
			m.msgType = s.msgType()
			raw, err := c.listener.localConn.WriteToUDPAddrPort(encData, c.remoteAddr, nowNano)
			if err != nil {
				return 0, 0, 0, err
			}
			if raw != len(encData) {
				return 0, 0, 0, fmt.Errorf("could not send all data. This should not happen")
			}

			packetLen := len(splitData)
			c.dataInFlight += packetLen
			pacingIntervalNano = c.CalcPacingInterval(uint64(len(encData)))
			c.nextWriteTime = nowNano + pacingIntervalNano
			return raw, packetLen, pacingIntervalNano, nil
		}
	}

	if ack == nil {
		return 0, 0, MinDeadLine, nil
	}
	slog.Debug(" Flush/Ack", getGoroutineID(), s.debug(), m.debug(), c.debug())
	return c.writeAck(s, ack, nowNano)
}

func (c *Connection) writeAck(stream *Stream, ack *Ack, nowNano uint64) (raw int, data int, pacingIntervalNano uint64, err error) {
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
	pacingIntervalNano = c.CalcPacingInterval(uint64(len(encData)))
	c.nextWriteTime = nowNano + pacingIntervalNano
	return raw, 0, pacingIntervalNano, nil
}

func (c *Connection) debug() slog.Attr {
	return slog.Group("connection",
		slog.Uint64("nextWrt:ms", c.nextWriteTime/msNano),
		//slog.Uint64("nextWrt:ns", c.nextWriteTime),
		slog.Int("inFlight", c.dataInFlight+startMtu),
		slog.Int("rcvBuf", c.rcv.capacity-c.rcv.size),
		slog.Uint64("rcvWnd", c.rcvWndSize))
}
