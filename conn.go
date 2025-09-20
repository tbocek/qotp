package qotp

import (
	"crypto/ecdh"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
)

type Conn struct {
	// Connection identification
	connId     uint64
	remoteAddr netip.AddrPort

	// Core components
	listener *Listener
	streams  *LinkedMap[uint32, *Stream]

	// Cryptographic keys
	prvKeyEpSnd *ecdh.PrivateKey
	pubKeyEpRcv *ecdh.PublicKey
	pubKeyIdRcv *ecdh.PublicKey

	// Shared secrets
	sharedSecret []byte

	// Buffers and flow control
	snd          *SendBuffer
	rcv          *ReceiveBuffer
	dataInFlight int
	rcvWndSize   uint64

	// Connection state
	isSenderOnInit       bool
	isWithCryptoOnInit   bool
	isHandshakeDoneOnRcv bool
	isInitSentOnSnd      bool

	nextWriteTime uint64

	// Crypto and performance
	snCrypto       uint64 //this is 48bit
	epochCryptoSnd uint64 //this is 47bit
	epochCryptoRcv uint64 //this is 47bit
	Measurements

	mu sync.Mutex
}

func (c *Conn) msgType() MsgType {
	if c.isHandshakeDoneOnRcv {
		return Data
	}

	switch {
	case c.isWithCryptoOnInit && c.isSenderOnInit:
		return InitCryptoSnd
	case c.isWithCryptoOnInit && !c.isSenderOnInit:
		return InitCryptoRcv
	case c.isSenderOnInit:
		return InitSnd
	default:
		return InitRcv
	}
}

func (c *Conn) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, s := range c.streams.Iterator(nil) {
		if s != nil {
			s.Close()
		}
	}
}

func (c *Conn) Stream(streamID uint32) (s *Stream) {
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

func (c *Conn) decode(p *PayloadHeader, userData []byte, rawLen int, nowNano uint64) (s *Stream, err error) {
	c.rcvWndSize = p.RcvWndSize
	s = c.Stream(p.StreamID)

	if p.Ack != nil {
		ackStatus, sentTimeNano := c.snd.AcknowledgeRange(p.Ack) //remove data from rbSnd if we got the ack
		if ackStatus == AckStatusOk {
			c.dataInFlight -= rawLen
		} else if ackStatus == AckDup {
			c.OnDuplicateAck()
		} else {
			slog.Debug("No stream?")
		}

		if nowNano > sentTimeNano {
			if ackStatus == AckStatusOk {
				rttNano := nowNano - sentTimeNano
				c.UpdateMeasurements(rttNano, uint64(p.Ack.len), nowNano)
			} else {
				return nil, errors.New("stream does not exist")
			}
		}

	}

	if len(userData) > 0 {
		c.rcv.Insert(s.streamID, p.StreamOffset, userData)
	}
	if len(userData) == 0 && p.IsNoRetry {
		c.rcv.EmptyInsert(s.streamID, p.StreamOffset)
	}

	if p.IsClose {
		c.rcv.CloseAt(s.streamID, p.StreamOffset)
	}

	return s, nil
}

func (c *Conn) updateState(s *Stream, isClose bool) {
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
func (c *Conn) cleanupStream(streamID uint32) {
	slog.Debug("Cleanup/Stream", gId(), c.debug(), slog.Uint64("streamID", uint64(streamID)))

	if c.listener.currentStreamID != nil && streamID == *c.listener.currentStreamID {
		*c.listener.currentStreamID, _, _ = c.streams.Next(streamID)
	}
	c.streams.Remove(streamID)
	//even if the stream size is 0, do not remove the connection yet, only after a certain timeout,
	// so that BBR, RTT, is preserved for a bit
}

func (c *Conn) cleanupConn() {
	slog.Debug("Cleanup/Stream", gId(), c.debug(),
		slog.Uint64("connID", c.connId), slog.Any("currId", c.listener.currentConnID))

	if c.listener.currentConnID != nil && c.connId == *c.listener.currentConnID {
		*c.listener.currentConnID, _, _ = c.listener.connMap.Next(c.connId)
	}
	c.listener.connMap.Remove(c.connId)
}

func (c *Conn) Ping(streamId uint32, nowNano uint64) error {
	ack := c.rcv.GetSndAck()
	p := &PayloadHeader{
		IsNoRetry:    true, //important as our data will be empty
		Ack:          ack,
		StreamID:     streamId,
		StreamOffset: nowNano,
	}
	encData, err := c.encode(p, []byte{}, c.msgType())

	err = c.listener.localConn.WriteToUDPAddrPort(encData, c.remoteAddr, nowNano)
	if err != nil {
		return err
	}

	return nil
}

func (c *Conn) Flush(s *Stream, nowNano uint64) (data int, pacingNano uint64, err error) {
	//update state for receiver
	ack := c.rcv.GetSndAck()

	// If close requested, do not send any data, just send ack
	if s.state == StreamStateCloseReceived {
		s.state = StreamStateClosed
		slog.Debug(" Flush/Close", gId(), s.debug(), c.debug(), slog.Bool("ack?", ack != nil))
		if ack == nil {
			return 0, MinDeadLine, nil
		}
		return c.writeAck(s, ack, nowNano)
	}

	// Respect pacing
	if c.nextWriteTime > nowNano {
		slog.Debug(" Flush/Pacing", gId(), s.debug(), c.debug(),
			slog.Uint64("waitTime:ms", (c.nextWriteTime-nowNano)/msNano),
			slog.Bool("ack?", ack != nil))
		if ack == nil {
			return 0, MinDeadLine, nil
		}
		return c.writeAck(s, ack, nowNano)
	}
	//Respect rwnd
	if c.dataInFlight+int(c.listener.mtu) > int(c.rcvWndSize) {
		slog.Debug(" Flush/Rwnd/Rcv", gId(), s.debug(), c.debug(), slog.Bool("ack?", ack != nil))
		if ack == nil {
			return 0, MinDeadLine, nil
		}
		return c.writeAck(s, ack, nowNano)
	}

	// Retransmission case
	splitData, offset, msgType, err := c.snd.ReadyToRetransmit(s.streamID, ack, c.listener.mtu, c.rtoNano(), nowNano)
	if err != nil {
		return 0, 0, err
	}

	if splitData != nil {
		c.OnPacketLoss()

		slog.Debug(" Flush/Retransmit", gId(), s.debug(), c.debug())

		p := &PayloadHeader{
			Ack:          ack,
			StreamOffset: offset,
		}

		encData, err := c.encode(p, splitData, msgType)
		if err != nil {
			return 0, 0, err
		}

		err = c.listener.localConn.WriteToUDPAddrPort(encData, c.remoteAddr, nowNano)
		if err != nil {
			return 0, 0, err
		}

		packetLen := len(splitData)
		pacingNano = c.calcPacing(uint64(packetLen))

		c.nextWriteTime = nowNano + pacingNano
		return packetLen, pacingNano, nil
	}

	//next check if we can send packets, during handshake we can only send 1 packet
	if c.isHandshakeDoneOnRcv || !c.isInitSentOnSnd {
		splitData, offset := c.snd.ReadyToSend(s.streamID, c.msgType(), ack, c.listener.mtu, s.noRetry, nowNano)
		if len(splitData) > 0 {
			slog.Debug(" Flush/Send", gId(), s.debug(), c.debug())

			p := &PayloadHeader{
				IsNoRetry:    s.noRetry,
				IsClose:      s.state == StreamStateClosed || s.state == StreamStateCloseRequest,
				RcvWndSize:   uint64(s.conn.rcv.capacity) - uint64(s.conn.rcv.Size()),
				Ack:          ack,
				StreamID:     s.streamID,
				StreamOffset: offset,
			}

			encData, err := c.encode(p, splitData, c.msgType())
			if err != nil {
				return 0, 0, err
			}

			err = c.listener.localConn.WriteToUDPAddrPort(encData, c.remoteAddr, nowNano)
			if err != nil {
				return 0, 0, err
			}

			packetLen := len(splitData)
			c.dataInFlight += packetLen
			pacingNano = c.calcPacing(uint64(len(encData)))
			c.nextWriteTime = nowNano + pacingNano
			return packetLen, pacingNano, nil
		} else if ack != nil || !c.isInitSentOnSnd {
			slog.Debug(" Flush/Ack", gId(), s.debug(), c.debug())
			return c.writeAck(s, ack, nowNano)
		}
	}

	return 0, MinDeadLine, nil
}

func (c *Conn) writeAck(s *Stream, ack *Ack, nowNano uint64) (data int, pacingNano uint64, err error) {
	p := &PayloadHeader{
		IsClose:    s.state == StreamStateClosed || s.state == StreamStateCloseRequest,
		RcvWndSize: uint64(s.conn.rcv.capacity) - uint64(s.conn.rcv.Size()),
		Ack:        ack,
		StreamID:   s.streamID,
	}

	encData, err := c.encode(p, []byte{}, c.msgType())
	if err != nil {
		return 0, 0, err
	}
	err = c.listener.localConn.WriteToUDPAddrPort(encData, c.remoteAddr, nowNano)
	if err != nil {
		return 0, 0, err
	}

	pacingNano = c.calcPacing(uint64(len(encData)))
	c.nextWriteTime = nowNano + pacingNano
	return 0, pacingNano, nil
}

func (c *Conn) payloadHeader() *PayloadHeader {
	return &PayloadHeader{
		RcvWndSize: uint64(c.rcv.capacity) - uint64(c.rcv.Size()),
	}
}

func (c *Conn) debug() slog.Attr {
	return slog.Group("connection",
		slog.Uint64("nextWrt:ms", c.nextWriteTime/msNano),
		//slog.Uint64("nextWrt:ns", c.nextWriteTime),
		slog.Int("inFlight", c.dataInFlight+c.listener.mtu),
		slog.Int("rcvBuf", c.rcv.capacity-c.rcv.size),
		slog.Uint64("rcvWnd", c.rcvWndSize),
		slog.Uint64("snCrypto", c.snCrypto),
		slog.Uint64("epochSnd", c.epochCryptoSnd),
		slog.Uint64("epochRcv", c.epochCryptoRcv))
}
