package tomtp

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
	streams  *skipList[uint32, *Stream]

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
	stateStream   *shmPair[uint32, *Stream]
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

	for node := c.streams.Min(); node != nil; node = node.Next() {
		if node.value != nil {
			node.value.Close()
		}
	}
}

func (c *Connection) Stream(streamId uint32) (s *Stream) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if node := c.streams.Get(streamId); node != nil && node.value != nil {
		return node.value
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

	if len(payloadData) > 0 || p.IsClose {
		c.rcvBuf.Insert(s.streamId, p.StreamOffset, payloadData, p.IsClose)
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
		c.cleanup(s.streamId)
	}
}

// We need to check if we remove the current state, if yes, then move the state to the next stream
func (c *Connection) cleanup(streamId uint32) {
	if c.stateStream != nil && streamId == c.stateStream.key {
		c.stateStream = c.stateStream.Next()
	}
	s := c.streams.Remove(streamId)

	if s != nil && c.streams.Size() == 0 {
		c.cleanup2(s.value.conn.connId)
	}
}

func (c *Connection) cleanup2(connId uint64) {
	if connId == c.listener.stateConn.key {
		c.listener.stateConn = c.listener.stateConn.Next()
	}
	c.listener.connMap.Remove(c.connId)
}

func (c *Connection) Flush(stream *Stream, nowNano uint64) (raw int, data int, pacingNano uint64, err error) {
	//update state for receiver
	if stream.state == StreamStateCloseReceived {
		stream.state = StreamStateClosed
	}

	ack := c.rcvBuf.GetSndAck()

	// Respect pacing
	if c.nextWriteTime > nowNano {
		slog.Debug("Flush/Pacing",
			debugGoroutineID(),
			stream.debug(),
			slog.Uint64("nowNano:ms", nowNano/msNano),
			slog.Uint64("nextWriteTime:ms", c.nextWriteTime/msNano),
			slog.Uint64("waitTime:ms", (c.nextWriteTime-nowNano)/msNano))
		if ack == nil {
			return 0, 0, MinDeadLine, nil
		}
		return c.writeAck(stream, ack, nowNano)
	}
	//Respect cwnd
	if c.dataInFlight+startMtu > c.sndBuf.capacity - c.sndBuf.size {
		slog.Debug("Flush/Cwnd/Snd",
			debugGoroutineID(),
			stream.debug(),
			slog.Int("dataInFlight", c.dataInFlight+startMtu ),
			slog.Int("size(snd-buf)", c.sndBuf.capacity - c.sndBuf.size))
		if ack == nil {
			return 0, 0, MinDeadLine, nil
		}
		return c.writeAck(stream, ack, nowNano)
	}
	//Respect rwnd
	if c.dataInFlight + startMtu > c.rcvBuf.capacity - c.rcvBuf.size {
		slog.Debug("Flush/Rwnd/Rcv",
			debugGoroutineID(),
			stream.debug(),
			slog.Int("dataInFlight", c.dataInFlight+startMtu ),
			slog.Int("size(rcv-buf)", c.rcvBuf.capacity - c.rcvBuf.size))
		if ack == nil {
			return 0, 0, MinDeadLine, nil
		}
		return c.writeAck(stream, ack, nowNano)
	}

	overhead := &Overhead{
		msgType:    stream.msgType(),
		ack:        ack,
		dataOffset: 0,
		currentMtu: startMtu,
	}

	// Retransmission case
	splitData, m, err := c.sndBuf.ReadyToRetransmit(stream.streamId, overhead, c.rtoNano(), nowNano)
	if err != nil {
		return 0, 0, 0, err
	}

	//during handshake, if we have something to retransmit, it will always be the first packet
	//otherwise go ahead
	if m != nil && splitData != nil {
		slog.Debug("Flush/Retransmit",
			debugGoroutineID(),
			stream.debug(),
			slog.Uint64("expetedRto:ms", m.expectedRtoBackoffNano/msNano),
			slog.Any("acutualRto:ms", m.actualRtoNano/msNano))
		c.OnPacketLoss()
		encData, err := stream.encode(splitData, m.offset, ack, m.msgType)
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
		splitData, m = c.sndBuf.ReadyToSend(stream.streamId, overhead, nowNano)
		if m != nil && splitData != nil {
			slog.Debug("Flush/Send", debugGoroutineID(), stream.debug())
			encData, err := stream.encode(splitData, m.offset, ack, stream.msgType())
			if err != nil {
				return 0, 0, 0, err
			}
			m.msgType = stream.msgType()
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
	slog.Debug("Flush/Ack", debugGoroutineID(), stream.debug())
	return c.writeAck(stream, ack, nowNano)
}

func (c *Connection) writeAck(stream *Stream, ack *Ack, nowNano uint64) (raw int, data int, pacingNano uint64, err error) {
	encData, err := stream.encode([]byte{}, stream.currentOffset(), ack, stream.msgType())
	if err != nil {
		return 0, 0, 0, err
	}
	slog.Debug("UpdateSnd/Acks", debugGoroutineID(), slog.Any("len(dataToSend)", len(encData)))
	raw, err = c.listener.localConn.WriteToUDPAddrPort(encData, c.remoteAddr, nowNano)
	if err != nil {
		return 0, 0, 0, err
	}
	if raw != len(encData) {
		return 0, 0, 0, fmt.Errorf("could not send all data. This should not happen.")
	}
	return raw, 0, MinDeadLine, nil
}
