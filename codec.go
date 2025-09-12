package qotp

import (
	"crypto/ecdh"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
)

func (s *Stream) msgType() MsgType {
	switch {
	case !s.conn.state.isHandshakeDoneOnRcv && s.conn.state.isWithCryptoOnInit && s.conn.state.isSenderOnInit:
		return InitCryptoSnd
	case !s.conn.state.isHandshakeDoneOnRcv && s.conn.state.isWithCryptoOnInit && !s.conn.state.isSenderOnInit:
		return InitCryptoRcv
	case !s.conn.state.isHandshakeDoneOnRcv && s.conn.state.isSenderOnInit:
		return InitSnd
	case !s.conn.state.isHandshakeDoneOnRcv && !s.conn.state.isSenderOnInit:
		return InitRcv
	default:
		return Data
	}
}

type Overhead struct {
	// Variables needed to calc the overhead
	ack        *Ack
	dataOffset uint64
	msgType    MsgType
	currentMtu uint16
	debug      uint16
}

func (o *Overhead) CalcOverhead() (needsExtend bool, overhead int) {
	hasAck := o.ack != nil
	needsExtend = (hasAck && o.ack.offset > 0xFFFFFF) || o.dataOffset > 0xFFFFFF
	overhead = CalcProtoOverhead(hasAck, needsExtend)
	return needsExtend, overhead
}

func CalcProtoOverhead(ack bool, needsExtension bool) int {
	overhead := 1 //header Size
	if ack {
		if !needsExtension {
			overhead += 4 + 3 + 2 // StreamId, StreamOffset (24-bit), Len
		} else {
			overhead += 4 + 6 + 2 // StreamId, StreamOffset (48-bit), Len
		}
	}
	if !needsExtension {
		overhead += 4 + 3 // StreamId, StreamOffset (24-bit)
	} else {
		overhead += 4 + 6 // StreamId, StreamOffset (48-bit)
	}

	// now comes the data... -> but not calculated in overhead
	return overhead
}

func (o *Overhead) CalcMaxData() (overhead uint16) {
	if o.debug > 0 {
		return o.debug
	}

	_, tmpOverhead := o.CalcOverhead()

	switch o.msgType {
	case InitSnd:
		return 0 //we cannot send data, this is unencrypted
	case InitRcv:
		tmpOverhead += MinInitRcvSizeHdr + FooterDataSize
	case InitCryptoSnd:
		tmpOverhead += MinInitCryptoSndSizeHdr + FooterDataSize + MsgInitFillLenSize
	case InitCryptoRcv:
		tmpOverhead += MinInitCryptoRcvSizeHdr + FooterDataSize
	case Data:
		tmpOverhead += MinDataSizeHdr + FooterDataSize
	}

	return o.currentMtu - uint16(tmpOverhead)
}

func (s *Stream) encode(userData []byte, offset uint64, ack *Ack, msgType MsgType) (encData []byte, err error) {
	// Create payload early for cases that need it
	var packetData []byte

	slog.Debug("  Encode", gId(), s.debug(), s.conn.debug(),
		slog.Uint64("offset", offset),
		slog.Int("l(userData)", len(userData)),
		slog.String("b…", string(userData[:min(16, len(userData))])))

	// Special case: InitHandshakeS0 doesn't need payload
	if msgType == InitSnd {
		encData = EncodeInitSnd(
			s.conn.listener.prvKeyId.PublicKey(),
			s.conn.keys.prvKeyEpSnd,
		)
		slog.Debug("   Encode/InitSnd", gId(), s.debug(), s.conn.debug(),
			slog.Int("l(encData)", len(encData)))
		s.conn.snCrypto++
		//here we cannot rollover
		s.conn.state.isInitSentOnSnd = true
		return encData, nil
	}

	// Create payload for all other message types
	p := &PayloadHeader{
		IsClose:      s.state == StreamStateClosed || s.state == StreamStateCloseRequest,
		RcvWndSize:   uint64(s.conn.rcv.capacity) - uint64(s.conn.rcv.Size()),
		Ack:          ack,
		StreamID:     s.streamID,
		StreamOffset: offset,
	}
	packetData, _ = EncodePayload(p, userData)

	// Handle message encoding based on connection state
	switch msgType {
	case InitCryptoSnd:
		encData, err = EncodeInitCryptoSnd(
			s.conn.keys.pubKeyIdRcv,
			s.conn.listener.prvKeyId.PublicKey(),
			s.conn.keys.prvKeyEpSnd,
			s.conn.snCrypto,
			packetData,
		)
		if err != nil {
			return nil, err
		}
		s.conn.state.isInitSentOnSnd = true
		slog.Debug("   Encode/InitCryptoSnd", gId(), s.debug(), s.conn.debug(),
			slog.Int("l(packetData)", len(packetData)),
			slog.Int("l(encData)", len(encData)))
	case InitCryptoRcv:
		encData, err = EncodeInitCryptoRcv(
			s.conn.keys.pubKeyIdRcv,
			s.conn.listener.prvKeyId.PublicKey(),
			s.conn.keys.pubKeyEpRcv,
			s.conn.keys.prvKeyEpSnd,
			s.conn.snCrypto,
			packetData,
		)
		if err != nil {
			return nil, err
		}
		s.conn.state.isInitSentOnSnd = true
		slog.Debug("   Encode/InitCryptoRcv", gId(), s.debug(), s.conn.debug(),
			slog.Int("l(packetData)", len(packetData)),
			slog.Int("l(encData)", len(encData)))
	case InitRcv:
		encData, err = EncodeInitRcv(
			s.conn.keys.pubKeyIdRcv,
			s.conn.listener.prvKeyId.PublicKey(),
			s.conn.keys.pubKeyEpRcv,
			s.conn.keys.prvKeyEpSnd,
			s.conn.snCrypto,
			packetData,
		)
		if err != nil {
			return nil, err
		}
		s.conn.state.isInitSentOnSnd = true
		slog.Debug("   Encode/InitRcv", gId(), s.debug(), s.conn.debug(),
			slog.Int("l(packetData)", len(packetData)),
			slog.Int("l(encData)", len(encData)))
	case Data:
		encData, err = EncodeData(
			s.conn.keys.prvKeyEpSnd.PublicKey(),
			s.conn.keys.pubKeyEpRcv,
			s.conn.state.isSenderOnInit,
			s.conn.sharedSecret,
			s.conn.snCrypto,
			s.conn.epochCryptoSnd,
			packetData,
		)
		if err != nil {
			return nil, err
		}
		slog.Debug("   Encode/Data", gId(), s.debug(), s.conn.debug(),
			slog.Int("len(payRaw)", len(packetData)),
			slog.Int("len(dataEnc)", len(encData)))
	default:
		return nil, fmt.Errorf("unknown message type: %v", msgType)
	}

	//update state ofter encode of packet
	s.conn.snCrypto++
	//rollover
	if s.conn.snCrypto > (1<<48)-1 {
		if s.conn.epochCryptoSnd+1 > (1<<47)-1 { //47, as the last bit is used for sender / receiver differentiation
			//TODO: quic has key rotation (via bitflip)
			return nil, errors.New("exhausted 2^95 sn number, cannot continue, you just sent ~5 billion ZettaBytes. " +
				"Now you need to reconnect manually. This is roughly 28 million times all the data humanity has ever created.")
		}
		s.conn.epochCryptoSnd++
		s.conn.snCrypto = 0
	}
	return encData, nil
}

func (l *Listener) decode(buffer []byte, remoteAddr netip.AddrPort) (*Connection, *Message, error) {
	msgType, err := decodeHeader(buffer)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode header: %w", err)
	}
	slog.Debug("  Decode", gId(), l.debug(), slog.Int("l(data)", len(buffer)), slog.Any("msgType", msgType))

	switch msgType {
	case InitSnd:
		// Decode S0 message
		connId, pubKeyIdSnd, pubKeyEpSnd, message, err := DecodeInitSnd(buffer)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode InitHandshakeS0: %w", err)
		}
		conn := l.connMap.Get(connId)
		//we might have received this a multiple times due to retransmission in the first packet
		//however the other side send us this, so we are expected to drop the old keys
		var prvKeyEpRcv *ecdh.PrivateKey
		if conn == nil {
			prvKeyEpRcv, err = generateKey()
			if err != nil {
				return nil, nil, fmt.Errorf("failed to generate keys: %w", err)
			}
			conn, err = l.newConn(remoteAddr, prvKeyEpRcv, pubKeyIdSnd, pubKeyEpSnd, false, false)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to create connection: %w", err)
			}
			l.connMap.Put(connId, conn)
		} else {
			prvKeyEpRcv = conn.keys.prvKeyEpSnd
		}

		sharedSecret, err := prvKeyEpRcv.ECDH(pubKeyEpSnd)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create connection: %w", err)
		}
		conn.sharedSecret = sharedSecret
		slog.Debug(" Decode/InitSnd", gId(), l.debug())
		return conn, message, nil
	case InitRcv:
		connId := Uint64(buffer[HeaderSize : HeaderSize+ConnIdSize])
		conn := l.connMap.Get(connId)
		if conn == nil {
			return nil, nil, errors.New("connection not found for InitRcv")
		}

		// Decode R0 message
		sharedSecret, pubKeyIdRcv, pubKeyEpRcv, message, err := DecodeInitRcv(
			buffer,
			conn.keys.prvKeyEpSnd)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode InitRcv: %w", err)
		}

		conn.keys.pubKeyIdRcv = pubKeyIdRcv
		conn.keys.pubKeyEpRcv = pubKeyEpRcv
		conn.sharedSecret = sharedSecret

		slog.Debug(" Decode/InitRcv", gId(), l.debug())
		return conn, message, nil
	case InitCryptoSnd:
		// Decode crypto S0 message
		connId, pubKeyIdSnd, pubKeyEpSnd, message, err := DecodeInitCryptoSnd(
			buffer,
			l.prvKeyId)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode InitWithCryptoS0: %w", err)
		}
		//we might have received this a multiple times due to retransmission in the first packet
		//however the other side send us this, so we are expected to drop the old keys
		conn := l.connMap.Get(connId)

		var prvKeyEpRcv *ecdh.PrivateKey
		if conn == nil {
			prvKeyEpRcv, err = generateKey()
			if err != nil {
				return nil, nil, fmt.Errorf("failed to generate keys: %w", err)
			}
			conn, err = l.newConn(remoteAddr, prvKeyEpRcv, pubKeyIdSnd, pubKeyEpSnd, false, true)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to create connection: %w", err)
			}
			l.connMap.Put(connId, conn)
		} else {
			prvKeyEpRcv = conn.keys.prvKeyEpSnd
		}

		sharedSecret, err := prvKeyEpRcv.ECDH(pubKeyEpSnd)

		conn.sharedSecret = sharedSecret
		slog.Debug(" Decode/InitCryptoSnd", gId(), l.debug())
		return conn, message, nil
	case InitCryptoRcv:
		connId := Uint64(buffer[HeaderSize : HeaderSize+ConnIdSize])
		conn := l.connMap.Get(connId)
		if conn == nil {
			return nil, nil, errors.New("connection not found for InitWithCryptoR0")
		}

		// Decode crypto R0 message
		sharedSecret, pubKeyEpRcv, message, err := DecodeInitCryptoRcv(buffer, conn.keys.prvKeyEpSnd)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode InitWithCryptoR0: %w", err)
		}

		conn.keys.pubKeyEpRcv = pubKeyEpRcv
		conn.sharedSecret = sharedSecret

		slog.Debug(" Decode/InitCryptoRcv", gId(), l.debug())
		return conn, message, nil
	case Data:
		connId := Uint64(buffer[HeaderSize : HeaderSize+ConnIdSize])
		conn := l.connMap.Get(connId)
		if conn == nil {
			return nil, nil, errors.New("connection not found for DataMessage")
		}

		// Decode Data message
		message, err := DecodeData(buffer, conn.state.isSenderOnInit, conn.epochCryptoRcv, conn.sharedSecret)
		if err != nil {
			return nil, nil, err
		}

		//we decoded conn.epochCrypto + 1, that means we can safely move forward with the epoch
		if message.currentEpochCrypt > conn.epochCryptoRcv {
			conn.epochCryptoRcv = message.currentEpochCrypt
		}

		slog.Debug(" Decode/Data", gId(), l.debug(), slog.Int("l(buffer)", len(buffer)))
		return conn, message, nil
	default:
		return nil, nil, fmt.Errorf("unknown message type: %v", msgType)
	}
}
