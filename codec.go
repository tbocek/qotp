package tomtp

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
)

func (s *Stream) msgType() MsgType {
	switch {
	case !s.conn.state.isHandshakeComplete && s.conn.state.withCrypto && s.conn.state.isSender:
		return InitWithCryptoS0MsgType
	case !s.conn.state.isHandshakeComplete && s.conn.state.withCrypto:
		return InitWithCryptoR0MsgType
	case !s.conn.state.isHandshakeComplete && s.conn.state.isSender:
		return InitHandshakeS0MsgType
	case !s.conn.state.isHandshakeComplete:
		return InitHandshakeR0MsgType
	case s.conn.state.isRoll:
		return Data0MsgType
	default:
		return DataMsgType
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

func (o *Overhead) CalcMaxData() (overhead uint16) {
	if o.debug > 0 {
		return o.debug
	}

	_, tmpOverhead := o.CalcOverhead()

	switch o.msgType {
	case InitHandshakeS0MsgType:
		return 0 //we cannot send data, this is unencrypted
	case InitHandshakeR0MsgType:
		tmpOverhead += MinR0InitHandshakeSize
	case InitWithCryptoS0MsgType:
		tmpOverhead += MinS0CryptoHandshakeSize
	case InitWithCryptoR0MsgType:
		tmpOverhead += MinR0CryptoHandshakeSize
	case Data0MsgType:
		tmpOverhead += MinData0MessageSize
	case DataMsgType:
		tmpOverhead += MinDataMessageSize
	}

	return o.currentMtu - uint16(tmpOverhead)
}

func (s *Stream) encode(origData []byte, offset uint64, ack *Ack, msgType MsgType) ([]byte, MsgType, error) {
	if msgType == -1 {
		msgType = s.msgType()
	}

	// Create payload early for cases that need it
	var payRaw []byte
	var data []byte

	// Special case: InitHandshakeS0 doesn't need payload
	if msgType == InitHandshakeS0MsgType {
		slog.Debug("EncodeInitHandshakeS0", debugGoroutineID(), s.debug())
		data = EncodeInitHandshakeS0(
			s.conn.listener.prvKeyId.PublicKey(),
			s.conn.keys.prvKeyEpSnd,
			s.conn.keys.prvKeyEpSndRoll,
		)
		s.conn.snCrypto++
		return data, msgType, nil
	}

	// Create payload for all other message types
	p := &PayloadMeta{
		IsClose:      s.state == StreamStateClosed || s.state == StreamStateCloseRequest,
		IsSender:     s.conn.state.isSender,
		RcvWndSize:   rcvBufferCapacity - uint64(s.conn.rbRcv.Size()),
		Ack:          ack,
		StreamId:     s.streamId,
		StreamOffset: offset,
	}
	payRaw, _ = EncodePayload(p, origData)

	// Handle message encoding based on connection state
	var err error
	switch msgType {
	case InitWithCryptoS0MsgType:
		slog.Debug("EncodeInitWithCryptoS0", debugGoroutineID(), s.debug(), slog.Int("len(payRaw)", len(payRaw)))
		data, err = EncodeInitWithCryptoS0(
			s.conn.keys.pubKeyIdRcv,
			s.conn.listener.prvKeyId.PublicKey(),
			s.conn.keys.prvKeyEpSnd,
			s.conn.keys.prvKeyEpSndRoll,
			payRaw,
		)
	case InitWithCryptoR0MsgType:
		slog.Debug("EncodeInitWithCryptoR0", debugGoroutineID(), s.debug(), slog.Int("len(payRaw)", len(payRaw)))
		data, err = EncodeInitWithCryptoR0(
			s.conn.keys.pubKeyIdRcv,
			s.conn.listener.prvKeyId.PublicKey(),
			s.conn.keys.pubKeyEpRcv,
			s.conn.keys.prvKeyEpSnd,
			s.conn.keys.prvKeyEpSndRoll,
			payRaw,
		)
	case InitHandshakeR0MsgType:
		slog.Debug("EncodeInitHandshakeR0", debugGoroutineID(), s.debug(), slog.Int("len(payRaw)", len(payRaw)))
		data, err = EncodeInitHandshakeR0(
			s.conn.keys.pubKeyIdRcv,
			s.conn.listener.prvKeyId.PublicKey(),
			s.conn.keys.pubKeyEpRcv,
			s.conn.keys.prvKeyEpSnd,
			s.conn.keys.prvKeyEpSndRoll,
			payRaw,
		)
	case Data0MsgType:
		slog.Debug("EncodeData0", debugGoroutineID(), s.debug(), slog.Int("len(payRaw)", len(payRaw)))
		data, err = EncodeData0(
			s.conn.keys.prvKeyEpSnd.PublicKey(),
			s.conn.keys.pubKeyEpRcv,
			s.conn.state.isSender,
			s.conn.keys.prvKeyEpSndRoll,
			payRaw,
		)
	case DataMsgType:
		slog.Debug("EncodeData", debugGoroutineID(), s.debug(), slog.Int("len(payRaw)", len(payRaw)))
		data, err = EncodeData(
			s.conn.keys.prvKeyEpSnd.PublicKey(),
			s.conn.keys.pubKeyEpRcv,
			s.conn.state.isSender,
			s.conn.sharedSecret,
			s.conn.snCrypto,
			payRaw,
		)
	default:
		return nil, 0, fmt.Errorf("unknown message type: %v", msgType)
	}
	if err != nil {
		return nil, 0, err
	}

	//update state ofter encode of packet
	s.conn.snCrypto++
	return data, msgType, nil
}

func (l *Listener) decode(buffer []byte, remoteAddr netip.AddrPort) (*Connection, *Message, error) {
	origConnId, msgType, err := decodeHeader(buffer)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode header: %w", err)
	}

	switch msgType {
	case InitHandshakeS0MsgType:
		slog.Debug("DecodeInitHandshakeS0", debugGoroutineID(), l.debug(remoteAddr))
		prvKeyEpRcv, prvKeyEpRcvRoll, err := generateTwoKeys()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate keys: %w", err)
		}

		// Decode S0 message
		pubKeyIdSnd, pubKeyEpSnd, pubKeyEpSndRoll, message, err := DecodeInitHandshakeS0(buffer, prvKeyEpRcv)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode InitHandshakeS0: %w", err)
		}

		// Create new connection
		conn, err := l.newConn(
			remoteAddr,
			prvKeyEpRcv,
			prvKeyEpRcvRoll,
			pubKeyIdSnd,
			pubKeyEpSnd,
			pubKeyEpSndRoll,
			false, false)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create connection: %w", err)
		}

		conn.sharedSecret = message.SharedSecret
		return conn, message, nil
	case InitHandshakeR0MsgType:
		slog.Debug("DecodeInitHandshakeR0", debugGoroutineID(), l.debug(remoteAddr))
		conn := l.connMap.Get(origConnId).value
		if conn == nil {
			return nil, nil, errors.New("connection not found for InitHandshakeR0MsgType")
		}
		l.connMap.Remove(origConnId) // only sender ep pub key connId no longer needed, we now have a proper connId

		// Decode R0 message
		pubKeyIdRcv, pubKeyEpRcv, pubKeyEpRcvRoll, message, err := DecodeInitHandshakeR0(
			buffer,
			conn.keys.prvKeyEpSnd)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode InitHandshakeR0: %w", err)
		}

		conn.connId = Uint64(conn.keys.prvKeyEpSnd.PublicKey().Bytes()) ^ Uint64(pubKeyEpRcv.Bytes())
		l.connMap.Put(conn.connId, conn)
		conn.keys.pubKeyIdRcv = pubKeyIdRcv
		conn.keys.pubKeyEpRcv = pubKeyEpRcv
		conn.keys.pubKeyEpRcvRoll = pubKeyEpRcvRoll
		conn.sharedSecret = message.SharedSecret

		return conn, message, nil
	case InitWithCryptoS0MsgType:
		slog.Debug("DecodeInitWithCryptoS0", debugGoroutineID(), l.debug(remoteAddr))
		prvKeyEpRcv, prvKeyEpRcvRoll, err := generateTwoKeys()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate keys: %w", err)
		}

		// Decode crypto S0 message
		pubKeyIdSnd, pubKeyEpSnd, pubKeyEpSndRoll, message, err := DecodeInitWithCryptoS0(
			buffer,
			l.prvKeyId,
			prvKeyEpRcv)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode InitWithCryptoS0: %w", err)
		}

		// Create new connection
		conn, err := l.newConn(
			remoteAddr,
			prvKeyEpRcv,
			prvKeyEpRcvRoll,
			pubKeyIdSnd,
			pubKeyEpSnd,
			pubKeyEpSndRoll,
			false, true)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create connection: %w", err)
		}

		conn.sharedSecret = message.SharedSecret
		return conn, message, nil
	case InitWithCryptoR0MsgType:
		slog.Debug("DecodeInitWithCryptoR0", debugGoroutineID(), l.debug(remoteAddr))
		connP := l.connMap.Get(origConnId)
		if connP == nil {
			return nil, nil, errors.New("connection not found for InitWithCryptoR0")
		}
		conn := connP.value
		l.connMap.Remove(origConnId) // only sender ep pub key connId no longer needed, we now have a proper connId

		// Decode crypto R0 message
		pubKeyEpRcv, pubKeyEpRcvRoll, message, err := DecodeInitWithCryptoR0(buffer, conn.keys.prvKeyEpSnd)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode InitWithCryptoR0: %w", err)
		}

		conn.connId = Uint64(conn.keys.prvKeyEpSnd.PublicKey().Bytes()) ^ Uint64(pubKeyEpRcv.Bytes())
		l.connMap.Put(conn.connId, conn)
		conn.keys.pubKeyEpRcv = pubKeyEpRcv
		conn.keys.pubKeyEpRcvRoll = pubKeyEpRcvRoll
		conn.sharedSecret = message.SharedSecret
		conn.sharedSecret = message.SharedSecret

		return conn, message, nil
	case Data0MsgType:
		conn := l.connMap.Get(origConnId).value
		if conn == nil {
			return nil, nil, errors.New("connection not found for Data0")
		}

		slog.Debug("DecodeData0",
			debugGoroutineID(),
			l.debug(remoteAddr),
			slog.Int("len(buffer)", len(buffer)))

		//rollover - TODO delete(l.connMap, origConnId)

		// Decode Data0 message
		pubKeyEpRoll, message, err := DecodeData0(buffer, conn.state.isSender, conn.keys.prvKeyEpSnd)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode Data0: %w", err)
		}

		conn.keys.pubKeyEpRcvRoll = pubKeyEpRoll
		conn.sharedSecret = message.SharedSecret
		return conn, message, nil
	case DataMsgType:
		conP := l.connMap.Get(origConnId)
		if conP == nil {
			return nil, nil, errors.New("connection not found for DataMessage")
		}
		conn := conP.value

		slog.Debug("DecodeDataMessage",
			debugGoroutineID(),
			l.debug(remoteAddr),
			slog.Int("len(buffer)", len(buffer)))

		// Decode Data message
		message, err := DecodeData(buffer, conn.state.isSender, conn.sharedSecret)
		if err != nil {
			return nil, nil, err
		}
		return conn, message, nil
	default:
		return nil, nil, fmt.Errorf("unknown message type: %v", msgType)
	}
}
