package tomtp

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
)

func (s *Stream) msgType() MsgType {
	switch {
	case !s.conn.isHandshakeComplete && s.conn.withCrypto && s.conn.isSender:
		return InitWithCryptoS0MsgType
	case !s.conn.isHandshakeComplete && s.conn.withCrypto:
		return InitWithCryptoR0MsgType
	case !s.conn.isHandshakeComplete && s.conn.isSender:
		return InitHandshakeS0MsgType
	case !s.conn.isHandshakeComplete:
		return InitHandshakeR0MsgType
	case s.conn.isRollover:
		return Data0MsgType
	default:
		return DataMsgType
	}
}

func (s *Stream) Overhead(hasAck bool) (overhead int) {
	protoOverhead := CalcProtoOverhead(hasAck)

	msgType := s.msgType()
	switch msgType {
	case InitHandshakeS0MsgType:
		return MinS0InitHandshakeSize //we cannot send data, this is unencrypted
	case InitHandshakeR0MsgType:
		return protoOverhead + MinR0InitHandshakeSize
	case InitWithCryptoS0MsgType:
		return protoOverhead + MinS0CryptoHandshakeSize
	case InitWithCryptoR0MsgType:
		return protoOverhead + MinR0CryptoHandshakeSize
	case Data0MsgType:
		return protoOverhead + MinData0MessageSize
	default: //case DataMsgType:
		return protoOverhead + MinDataMessageSize
	}
}

func (s *Stream) encode(origData []byte, offset uint64, ack *Ack, msgType MsgType) ([]byte, MsgType, error) {
	p := &PayloadMeta{
		IsClose:      s.state == StreamStateClosed || s.state == StreamStateCloseRequest,
		IsSender:     s.conn.isSender,
		RcvWndSize:   initBufferCapacity - uint64(s.conn.rbRcv.Size()),
		Ack:          ack,
		StreamId:     s.streamId,
		StreamOffset: offset,
	}

	if msgType == -1 {
		msgType = s.msgType()
	}

	// Create payload early for cases that need it
	var payRaw []byte
	var data []byte
	var err error

	// Only encode payload if not InitHandshakeS0 (which doesn't need it)
	if msgType != InitHandshakeS0MsgType {
		payRaw, _, err = EncodePayload(p, origData)
		if err != nil {
			return nil, -1, err
		}
	}

	// Handle message encoding based on connection state
	switch msgType {
	case InitWithCryptoS0MsgType:
		slog.Debug("EncodeInitWithCryptoS0", debugGoroutineID(), s.debug(), slog.Int("len(payRaw)", len(payRaw)))
		data, err = EncodeInitWithCryptoS0(
			s.conn.pubKeyIdRcv,
			s.conn.listener.prvKeyId.PublicKey(),
			s.conn.prvKeyEpSnd,
			s.conn.prvKeyEpSndRollover,
			payRaw,
		)
	case InitWithCryptoR0MsgType:
		slog.Debug("EncodeInitWithCryptoR0", debugGoroutineID(), s.debug(), slog.Int("len(payRaw)", len(payRaw)))
		data, err = EncodeInitWithCryptoR0(
			s.conn.pubKeyIdRcv,
			s.conn.listener.prvKeyId.PublicKey(),
			s.conn.pubKeyEpRcv,
			s.conn.prvKeyEpSnd,
			s.conn.prvKeyEpSndRollover,
			payRaw,
		)
	case InitHandshakeS0MsgType:
		slog.Debug("EncodeInitHandshakeS0", debugGoroutineID(), s.debug())
		data = EncodeInitHandshakeS0(
			s.conn.listener.prvKeyId.PublicKey(),
			s.conn.prvKeyEpSnd,
			s.conn.prvKeyEpSndRollover,
			s.conn.connId,
		)
	case InitHandshakeR0MsgType:
		slog.Debug("EncodeInitHandshakeR0", debugGoroutineID(), s.debug(), slog.Int("len(payRaw)", len(payRaw)))
		data, err = EncodeInitHandshakeR0(
			s.conn.pubKeyIdRcv,
			s.conn.listener.prvKeyId.PublicKey(),
			s.conn.pubKeyEpRcv,
			s.conn.prvKeyEpSnd,
			s.conn.prvKeyEpSndRollover,
			s.conn.connId,
			payRaw,
		)
	case Data0MsgType:
		slog.Debug("EncodeData0", debugGoroutineID(), s.debug(), slog.Int("len(payRaw)", len(payRaw)))
		data, err = EncodeData0(
			s.conn.prvKeyEpSnd.PublicKey(),
			s.conn.pubKeyEpRcv,
			s.conn.isSender,
			s.conn.prvKeyEpSndRollover,
			payRaw,
		)
	default: //case DataMsgType:
		slog.Debug("EncodeData", debugGoroutineID(), s.debug(), slog.Int("len(payRaw)", len(payRaw)))
		data, err = EncodeData(
			s.conn.prvKeyEpSnd.PublicKey(),
			s.conn.pubKeyEpRcv,
			s.conn.isSender,
			s.conn.sharedSecret,
			s.conn.snCrypto,
			payRaw,
		)
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
		// Generate keys for the receiver
		prvKeyEpRcv, prvKeyEpRcvRollover, err := generateTwoKeys()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate keys: %w", err)
		}

		slog.Debug("DecodeInitHandshakeS0",
			debugGoroutineID(),
			l.debug(remoteAddr),
			debugPrvKey("prvKeyEpRcv", prvKeyEpRcv))

		// Decode S0 message
		pubKeyIdSnd, pubKeyEpSnd, pubKeyEpSndRollover, message, err := DecodeInitHandshakeS0(
			buffer,
			prvKeyEpRcv)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode InitHandshakeS0: %w", err)
		}

		// Create new connection
		conn, err := l.newConn(
			remoteAddr,
			prvKeyEpRcv,
			prvKeyEpRcvRollover,
			pubKeyIdSnd,
			pubKeyEpSnd,
			pubKeyEpSndRollover,
			false, false)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create connection: %w", err)
		}

		conn.sharedSecret = message.SharedSecret
		return conn, message, nil
	case InitHandshakeR0MsgType:
		conn := l.connMap.Get(origConnId).value
		if conn == nil {
			return nil, nil, errors.New("connection not found for InitHandshakeR0MsgType")
		}
		l.connMap.Remove(origConnId) // only sender ep pub key connId no longer needed, we now have a proper connId

		slog.Debug("DecodeInitHandshakeR0",
			debugGoroutineID(),
			l.debug(remoteAddr),
			debugPrvKey("prvKeyEpSnd", conn.prvKeyEpSnd))

		// Decode R0 message
		pubKeyIdRcv, pubKeyEpRcv, pubKeyEpRcvRollover, message, err := DecodeInitHandshakeR0(
			buffer,
			conn.prvKeyEpSnd)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode InitHandshakeR0: %w", err)
		}

		conn.connId = Uint64(conn.prvKeyEpSnd.PublicKey().Bytes()) ^ Uint64(pubKeyEpRcv.Bytes())
		l.connMap.Put(conn.connId, conn)
		conn.pubKeyIdRcv = pubKeyIdRcv
		conn.pubKeyEpRcv = pubKeyEpRcv
		conn.pubKeyEpRcvRollover = pubKeyEpRcvRollover
		conn.sharedSecret = message.SharedSecret

		return conn, message, nil
	case InitWithCryptoS0MsgType:
		// Generate keys for the receiver
		prvKeyEpRcv, prvKeyEpRcvRollover, err := generateTwoKeys()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate keys: %w", err)
		}

		slog.Debug("DecodeInitWithCryptoS0",
			debugGoroutineID(),
			l.debug(remoteAddr),
			debugPrvKey("privKeyId", l.prvKeyId),
			debugPrvKey("prvKeyEpRcv", prvKeyEpRcv))

		// Decode crypto S0 message
		pubKeyIdSnd, pubKeyEpSnd, pubKeyEpSndRollover, message, err := DecodeInitWithCryptoS0(
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
			prvKeyEpRcvRollover,
			pubKeyIdSnd,
			pubKeyEpSnd,
			pubKeyEpSndRollover,
			false, true)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create connection: %w", err)
		}

		conn.sharedSecret = message.SharedSecret
		return conn, message, nil
	case InitWithCryptoR0MsgType:
		connP := l.connMap.Get(origConnId)
		if connP == nil {
			return nil, nil, errors.New("connection not found for InitWithCryptoR0")
		}
		conn := connP.value
		l.connMap.Remove(origConnId) // only sender ep pub key connId no longer needed, we now have a proper connId

		slog.Debug("DecodeInitWithCryptoR0", debugGoroutineID(), l.debug(remoteAddr))

		// Decode crypto R0 message
		pubKeyEpRcv, pubKeyEpRcvRollover, message, err := DecodeInitWithCryptoR0(buffer, conn.prvKeyEpSnd)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode InitWithCryptoR0: %w", err)
		}

		conn.connId = Uint64(conn.prvKeyEpSnd.PublicKey().Bytes()) ^ Uint64(pubKeyEpRcv.Bytes())
		l.connMap.Put(conn.connId, conn)
		conn.pubKeyEpRcv = pubKeyEpRcv
		conn.pubKeyEpRcvRollover = pubKeyEpRcvRollover
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
		pubKeyEpRollover, message, err := DecodeData0(buffer, conn.isSender, conn.prvKeyEpSnd)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode Data0: %w", err)
		}

		conn.pubKeyEpRcvRollover = pubKeyEpRollover
		conn.sharedSecret = message.SharedSecret
		return conn, message, nil
	default: //case DataMsgType:
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
		message, err := DecodeData(buffer, conn.isSender, conn.sharedSecret)
		if err != nil {
			return nil, nil, err
		}
		return conn, message, nil
	}
}
