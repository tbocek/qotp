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
		return InitCryptoSnd
	case !s.conn.state.isHandshakeComplete && s.conn.state.withCrypto:
		return InitCryptoRcv
	case !s.conn.state.isHandshakeComplete && s.conn.state.isSender:
		return InitSnd
	case !s.conn.state.isHandshakeComplete:
		return InitRcv
	case s.conn.state.isRoll:
		return DataRot
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

func (o *Overhead) CalcMaxData() (overhead uint16) {
	if o.debug > 0 {
		return o.debug
	}

	_, tmpOverhead := o.CalcOverhead()

	switch o.msgType {
	case InitSnd:
		return 0 //we cannot send data, this is unencrypted
	case InitRcv:
		tmpOverhead += MinInitRcvSize
	case InitCryptoSnd:
		tmpOverhead += MinInitCryptoSndSize
	case InitCryptoRcv:
		tmpOverhead += MinInitCryptoRcvSize
	case DataRot:
		tmpOverhead += MinDataRotSize
	case Data:
		tmpOverhead += MinDataSize
	}

	return o.currentMtu - uint16(tmpOverhead)
}

func (s *Stream) encode(origData []byte, offset uint64, ack *Ack, msgType MsgType) (dataEnc []byte, err error) {
	// Create payload early for cases that need it
	var dataProto []byte
	
	slog.Debug("Encode", debugGoroutineID(), s.debug(), slog.Uint64("offset", offset), slog.Int("len(data)", len(origData)))

	// Special case: InitHandshakeS0 doesn't need payload
	if msgType == InitSnd {
		dataEnc = EncodeInitSnd(
			s.conn.listener.prvKeyId.PublicKey(),
			s.conn.keys.prvKeyEpSnd,
			s.conn.keys.prvKeyEpSndRoll,
		)
		slog.Debug("Encode/InitSnd", 
			debugGoroutineID(), 
			s.debug(), 
			slog.Int("len(dataEnc)", len(dataEnc)), 
			slog.Uint64("snCrypto", s.conn.snCrypto))
		s.conn.snCrypto++
		return dataEnc, nil
	}

	// Create payload for all other message types
	p := &PayloadMeta{
		IsClose:      s.state == StreamStateClosed || s.state == StreamStateCloseRequest,
		IsSender:     s.conn.state.isSender,
		RcvWndSize:   rcvBufferCapacity - uint64(s.conn.rcvBuf.Size()),
		Ack:          ack,
		StreamId:     s.streamId,
		StreamOffset: offset,
	}
	dataProto, _ = EncodePayload(p, origData)

	// Handle message encoding based on connection state
	switch msgType {
	case InitCryptoSnd:
		dataEnc, err = EncodeInitCryptoSnd(
			s.conn.keys.pubKeyIdRcv,
			s.conn.listener.prvKeyId.PublicKey(),
			s.conn.keys.prvKeyEpSnd,
			s.conn.keys.prvKeyEpSndRoll,
			dataProto,
		)
		if err != nil {
			return nil, err
		}
		slog.Debug("Encode/InitCryptoSnd", 
			debugGoroutineID(), 
			s.debug(), 
			slog.Int("len(dataProto)", len(dataProto)), 
			slog.Int("len(dataEnc)", len(dataEnc)), 
			slog.Uint64("snCrypto", s.conn.snCrypto))
	case InitCryptoRcv:
		dataEnc, err = EncodeInitCryptoRcv(
			s.conn.keys.pubKeyIdRcv,
			s.conn.listener.prvKeyId.PublicKey(),
			s.conn.keys.pubKeyEpRcv,
			s.conn.keys.prvKeyEpSnd,
			s.conn.keys.prvKeyEpSndRoll,
			dataProto,
		)
		if err != nil {
			return nil, err
		}
		slog.Debug("Encode/InitCryptoRcv", 
			debugGoroutineID(), 
			s.debug(), 
			slog.Int("len(dataProto)", len(dataProto)), 
			slog.Int("len(dataEnc)", len(dataEnc)), 
			slog.Uint64("snCrypto", s.conn.snCrypto))
	case InitRcv:
		dataEnc, err = EncodeInitRcv(
			s.conn.keys.pubKeyIdRcv,
			s.conn.listener.prvKeyId.PublicKey(),
			s.conn.keys.pubKeyEpRcv,
			s.conn.keys.prvKeyEpSnd,
			s.conn.keys.prvKeyEpSndRoll,
			dataProto,
		)
		if err != nil {
			return nil, err
		}
		slog.Debug("Encode/InitRcv", 
			debugGoroutineID(), 
			s.debug(), 
			slog.Int("len(dataProto)", len(dataProto)), 
			slog.Int("len(dataEnc)", len(dataEnc)), 
			slog.Uint64("snCrypto", s.conn.snCrypto))
	case DataRot:
		dataEnc, err = EncodeDataRot(
			s.conn.keys.prvKeyEpSnd.PublicKey(),
			s.conn.keys.pubKeyEpRcv,
			s.conn.state.isSender,
			s.conn.keys.prvKeyEpSndRoll,
			dataProto,
		)
		if err != nil {
			return nil, err
		}
		slog.Debug("Encode/DataRot", 
			debugGoroutineID(), 
			s.debug(), 
			slog.Int("len(payRaw)", len(dataProto)), 
			slog.Int("len(dataEnc)", len(dataEnc)), 
			slog.Uint64("snCrypto", s.conn.snCrypto))
	case Data:
		dataEnc, err = EncodeData(
			s.conn.keys.prvKeyEpSnd.PublicKey(),
			s.conn.keys.pubKeyEpRcv,
			s.conn.state.isSender,
			s.conn.sharedSecret,
			s.conn.snCrypto,
			dataProto,
		)
		if err != nil {
			return nil, err
		}
		slog.Debug("Encode/Data", 
			debugGoroutineID(), 
			s.debug(), 
			slog.Int("len(payRaw)", len(dataProto)), 
			slog.Int("len(dataEnc)", len(dataEnc)), 
			slog.Uint64("snCrypto", s.conn.snCrypto))
	default:
		return nil, fmt.Errorf("unknown message type: %v", msgType)
	}
	
	//update state ofter encode of packet
	s.conn.snCrypto++
	return dataEnc, nil
}

func (l *Listener) decode(buffer []byte, remoteAddr netip.AddrPort) (*Connection, *Message, error) {
	origConnId, msgType, err := decodeHeader(buffer)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode header: %w", err)
	}
	
	slog.Debug("Decode", debugGoroutineID(), l.debug(), slog.Int("len(data)", len(buffer)))

	switch msgType {
	case InitSnd:
		slog.Debug("DecodeInitHandshakeS0", debugGoroutineID(), l.debug())
		prvKeyEpRcv, prvKeyEpRcvRoll, err := generateTwoKeys()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate keys: %w", err)
		}

		// Decode S0 message
		pubKeyIdSnd, pubKeyEpSnd, pubKeyEpSndRoll, message, err := DecodeInitSnd(buffer, prvKeyEpRcv)
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
	case InitRcv:
		slog.Debug("DecodeInitHandshakeR0", debugGoroutineID(), l.debug())
		conn := l.connMap.Get(origConnId).value
		if conn == nil {
			return nil, nil, errors.New("connection not found for InitHandshakeR0MsgType")
		}
		l.connMap.Remove(origConnId) // only sender ep pub key connId no longer needed, we now have a proper connId

		// Decode R0 message
		pubKeyIdRcv, pubKeyEpRcv, pubKeyEpRcvRoll, message, err := DecodeInitRcv(
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
	case InitCryptoSnd:
		slog.Debug("Decode/InitCryptoSnd", debugGoroutineID(), l.debug())
		prvKeyEpRcv, prvKeyEpRcvRoll, err := generateTwoKeys()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate keys: %w", err)
		}

		// Decode crypto S0 message
		pubKeyIdSnd, pubKeyEpSnd, pubKeyEpSndRoll, message, err := DecodeInitCryptoSnd(
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
	case InitCryptoRcv:
		slog.Debug("DecodeInitWithCryptoR0", debugGoroutineID(), l.debug())
		connP := l.connMap.Get(origConnId)
		if connP == nil {
			return nil, nil, errors.New("connection not found for InitWithCryptoR0")
		}
		conn := connP.value
		l.connMap.Remove(origConnId) // only sender ep pub key connId no longer needed, we now have a proper connId

		// Decode crypto R0 message
		pubKeyEpRcv, pubKeyEpRcvRoll, message, err := DecodeInitCryptoRcv(buffer, conn.keys.prvKeyEpSnd)
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
	case DataRot:
		conn := l.connMap.Get(origConnId).value
		if conn == nil {
			return nil, nil, errors.New("connection not found for Data0")
		}

		slog.Debug("DecodeData0",
			debugGoroutineID(),
			l.debug(),
			slog.Int("len(buffer)", len(buffer)))

		//rollover - TODO delete(l.connMap, origConnId)

		// Decode Data0 message
		pubKeyEpRoll, message, err := DecodeDataRot(buffer, conn.state.isSender, conn.keys.prvKeyEpSnd)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode Data0: %w", err)
		}

		conn.keys.pubKeyEpRcvRoll = pubKeyEpRoll
		conn.sharedSecret = message.SharedSecret
		return conn, message, nil
	case Data:
		conP := l.connMap.Get(origConnId)
		if conP == nil {
			return nil, nil, errors.New("connection not found for DataMessage")
		}
		conn := conP.value

		slog.Debug("DecodeDataMessage",
			debugGoroutineID(),
			l.debug(),
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
