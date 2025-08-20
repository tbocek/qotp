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
	case !s.conn.state.isHandshakeComplete && s.conn.state.withCrypto && s.conn.state.isSender:
		return InitCryptoSnd
	case !s.conn.state.isHandshakeComplete && s.conn.state.withCrypto:
		return InitCryptoRcv
	case !s.conn.state.isHandshakeComplete && s.conn.state.isSender:
		return InitSnd
	case !s.conn.state.isHandshakeComplete:
		return InitRcv
	case s.conn.state.isRoll:
		return DataRoll
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
	case DataRoll:
		tmpOverhead += MinDataRotSize
	case Data:
		tmpOverhead += MinDataSize
	}

	return o.currentMtu - uint16(tmpOverhead)
}

func (s *Stream) encode(userData []byte, offset uint64, ack *Ack, msgType MsgType) (encData []byte, err error) {
	// Create payload early for cases that need it
	var packetData []byte

	slog.Debug("  Encode", 
		getGoroutineID(), 
		s.debug(), 
		slog.Uint64("offset", offset), 
		slog.Int("len(data)", len(userData)), 
		slog.String("b…", string(userData[:min(16, len(userData))])))

	// Special case: InitHandshakeS0 doesn't need payload
	if msgType == InitSnd {
		encData = EncodeInitSnd(
			s.conn.listener.prvKeyId.PublicKey(),
			s.conn.keys.prvKeyEpSnd,
			s.conn.keys.prvKeyEpSndRoll,
		)
		slog.Debug("   Encode/InitSnd",
			getGoroutineID(),
			s.debug(),
			slog.Int("len(dataEnc)", len(encData)),
			slog.Uint64("snCrypto", s.conn.snCrypto))
		s.conn.snCrypto++
		return encData, nil
	}

	// Create payload for all other message types
	p := &PayloadHeader{
		IsClose:      s.state == StreamStateClosed || s.state == StreamStateCloseRequest,
		IsSender:     s.conn.state.isSender,
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
			s.conn.keys.prvKeyEpSndRoll,
			packetData,
		)
		if err != nil {
			return nil, err
		}
		slog.Debug("   Encode/InitCryptoSnd",
			getGoroutineID(),
			s.debug(),
			slog.Int("len(dataProto)", len(packetData)),
			slog.Int("len(dataEnc)", len(encData)),
			slog.Uint64("snCrypto", s.conn.snCrypto))
	case InitCryptoRcv:
		encData, err = EncodeInitCryptoRcv(
			s.conn.keys.pubKeyIdRcv,
			s.conn.listener.prvKeyId.PublicKey(),
			s.conn.keys.pubKeyEpRcv,
			s.conn.keys.prvKeyEpSnd,
			s.conn.keys.prvKeyEpSndRoll,
			packetData,
		)
		if err != nil {
			return nil, err
		}
		slog.Debug("   Encode/InitCryptoRcv",
			getGoroutineID(),
			s.debug(),
			slog.Int("len(dataProto)", len(packetData)),
			slog.Int("len(dataEnc)", len(encData)),
			slog.Uint64("snCrypto", s.conn.snCrypto))
	case InitRcv:
		encData, err = EncodeInitRcv(
			s.conn.keys.pubKeyIdRcv,
			s.conn.listener.prvKeyId.PublicKey(),
			s.conn.keys.pubKeyEpRcv,
			s.conn.keys.prvKeyEpSnd,
			s.conn.keys.prvKeyEpSndRoll,
			packetData,
		)
		if err != nil {
			return nil, err
		}
		slog.Debug("   Encode/InitRcv",
			getGoroutineID(),
			s.debug(),
			slog.Int("len(dataProto)", len(packetData)),
			slog.Int("len(dataEnc)", len(encData)),
			slog.Uint64("snCrypto", s.conn.snCrypto))
	case DataRoll:
		encData, err = EncodeDataRot(
			s.conn.keys.prvKeyEpSnd.PublicKey(),
			s.conn.keys.pubKeyEpRcv,
			s.conn.state.isSender,
			s.conn.keys.prvKeyEpSndRoll,
			packetData,
		)
		if err != nil {
			return nil, err
		}
		slog.Debug("   Encode/DataRot",
			getGoroutineID(),
			s.debug(),
			slog.Int("len(payRaw)", len(packetData)),
			slog.Int("len(dataEnc)", len(encData)),
			slog.Uint64("snCrypto", s.conn.snCrypto))
	case Data:
		encData, err = EncodeData(
			s.conn.keys.prvKeyEpSnd.PublicKey(),
			s.conn.keys.pubKeyEpRcv,
			s.conn.state.isSender,
			s.conn.sharedSecret,
			s.conn.snCrypto,
			packetData,
		)
		if err != nil {
			return nil, err
		}
		slog.Debug("   Encode/Data",
			getGoroutineID(),
			s.debug(),
			slog.Int("len(payRaw)", len(packetData)),
			slog.Int("len(dataEnc)", len(encData)),
			slog.Uint64("snCrypto", s.conn.snCrypto))
	default:
		return nil, fmt.Errorf("unknown message type: %v", msgType)
	}

	//update state ofter encode of packet
	s.conn.snCrypto++
	return encData, nil
}

func (l *Listener) decode(buffer []byte, remoteAddr netip.AddrPort) (*Connection, *Message, error) {
	origConnId, msgType, err := decodeHeader(buffer)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode header: %w", err)
	}
	slog.Debug("  Decode", getGoroutineID(), l.debug(), slog.Int("len(data)", len(buffer)), slog.Any("msgType", msgType))

	switch msgType {
	case InitSnd:
		//we might have received this a multiple times due to retransmission in the first packet
		//however the other side send us this, so we are expected to drop the old keys
		conn := l.connMap.Get(origConnId)
		
		var prvKeyEpRcv *ecdh.PrivateKey
		var prvKeyEpRcvRoll *ecdh.PrivateKey
		if conn == nil {
			prvKeyEpRcv, prvKeyEpRcvRoll, err = generateTwoKeys()
			if err != nil {
				return nil, nil, fmt.Errorf("failed to generate keys: %w", err)
			}
		} else {
			prvKeyEpRcv = conn.keys.prvKeyEpSnd
			prvKeyEpRcvRoll = conn.keys.prvKeyEpSndRoll
		}

		// Decode S0 message
		pubKeyIdSnd, pubKeyEpSnd, pubKeyEpSndRoll, message, err := DecodeInitSnd(buffer, prvKeyEpRcv)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode InitHandshakeS0: %w", err)
		}

		// We need to reuse the connection and just replace the keys in case of duplicates. Otherwise
		// we will have the situtaion that we already inserted 1 package in our buffer, delivered it to the user
		// and here we would initialize from scratch, which results that the duplicate data will be
		// sent to the user
		if conn == nil {
			conn, err = l.newConn(
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
			//this is tricky: we need to store the first message on the receiver side twice, once under the old id, once under the new id
			//in case of duplicate, we need to find the right connection, and if we already store it under the new, then duplciate data
			// will arrive. That also means, we need to remove the old id on the first data packet
			l.connMap.Put(origConnId, conn)
		}
		
		conn.sharedSecret = message.SharedSecret
		slog.Debug(" Decode/InitSnd", getGoroutineID(), l.debug())
		return conn, message, nil
	case InitRcv:
		conn := l.connMap.Get(origConnId)
		if conn == nil {
			return nil, nil, errors.New("connection not found for InitRcv")
		}
		l.connMap.Remove(origConnId) // only sender ep pub key connId no longer needed, we now have a proper connId

		// Decode R0 message
		pubKeyIdRcv, pubKeyEpRcv, pubKeyEpRcvRoll, message, err := DecodeInitRcv(
			buffer,
			conn.keys.prvKeyEpSnd)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode InitRcv: %w", err)
		}

		conn.connId = Uint64(conn.keys.prvKeyEpSnd.PublicKey().Bytes()) ^ Uint64(pubKeyEpRcv.Bytes())
		l.connMap.Put(conn.connId, conn)
		conn.keys.pubKeyIdRcv = pubKeyIdRcv
		conn.keys.pubKeyEpRcv = pubKeyEpRcv
		conn.keys.pubKeyEpRcvRoll = pubKeyEpRcvRoll
		conn.sharedSecret = message.SharedSecret

		slog.Debug(" Decode/InitRcv", getGoroutineID(), l.debug())
		return conn, message, nil
	case InitCryptoSnd:
		//we might have received this a multiple times due to retransmission in the first packet
		//however the other side send us this, so we are expected to drop the old keys
		conn := l.connMap.Get(origConnId)
		
		var prvKeyEpRcv *ecdh.PrivateKey
		var prvKeyEpRcvRoll *ecdh.PrivateKey
		if conn == nil {
			prvKeyEpRcv, prvKeyEpRcvRoll, err = generateTwoKeys()
			if err != nil {
				return nil, nil, fmt.Errorf("failed to generate keys: %w", err)
			}
		} else {
			prvKeyEpRcv = conn.keys.prvKeyEpSnd
			prvKeyEpRcvRoll = conn.keys.prvKeyEpSndRoll
		}

		// Decode crypto S0 message
		pubKeyIdSnd, pubKeyEpSnd, pubKeyEpSndRoll, message, err := DecodeInitCryptoSnd(
			buffer,
			l.prvKeyId,
			prvKeyEpRcv)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode InitWithCryptoS0: %w", err)
		}

		// We need to reuse the connection and just replace the keys in case of duplicates. Otherwise
		// we will have the situtaion that we already inserted 1 package in our buffer, delivered it to the user
		// and here we would initialize from scratch, which results that the duplicate data will be
		// sent to the user
		if conn == nil {
			conn, err = l.newConn(
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
			//this is tricky: we need to store the first message on the receiver side twice, once under the old id, once under the new id
			//in case of duplicate, we need to find the right connection, and if we already store it under the new, then duplciate data
			// will arrive. That also means, we need to remove the old id on the first data packet
			l.connMap.Put(origConnId, conn)
		}

		conn.sharedSecret = message.SharedSecret
		slog.Debug(" Decode/InitCryptoSnd", getGoroutineID(), l.debug())
		return conn, message, nil
	case InitCryptoRcv:
		conn := l.connMap.Get(origConnId)
		if conn == nil {
			return nil, nil, errors.New("connection not found for InitWithCryptoR0")
		}
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

		slog.Debug(" Decode/InitCryptoRcv", getGoroutineID(), l.debug())
		return conn, message, nil
	case DataRoll:
		conn := l.connMap.Get(origConnId)
		if conn == nil {
			return nil, nil, errors.New("connection not found for Data0")
		}
		
		//only needs to be done right after the handshake
		firstConnId := Uint64(conn.keys.pubKeyEpRcv.Bytes())
		l.connMap.Remove(firstConnId)

		//rollover - TODO delete(l.connMap, origConnId)

		// Decode Data0 message
		pubKeyEpRoll, message, err := DecodeDataRot(buffer, conn.state.isSender, conn.keys.prvKeyEpSnd)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode Data0: %w", err)
		}

		conn.keys.pubKeyEpRcvRoll = pubKeyEpRoll
		conn.sharedSecret = message.SharedSecret

		slog.Debug(" Decode/DataRot",
			getGoroutineID(),
			l.debug(),
			slog.Int("len(buffer)", len(buffer)))
		return conn, message, nil
	case Data:
		conn := l.connMap.Get(origConnId)
		if conn == nil {
			return nil, nil, errors.New("connection not found for DataMessage")
		}
		
		//only needs to be done right after the handshake
		firstConnId := Uint64(conn.keys.pubKeyEpRcv.Bytes())
		l.connMap.Remove(firstConnId)

		// Decode Data message
		message, err := DecodeData(buffer, conn.state.isSender, conn.sharedSecret)
		if err != nil {
			return nil, nil, err
		}

		slog.Debug(" Decode/Data",
			getGoroutineID(),
			l.debug(),
			slog.Int("len(buffer)", len(buffer)))
		return conn, message, nil
	default:
		return nil, nil, fmt.Errorf("unknown message type: %v", msgType)
	}
}
