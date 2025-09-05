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
	case !s.conn.state.isHandshakeDoneOnRcv && s.conn.state.isWithCryptoOnInit:
		return InitCryptoRcv
	case !s.conn.state.isHandshakeDoneOnRcv && s.conn.state.isSenderOnInit:
		return InitSnd
	case !s.conn.state.isHandshakeDoneOnRcv:
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
		)
		slog.Debug("   Encode/InitSnd",
			getGoroutineID(),
			s.debug(),
			slog.Int("len(dataEnc)", len(encData)),
			slog.Uint64("snCrypto", s.conn.snCrypto),
			slog.Uint64("epochCryptoSnd", s.conn.epochCryptoSnd),
			slog.Uint64("epochCryptoRcv", s.conn.epochCryptoRcv))
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
			s.conn.epochCryptoSnd,
			packetData,
		)
		if err != nil {
			return nil, err
		}
		s.conn.state.isInitSentOnSnd = true
		slog.Debug("   Encode/InitCryptoSnd",
			getGoroutineID(),
			s.debug(),
			slog.Int("len(dataProto)", len(packetData)),
			slog.Int("len(dataEnc)", len(encData)),
			slog.Uint64("snCrypto", s.conn.snCrypto),
			slog.Uint64("epochCryptoSnd", s.conn.epochCryptoSnd),
			slog.Uint64("epochCryptoRcv", s.conn.epochCryptoRcv))
	case InitCryptoRcv:
		encData, err = EncodeInitCryptoRcv(
			s.conn.keys.pubKeyIdRcv,
			s.conn.listener.prvKeyId.PublicKey(),
			s.conn.keys.pubKeyEpRcv,
			s.conn.keys.prvKeyEpSnd,
			s.conn.snCrypto,
			s.conn.epochCryptoSnd,
			packetData,
		)
		if err != nil {
			return nil, err
		}
		s.conn.state.isInitSentOnSnd = true
		slog.Debug("   Encode/InitCryptoRcv",
			getGoroutineID(),
			s.debug(),
			slog.Int("len(dataProto)", len(packetData)),
			slog.Int("len(dataEnc)", len(encData)),
			slog.Uint64("snCrypto", s.conn.snCrypto),
			slog.Uint64("epochCryptoSnd", s.conn.epochCryptoSnd),
			slog.Uint64("epochCryptoRcv", s.conn.epochCryptoRcv))
	case InitRcv:
		encData, err = EncodeInitRcv(
			s.conn.keys.pubKeyIdRcv,
			s.conn.listener.prvKeyId.PublicKey(),
			s.conn.keys.pubKeyEpRcv,
			s.conn.keys.prvKeyEpSnd,
			s.conn.snCrypto,
			s.conn.epochCryptoSnd,
			packetData,
		)
		if err != nil {
			return nil, err
		}
		s.conn.state.isInitSentOnSnd = true
		slog.Debug("   Encode/InitRcv",
			getGoroutineID(),
			s.debug(),
			slog.Int("len(dataProto)", len(packetData)),
			slog.Int("len(dataEnc)", len(encData)),
			slog.Uint64("snCrypto", s.conn.snCrypto),
			slog.Uint64("epochCryptoSnd", s.conn.epochCryptoSnd),
			slog.Uint64("epochCryptoRcv", s.conn.epochCryptoRcv))
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
		slog.Debug("   Encode/Data",
			getGoroutineID(),
			s.debug(),
			slog.Int("len(payRaw)", len(packetData)),
			slog.Int("len(dataEnc)", len(encData)),
			slog.Uint64("snCrypto", s.conn.snCrypto),
			slog.Uint64("epochCryptoSnd", s.conn.epochCryptoSnd),
			slog.Uint64("epochCryptoRcv", s.conn.epochCryptoRcv))
	default:
		return nil, fmt.Errorf("unknown message type: %v", msgType)
	}

	//update state ofter encode of packet
	s.conn.snCrypto++
	//rollover
	if s.conn.snCrypto > (1<<48)-1 {
		if s.conn.epochCryptoSnd+1 > (1<<47)-1 {
			//TODO: quic has key rotation (via bitflip), but this adds complexity and 2^96 bytes is a lot.
			return nil, errors.New("exhausted 2^95 sn number, cannot continue, you just sent ~34'000'000 ZettaBytes. Now you need to reconnect manually. This is roughly 200'000 times all the data humanity has ever created!")
		}
		s.conn.epochCryptoSnd++
		s.conn.snCrypto = 0
	}
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
		pubKeyIdSnd, pubKeyEpSnd, message, err := DecodeInitSnd(buffer, prvKeyEpRcv)
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
		pubKeyIdRcv, pubKeyEpRcv, message, err := DecodeInitRcv(
			buffer,
			conn.keys.prvKeyEpSnd)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode InitRcv: %w", err)
		}

		conn.connId = Uint64(conn.keys.prvKeyEpSnd.PublicKey().Bytes()) ^ Uint64(pubKeyEpRcv.Bytes())
		l.connMap.Put(conn.connId, conn)
		conn.keys.pubKeyIdRcv = pubKeyIdRcv
		conn.keys.pubKeyEpRcv = pubKeyEpRcv
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
		pubKeyIdSnd, pubKeyEpSnd, message, err := DecodeInitCryptoSnd(
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
		pubKeyEpRcv, message, err := DecodeInitCryptoRcv(buffer, conn.keys.prvKeyEpSnd)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode InitWithCryptoR0: %w", err)
		}

		conn.connId = Uint64(conn.keys.prvKeyEpSnd.PublicKey().Bytes()) ^ Uint64(pubKeyEpRcv.Bytes())
		l.connMap.Put(conn.connId, conn)
		conn.keys.pubKeyEpRcv = pubKeyEpRcv
		conn.sharedSecret = message.SharedSecret

		slog.Debug(" Decode/InitCryptoRcv", getGoroutineID(), l.debug())
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
		message, err := DecodeData(buffer, conn.state.isSenderOnInit, conn.epochCryptoRcv, conn.sharedSecret)
		if err != nil {
			return nil, nil, err
		}
		
		//we decoded conn.epochCrypto + 1, that means we can safely move forward with the epoch
		if message.currentEpochCrypt > conn.epochCryptoRcv {
			conn.epochCryptoRcv = message.currentEpochCrypt
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
