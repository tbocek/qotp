package qotp

import (
	"crypto/ecdh"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
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

func CalcMaxOverhead(msgType MsgType, ack *Ack, offset uint64) (overhead int) {
	hasAck := ack != nil
	needsExtension := (hasAck && ack.offset > 0xFFFFFF) || offset > 0xFFFFFF

	overhead = calcOverhead(hasAck, needsExtension)

	switch msgType {
	case InitSnd:
		return -1 //we cannot send data, this is unencrypted
	case InitRcv:
		overhead += MinInitRcvSizeHdr + FooterDataSize
	case InitCryptoSnd:
		overhead += MinInitCryptoSndSizeHdr + FooterDataSize + MsgInitFillLenSize
	case InitCryptoRcv:
		overhead += MinInitCryptoRcvSizeHdr + FooterDataSize
	case Data:
		overhead += MinDataSizeHdr + FooterDataSize
	}

	return overhead
}

func (conn *Connection) encode(p *PayloadHeader, userData []byte, msgType MsgType) (encData []byte, err error) {
	// Create payload early for cases that need it
	var packetData []byte

	slog.Debug("  Encode", gId(), conn.debug(),
		slog.Int("l(userData)", len(userData)),
		slog.String("b…", string(userData[:min(16, len(userData))])))

	// Handle message encoding based on connection state
	switch msgType {
	case InitSnd:
		_, encData = EncodeInitSnd(
			conn.listener.prvKeyId.PublicKey(),
			conn.keys.prvKeyEpSnd.PublicKey(),
		)
		conn.state.isInitSentOnSnd = true
		slog.Debug("   Encode/InitSnd", gId(), conn.debug(),
			slog.Int("l(encData)", len(encData)))
	case InitCryptoSnd:
		packetData, _ = EncodePayload(p, userData)
		_, encData, err = EncodeInitCryptoSnd(
			conn.keys.pubKeyIdRcv,
			conn.listener.prvKeyId.PublicKey(),
			conn.keys.prvKeyEpSnd,
			conn.snCrypto,
			packetData,
		)
		if err != nil {
			return nil, err
		}
		conn.state.isInitSentOnSnd = true
		slog.Debug("   Encode/InitCryptoSnd", gId(), conn.debug(),
			slog.Int("l(packetData)", len(packetData)),
			slog.Int("l(encData)", len(encData)))
	case InitCryptoRcv:
		packetData, _ = EncodePayload(p, userData)
		encData, err = EncodeInitCryptoRcv(
			conn.connId,
			conn.keys.pubKeyEpRcv,
			conn.keys.prvKeyEpSnd,
			conn.snCrypto,
			packetData,
		)
		if err != nil {
			return nil, err
		}
		conn.state.isInitSentOnSnd = true
		slog.Debug("   Encode/InitCryptoRcv", gId(), conn.debug(),
			slog.Int("l(packetData)", len(packetData)),
			slog.Int("l(encData)", len(encData)))
	case InitRcv:
		packetData, _ = EncodePayload(p, userData)
		encData, err = EncodeInitRcv(
			conn.connId,
			conn.listener.prvKeyId.PublicKey(),
			conn.keys.pubKeyEpRcv,
			conn.keys.prvKeyEpSnd,
			conn.snCrypto,
			packetData,
		)
		if err != nil {
			return nil, err
		}
		conn.state.isInitSentOnSnd = true
		slog.Debug("   Encode/InitRcv", gId(), conn.debug(),
			slog.Int("l(packetData)", len(packetData)),
			slog.Int("l(encData)", len(encData)))
	case Data:
		packetData, _ = EncodePayload(p, userData)
		encData, err = EncodeData(
			conn.connId,
			conn.state.isSenderOnInit,
			conn.sharedSecret,
			conn.snCrypto,
			conn.epochCryptoSnd,
			packetData,
		)
		if err != nil {
			return nil, err
		}
		slog.Debug("   Encode/Data", gId(), conn.debug(),
			slog.Int("len(payRaw)", len(packetData)),
			slog.Int("len(dataEnc)", len(encData)))
	default:
		return nil, errors.New("unknown message type")
	}

	//update state ofter encode of packet
	conn.snCrypto++
	//rollover
	if conn.snCrypto > (1<<48)-1 {
		if conn.epochCryptoSnd+1 > (1<<47)-1 { //47, as the last bit is used for sender / receiver differentiation
			//TODO: quic has key rotation (via bitflip)
			return nil, errors.New("exhausted 2^95 sn number, cannot continue, you just sent ~5 billion ZettaBytes. " +
				"Now you need to reconnect manually. This is roughly 28 million times all the data humanity has ever created.")
		}
		conn.epochCryptoSnd++
		conn.snCrypto = 0
	}
	return encData, nil
}

func (l *Listener) decode(buffer []byte, remoteAddr netip.AddrPort) (conn *Connection, payload []byte, msgType MsgType, err error) {

	// Read the header byte and connId
	if len(buffer) < MinPacketSize {
		return nil, nil, 0, fmt.Errorf("header needs to be at least %v bytes", MinPacketSize)
	}

	header := buffer[0]
	version := header >> 3

	if version != Version {
		return nil, nil, 0, errors.New("unsupported version version")
	}

	msgType = MsgType(header & 0x07)

	connId := Uint64(buffer[HeaderSize : ConnIdSize+HeaderSize])

	slog.Debug("  Decode", gId(), l.debug(), slog.Int("l(data)", len(buffer)), slog.Any("msgType", msgType))

	switch msgType {
	case InitSnd:
		// Decode S0 message
		pubKeyIdSnd, pubKeyEpSnd, err := DecodeInitSnd(buffer)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("failed to decode InitHandshakeS0: %w", err)
		}
		conn := l.connMap.Get(connId)
		//we might have received this a multiple times due to retransmission in the first packet
		//however the other side send us this, so we are expected to drop the old keys
		var prvKeyEpRcv *ecdh.PrivateKey
		if conn == nil {
			prvKeyEpRcv, err = generateKey()
			if err != nil {
				return nil, nil, 0, fmt.Errorf("failed to generate keys: %w", err)
			}
			conn, err = l.newConn(connId, remoteAddr, prvKeyEpRcv, pubKeyIdSnd, pubKeyEpSnd, false, false)
			if err != nil {
				return nil, nil, 0, fmt.Errorf("failed to create connection: %w", err)
			}
			l.connMap.Put(connId, conn)
		} else {
			prvKeyEpRcv = conn.keys.prvKeyEpSnd
		}

		sharedSecret, err := prvKeyEpRcv.ECDH(pubKeyEpSnd)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("failed to create connection: %w", err)
		}
		conn.sharedSecret = sharedSecret
		slog.Debug(" Decode/InitSnd", gId(), l.debug())
		return conn, []byte{}, InitSnd, nil
	case InitRcv:
		connId := Uint64(buffer[HeaderSize : HeaderSize+ConnIdSize])
		conn := l.connMap.Get(connId)
		if conn == nil {
			return nil, nil, 0, errors.New("connection not found for InitRcv")
		}

		// Decode R0 message
		sharedSecret, pubKeyIdRcv, pubKeyEpRcv, message, err := DecodeInitRcv(
			buffer,
			conn.keys.prvKeyEpSnd)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("failed to decode InitRcv: %w", err)
		}

		conn.keys.pubKeyIdRcv = pubKeyIdRcv
		conn.keys.pubKeyEpRcv = pubKeyEpRcv
		conn.sharedSecret = sharedSecret

		slog.Debug(" Decode/InitRcv", gId(), l.debug())
		return conn, message.PayloadRaw, InitRcv, nil
	case InitCryptoSnd:
		// Decode crypto S0 message
		pubKeyIdSnd, pubKeyEpSnd, message, err := DecodeInitCryptoSnd(
			buffer,
			l.prvKeyId)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("failed to decode InitWithCryptoS0: %w", err)
		}
		//we might have received this a multiple times due to retransmission in the first packet
		//however the other side send us this, so we are expected to drop the old keys
		conn := l.connMap.Get(connId)

		var prvKeyEpRcv *ecdh.PrivateKey
		if conn == nil {
			prvKeyEpRcv, err = generateKey()
			if err != nil {
				return nil, nil, 0, fmt.Errorf("failed to generate keys: %w", err)
			}
			conn, err = l.newConn(connId, remoteAddr, prvKeyEpRcv, pubKeyIdSnd, pubKeyEpSnd, false, true)
			if err != nil {
				return nil, nil, 0, fmt.Errorf("failed to create connection: %w", err)
			}
			l.connMap.Put(connId, conn)
		} else {
			prvKeyEpRcv = conn.keys.prvKeyEpSnd
		}

		sharedSecret, err := prvKeyEpRcv.ECDH(pubKeyEpSnd)

		conn.sharedSecret = sharedSecret
		slog.Debug(" Decode/InitCryptoSnd", gId(), l.debug())
		return conn, message.PayloadRaw, InitCryptoSnd, nil
	case InitCryptoRcv:
		connId := Uint64(buffer[HeaderSize : HeaderSize+ConnIdSize])
		conn := l.connMap.Get(connId)
		if conn == nil {
			return nil, nil, 0, errors.New("connection not found for InitWithCryptoR0")
		}

		// Decode crypto R0 message
		sharedSecret, pubKeyEpRcv, message, err := DecodeInitCryptoRcv(buffer, conn.keys.prvKeyEpSnd)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("failed to decode InitWithCryptoR0: %w", err)
		}

		conn.keys.pubKeyEpRcv = pubKeyEpRcv
		conn.sharedSecret = sharedSecret

		slog.Debug(" Decode/InitCryptoRcv", gId(), l.debug())
		return conn, message.PayloadRaw, InitCryptoRcv, nil
	case Data:
		connId := Uint64(buffer[HeaderSize : HeaderSize+ConnIdSize])
		conn := l.connMap.Get(connId)
		if conn == nil {
			slog.Debug("Looking for connection", slog.Uint64("connId", connId), slog.Int("available", l.connMap.Size()))
			return nil, nil, 0, errors.New("connection not found for DataMessage")
		}

		// Decode Data message
		message, err := DecodeData(buffer, conn.state.isSenderOnInit, conn.epochCryptoRcv, conn.sharedSecret)
		if err != nil {
			return nil, nil, 0, err
		}

		//we decoded conn.epochCrypto + 1, that means we can safely move forward with the epoch
		if message.currentEpochCrypt > conn.epochCryptoRcv {
			conn.epochCryptoRcv = message.currentEpochCrypt
		}

		slog.Debug(" Decode/Data", gId(), l.debug(), slog.Int("l(buffer)", len(buffer)))
		return conn, message.PayloadRaw, Data, nil
	default:
		return nil, nil, 0, fmt.Errorf("unknown message type: %v", msgType)
	}
}

func decodeHex(pubKeyHex string) ([]byte, error) {
	if strings.HasPrefix(pubKeyHex, "0x") {
		pubKeyHex = strings.Replace(pubKeyHex, "0x", "", 1)
	}

	return hex.DecodeString(pubKeyHex)
}

// //////////////////////////////////////////
func PutUint16(b []byte, v uint16) int {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	return 2
}

func PutUint24(b []byte, v uint64) int {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	return 3
}

func PutUint32(b []byte, v uint32) int {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	return 4
}

func PutUint48(b []byte, v uint64) int {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	b[4] = byte(v >> 32)
	b[5] = byte(v >> 40)
	return 6
}

func PutUint64(b []byte, v uint64) int {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	b[4] = byte(v >> 32)
	b[5] = byte(v >> 40)
	b[6] = byte(v >> 48)
	b[7] = byte(v >> 56)
	return 8
}

func Uint16(b []byte) uint16 {
	return uint16(b[0]) | uint16(b[1])<<8
}

func Uint24(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16
}

func Uint32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func Uint48(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 |
		uint64(b[3])<<24 | uint64(b[4])<<32 | uint64(b[5])<<40
}

func Uint64(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}
