package qotp

import (
	"errors"
	"log/slog"
	"math/bits"
)

const (
	FlagRetryAckShift     = 0
	FlagAckPakShift       = 1
	FlagRcvClosePingShift = 3

	MinProtoSize = 8
	CloseFlag    = uint8(31)
	PingFlag     = uint8(30)
)

type PayloadHeader struct {
	IsNoRetry    bool
	IsClose      bool
	IsPing       bool
	Ack          *Ack
	RcvWndSize   uint64
	StreamID     uint32
	StreamOffset uint64
}

type Ack struct {
	streamID uint32
	offset   uint64
	len      uint16
}

/*
RCV encoding / deconding sizes
encoded | capacity                  | max capacity (human readable)
--------|---------------------------|--------------------------
 0      | 0                         | 0
 1      | 1 - 512                   | 512B
 2      | 513 - 1024                | 1KB
 3      | 1025 - 2048               | 2KB
 4      | 2049 - 4096               | 4KB
 5      | 4097 - 8192               | 8KB
 6      | 8193 - 16384              | 16KB
 7      | 16385 - 32768             | 32KB
 8      | 32769 - 65536             | 64KB
 9      | 65537 - 131072            | 128KB
10      | 131073 - 262144           | 256KB
11      | 262145 - 524288           | 512KB
12      | 524289 - 1048576          | 1MB
13      | 1048577 - 2097152         | 2MB
14      | 2097153 - 4194304         | 4MB
15      | 4194305 - 8388608         | 8MB
16      | 8388609 - 16777216        | 16MB
17      | 16777217 - 33554432       | 32MB
18      | 33554433 - 67108864       | 64MB
19      | 67108865 - 134217728      | 128MB
20      | 134217729 - 268435456     | 256MB
21      | 268435457 - 536870912     | 512MB
22      | 536870913 - 1073741824    | 1GB
23      | 1073741825 - 2147483648   | 2GB
24      | 2147483649 - 4294967296   | 4GB
25      | 4294967297 - 8589934592   | 8GB
26      | 8589934593 - 17179869184  | 16GB
27      | 17179869185 - 34359738368 | 32GB
28      | 34359738369 - 68719476736 | 64GB
29      | 68719476737 - 137438953472| 128GB
*/

func EncodeRcvWindow(actualBytes uint64) uint8 {
	if actualBytes == 0 {
		return 0
	}
	if actualBytes <= 512 {
		return 1
	}
	highBit := bits.Len64(actualBytes-1) - 8
	if highBit > 29 {
		return 29
	}
	return uint8(highBit)
}

func DecodeRcvWindow(encoded uint8) uint64 {
	if encoded == 0 {
		return 0
	}
	return 512 << (encoded - 1) // 512 * 2^(encoded-1)
}

// Determine if we need extended (48-bit) encoding
func EncodePacketType(ack *Ack, dataSeq uint64) (flag uint8, isExtend bool) {
	if ack == nil {
		if dataSeq > 0xFFFFFF {
			return 1, true // No ACK/Data with 48bit, 6 bytes overhead
		}
		return 0, false // No ACK/Data with 24bit, 3 bytes overhead
	} else {
		if dataSeq > 0xFFFFFF || ack.offset > 0xFFFFFF {
			return 3, true // ACK/Data with 48bit, 6 bytes overhead
		}
		return 2, false // ACK/Data with 24bit, 3 bytes overhead
	}
}

func DecodePacketType(packetType uint8) (isAck bool, isExtend bool) {
	switch packetType {
	case 0:
		return false, false // No ACK/Data with 24bit
	case 1:
		return false, true // No ACK/Data with 48bit
	case 2:
		return true, false // ACK/Data with 24bit
	case 3:
		return true, true // ACK/Data with 48bit
	default:
		// Handle invalid packet type (optional)
		return false, false // Default to simplest case
	}
}

func EncodePayload(p *PayloadHeader, userData []byte) (encoded []byte, offset int) {
	// Calculate flags
	var flags uint8

	// Ping flag
	if p.IsNoRetry {
		flags = 1 << FlagRetryAckShift
	}

	// Ack flags
	ackPak, isExtend := EncodePacketType(p.Ack, p.StreamOffset)
	flags |= ackPak << FlagAckPakShift

	// Close / RcvWnd Flag
	if p.IsClose {
		flags |= CloseFlag << FlagRcvClosePingShift
	} else if p.IsPing {
		flags |= PingFlag << FlagRcvClosePingShift
	} else {
		rcvClose := EncodeRcvWindow(p.RcvWndSize)
		flags |= rcvClose << FlagRcvClosePingShift
	}

	// Allocate buffer
	userDataLen := len(userData)
	overhead := calcProtoOverhead(p.Ack != nil, isExtend)
	encoded = make([]byte, overhead+userDataLen)

	// Write header
	encoded[offset] = flags
	offset++

	// Write ACKs section if present
	if p.Ack != nil {
		// Write ACKs
		offset += PutUint32(encoded[offset:], p.Ack.streamID)
		if isExtend {
			offset += PutUint48(encoded[offset:], p.Ack.offset)
		} else {
			offset += PutUint24(encoded[offset:], p.Ack.offset)
		}
		offset += PutUint16(encoded[offset:], p.Ack.len)
	}

	// Write Data
	offset += PutUint32(encoded[offset:], p.StreamID)

	if isExtend {
		offset += PutUint48(encoded[offset:], p.StreamOffset)
	} else {
		offset += PutUint24(encoded[offset:], p.StreamOffset)
	}

	if userDataLen > 0 {
		offset += copy(encoded[offset:], userData)
	}

	return encoded, offset
}

func DecodePayload(data []byte) (payload *PayloadHeader, userData []byte, err error) {
	dataLen := len(data)
	if dataLen < MinProtoSize {
		slog.Error("payload size too low", "dataLen", dataLen, "MinProtoSize", MinProtoSize)
		return nil, nil, errors.New("payload Size below minimum of 8 bytes")
	}

	offset := 0
	payload = &PayloadHeader{}

	// Flags (8 bits)
	flags := data[offset]

	payload.IsNoRetry = flags&1 != 0

	ackPack := (flags >> FlagAckPakShift) & 3
	isAck, isExtend := DecodePacketType(ackPack)

	rcvClose := flags >> FlagRcvClosePingShift
	if rcvClose == CloseFlag {
		payload.IsClose = true
	} else if rcvClose == PingFlag {
		payload.IsPing = true
	} else {
		payload.RcvWndSize = DecodeRcvWindow(rcvClose)
	}
	offset++ //we processed the header

	//now we know the correct header size, check again
	overhead := calcProtoOverhead(isAck, isExtend)
	if dataLen < overhead {
		return nil, nil, errors.New("payload Size below minimum")
	}

	// Decode ACKs if present
	if isAck {
		payload.Ack = &Ack{}
		payload.Ack.streamID = Uint32(data[offset:])
		offset += 4
		if isExtend {
			payload.Ack.offset = Uint48(data[offset:])
			offset += 6
		} else {
			payload.Ack.offset = Uint24(data[offset:])
			offset += 3
		}
		payload.Ack.len = Uint16(data[offset:])
		offset += 2
	}

	// Decode Data
	payload.StreamID = Uint32(data[offset:])
	offset += 4

	if isExtend {
		payload.StreamOffset = Uint48(data[offset:])
		offset += 6
	} else {
		payload.StreamOffset = Uint24(data[offset:])
		offset += 3
	}

	if dataLen > offset {
		userData = make([]byte, dataLen-offset)
		copy(userData, data[offset:dataLen])
		offset += dataLen
	} else {
		userData = make([]byte, 0)
	}

	return payload, userData, nil
}

func calcProtoOverhead(isAck, isExtend bool) (overhead int) {
	overhead = 1 + 4 + 3 //header + 32bit + 24bit
	if isExtend {
		overhead += 3 //in total 6 bytes for 48bit, we already counted 24bit, so just add 3
	}
	if isAck {
		overhead += 4 + 3 + 2 //32bit + 24bit + 16bit
		if isExtend {
			overhead += 3 //in total 6 bytes for 48bit, we already counted 24bit, so just add 3
		}
	}
	return overhead
}
