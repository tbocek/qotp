package qotp

import (
	"errors"
	"math/bits"
)

const (
	FlagSenderShift   = 0
	FlagAckPakShift   = 1
	FlagRcvCloseShift = 3

	MinProtoSize = 8
	CloseFlag    = 31
)

var (
	ErrPayloadTooSmall = errors.New("payload Size below minimum of 8 bytes")
)

type PayloadHeader struct {
	IsClose      bool
	IsSender     bool
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

/*
encoded | actualBytes range        | decoded value (middle)
--------|--------------------------|------------------------
0       | 0-511                    | 0
1       | 512-1023                 | 768
2       | 1024-2047                | 1536 (1.5KB)
3       | 2048-4095                | 3072 (3KB)
4       | 4096-8191                | 6144 (6KB)
5       | 8192-16383               | 12288 (12KB)
6       | 16384-32767              | 24576 (24KB)
7       | 32768-65535              | 49152 (48KB)
8       | 65536-131071             | 98304 (96KB)
9       | 131072-262143            | 196608 (192KB)
10      | 262144-524287            | 393216 (384KB)
11      | 524288-1048575           | 786432 (768KB)
12      | 1048576-2097151          | 1572864 (1.5MB)
13      | 2097152-4194303          | 3145728 (3MB)
14      | 4194304-8388607          | 6291456 (6MB)
15      | 8388608-16777215         | 12582912 (12MB)
16      | 16777216-33554431        | 25165824 (24MB)
17      | 33554432-67108863        | 50331648 (48MB)
18      | 67108864-134217727       | 100663296 (96MB)
19      | 134217728-268435455      | 201326592 (192MB)
20      | 268435456-536870911      | 402653184 (384MB)
21      | 536870912-1073741823     | 805306368 (768MB)
22      | 1073741824-2147483647    | 1610612736 (1.5GB)
23      | 2147483648-4294967295    | 3221225472 (3GB)
24      | 4294967296-8589934591    | 6442450944 (6GB)
25      | 8589934592-17179869183   | 12884901888 (12GB)
26      | 17179869184-34359738367  | 25769803776 (24GB)
27      | 34359738368-68719476735  | 51539607552 (48GB)
28      | 68719476736-137438953471 | 103079215104 (96GB)
29      | 137438953472-274877906943| 206158430208 (192GB)
30      | 274877906944+            | 412316860416 (384GB)
*/
func DecodeRcvWindow(encoded uint8) uint64 {
	if encoded == 0 {
		return 0
	}
	return 768 << (encoded - 1)
}

func EncodeRcvWindow(actualBytes uint64) uint8 {
	if actualBytes < 512 {
		return 0
	}
	highBit := bits.Len64(actualBytes >> 9) // Divide by 512
	if highBit > 30 {
		return 30
	}
	return uint8(highBit)
}

func EncodePacketType(hasAck bool, ackSeq uint64, dataSeq uint64) uint8 {
	// Determine if we need extended (48-bit) encoding
	needsExtended := ackSeq > 0xFFFFFF || dataSeq > 0xFFFFFF

	// Handle the different cases more clearly
	if !hasAck {
		if needsExtended {
			return 1 // No ACK/Data with 48bit
		}
		return 0 // No ACK/Data with 24bit
	}

	// hasAck is true
	if needsExtended {
		return 3 // ACK/Data with 48bit
	}
	return 2 // ACK/Data with 24bit
}

func DecodePacketType(packetType uint8) (hasAck bool, needsExtended bool) {
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

	if p.IsSender {
		flags = 1 << FlagSenderShift
	}

	var ackPak uint8
	if p.Ack != nil {
		ackPak = EncodePacketType(true, p.Ack.offset, p.StreamOffset)
	} else {
		ackPak = EncodePacketType(false, 0, p.StreamOffset)
	}
	flags |= ackPak << FlagAckPakShift

	var rcvClose uint8
	if p.IsClose {
		rcvClose = CloseFlag
	} else {
		rcvClose = EncodeRcvWindow(p.RcvWndSize)
	}
	flags |= rcvClose << FlagRcvCloseShift

	// Calculate total size of header
	o := &Overhead{ack: p.Ack, dataOffset: p.StreamOffset}
	needExtend, overhead := o.CalcOverhead()
	// Allocate buffer
	dataLen := len(userData)
	encoded = make([]byte, int(overhead)+dataLen)

	// Write header
	encoded[offset] = flags
	offset++

	// Write ACKs section if present
	if p.Ack != nil {
		// Write ACKs
		offset += PutUint32(encoded[offset:], p.Ack.streamID)
		if needExtend {
			offset += PutUint48(encoded[offset:], p.Ack.offset)
		} else {
			offset += PutUint24(encoded[offset:], p.Ack.offset)
		}
		offset += PutUint16(encoded[offset:], p.Ack.len)
	}

	// Write Data
	offset += PutUint32(encoded[offset:], p.StreamID)

	if needExtend {
		offset += PutUint48(encoded[offset:], p.StreamOffset)
	} else {
		offset += PutUint24(encoded[offset:], p.StreamOffset)
	}

	if dataLen > 0 {
		offset += copy(encoded[offset:], userData)
	}

	return encoded, offset
}

func DecodePayload(data []byte) (payload *PayloadHeader, offset int, userData []byte, err error) {
	dataLen := len(data)
	if dataLen < MinProtoSize {
		return nil, 0, nil, ErrPayloadTooSmall
	}

	offset = 0
	payload = &PayloadHeader{}

	// Flags (8 bits)
	flags := data[offset]

	payload.IsSender = flags&1 != 0

	ackPack := (flags >> FlagAckPakShift) & 3
	ack, needsExtended := DecodePacketType(ackPack)
	expectedSize := CalcProtoOverhead(ack, needsExtended)
	if offset+expectedSize > dataLen {
		return nil, 0, nil, ErrPayloadTooSmall
	}

	rcvClose := flags >> FlagRcvCloseShift
	if rcvClose == CloseFlag {
		payload.IsClose = true
	} else {
		payload.RcvWndSize = DecodeRcvWindow(rcvClose)
	}
	offset++

	// Decode ACKs if present
	if ack {
		payload.Ack = &Ack{}
		payload.Ack.streamID = Uint32(data[offset:])
		offset += 4
		if needsExtended {
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

	if needsExtended {
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

	return payload, offset, userData, nil
}
