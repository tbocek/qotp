package qotp

import (
	"bytes"
	"crypto/ecdh"
	"encoding/binary"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/netip"
	"testing"
)

var (
	seed1 = [32]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	seed2 = [32]byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	seed3 = [32]byte{3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	seed4 = [32]byte{4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	seed5 = [32]byte{5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	seed6 = [32]byte{6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}

	prvIdAlice, _     = ecdh.X25519().NewPrivateKey(seed1[:])
	prvIdBob, _       = ecdh.X25519().NewPrivateKey(seed2[:])
	prvEpAlice, _     = ecdh.X25519().NewPrivateKey(seed3[:])
	prvEpBob, _       = ecdh.X25519().NewPrivateKey(seed4[:])
	prvEpAliceRoll, _ = ecdh.X25519().NewPrivateKey(seed5[:])
	prvEpBobRoll, _   = ecdh.X25519().NewPrivateKey(seed6[:])
)

// Test encoding when stream or connection is closed
func TestStreamEncodeClosedStates(t *testing.T) {
	// Setup base connection
	conn := &Connection{
		rcv: NewReceiveBuffer(1000),
		keys: ConnectionKeys{
			pubKeyEpRcv:     prvEpBob.PublicKey(),
			prvKeyEpSnd:     prvEpAlice,
			pubKeyIdRcv:     prvIdAlice.PublicKey(),
			prvKeyEpSndRoll: prvEpAliceRoll,
		},
		sharedSecret: bytes.Repeat([]byte{1}, 32),
		listener:     &Listener{prvKeyId: prvIdAlice},
		streams:      NewLinkedMap[uint32, *Stream](),
	}

	// Test stream closed
	stream := conn.Stream(1)
	stream.Close()
	output, err := stream.encode([]byte("test data"), 0, nil, stream.msgType())
	assert.NotNil(t, output)
	assert.Nil(t, err)

	// Test connection closed
	stream2 := conn.Stream(2)
	stream2.conn.Close()
	output, err = stream2.encode([]byte("test data"), 0, nil, stream2.msgType())
	assert.NotNil(t, output)
	assert.Nil(t, err)
}

// Test all handshake message types
func TestStreamEncodeHandshakeTypes(t *testing.T) {
	testCases := []struct {
		name         string
		isSender     bool
		withCrypto   bool
		expectedType MsgType
		hasData      bool
	}{
		{"InitHandshakeS0", true, false, InitSnd, false},
		{"InitHandshakeR0", false, false, InitRcv, true},
		{"InitWithCryptoS0", true, true, InitCryptoSnd, true},
		{"InitWithCryptoR0", false, true, InitCryptoRcv, true},
	}

	for _, tc := range testCases {
		conn := &Connection{
			state: ConnectionState{
				isSender:   tc.isSender,
				withCrypto: tc.withCrypto,
			},
			snCrypto: 0,
			mtu:      1400,
			keys: ConnectionKeys{
				pubKeyIdRcv:     prvIdBob.PublicKey(),
				prvKeyEpSnd:     prvEpAlice,
				prvKeyEpSndRoll: prvEpAliceRoll,
			},
			listener: &Listener{prvKeyId: prvIdAlice},
			rcv:    NewReceiveBuffer(1000),
		}

		if !tc.isSender {
			conn.keys.pubKeyIdRcv = prvIdAlice.PublicKey()
			conn.keys.pubKeyEpRcv = prvEpAlice.PublicKey()
		}

		stream := &Stream{conn: conn}

		var input []byte
		if tc.hasData {
			input = []byte("test data")
		}

		output, err := stream.encode(input, 0, nil, stream.msgType())
		assert.NoError(t, err, tc.name)
		assert.NotNil(t, output, tc.name)

		// Verify message type
		_, msgType, err := decodeHeader(output)
		assert.NoError(t, err, tc.name)
		assert.Equal(t, tc.expectedType, msgType, tc.name)
	}
}

// Test data message types (Data0 and Data)
func TestStreamEncodeDataTypes(t *testing.T) {
	// Test Data0 (rollover)
	connRollover := &Connection{
		state: ConnectionState{
			isHandshakeComplete: true,
			isSender:            true,
			isRoll:              true,
		},
		snCrypto: 1,
		mtu:      1400,
		keys: ConnectionKeys{
			pubKeyIdRcv:     prvIdBob.PublicKey(),
			prvKeyEpSnd:     prvEpAlice,
			prvKeyEpSndRoll: prvEpAliceRoll,
			pubKeyEpRcv:     prvEpBob.PublicKey(),
		},
		listener:     &Listener{prvKeyId: prvIdAlice},
		rcv:        NewReceiveBuffer(1000),
		sharedSecret: seed1[:],
		streams:      NewLinkedMap[uint32, *Stream](),
	}

	streamRollover := &Stream{conn: connRollover}
	output, err := streamRollover.encode([]byte("rollover data"), 0, nil, streamRollover.msgType())
	assert.NoError(t, err)
	assert.NotNil(t, output)
	_, msgType, _ := decodeHeader(output)
	assert.Equal(t, DataRoll, msgType)

	// Test regular Data message
	connData := &Connection{
		state: ConnectionState{
			isHandshakeComplete: true,
			isSender:            true,
			isRoll:              false,
		},
		snCrypto: 1,
		mtu:      1400,
		keys: ConnectionKeys{
			pubKeyIdRcv: prvIdBob.PublicKey(),
			prvKeyEpSnd: prvEpAlice,
			pubKeyEpRcv: prvEpBob.PublicKey(),
		},
		listener:     &Listener{prvKeyId: prvIdAlice},
		rcv:        NewReceiveBuffer(1000),
		sharedSecret: seed1[:],
		streams:      NewLinkedMap[uint32, *Stream](),
	}

	streamData := &Stream{conn: connData}
	output, err = streamData.encode([]byte("regular data"), 0, nil, streamData.msgType())
	assert.NoError(t, err)
	assert.NotNil(t, output)
	_, msgType, _ = decodeHeader(output)
	assert.Equal(t, Data, msgType)
}

// Test end-to-end codec with various data sizes
func TestEndToEndCodec(t *testing.T) {
	dataSizes := []int{0, 100, 1000, 2000, 10000}

	for _, size := range dataSizes {
		// Setup listeners
		lAlice := &Listener{
			connMap:  NewLinkedMap[uint64, *Connection](),
			prvKeyId: prvIdAlice,
		}
		lBob := &Listener{
			connMap:  NewLinkedMap[uint64, *Connection](),
			prvKeyId: prvIdBob,
		}

		// Create Alice's connection
		connAlice := &Connection{
			state: ConnectionState{
				isSender:   true,
				withCrypto: true,
			},
			snCrypto: 0,
			mtu:      1400,
			keys: ConnectionKeys{
				pubKeyIdRcv:     prvIdBob.PublicKey(),
				prvKeyEpSnd:     prvEpAlice,
				prvKeyEpSndRoll: prvEpAliceRoll,
			},
			listener: lAlice,
			snd:    NewSendBuffer(rcvBufferCapacity),
			rcv:    NewReceiveBuffer(12000),
			streams:  NewLinkedMap[uint32, *Stream](),
		}
		connId := binary.LittleEndian.Uint64(prvEpAlice.PublicKey().Bytes())
		lAlice.connMap.Put(connId, connAlice)
		connAlice.connId = connId

		streamAlice := &Stream{conn: connAlice}

		// Create test data
		testData := make([]byte, size)
		for i := 0; i < len(testData); i++ {
			testData[i] = byte(i % 256)
		}

		// Encode
		encoded, err := streamAlice.encode(testData, 0, nil, streamAlice.msgType())
		require.NoError(t, err, fmt.Sprintf("Size %d", size))
		require.NotNil(t, encoded, fmt.Sprintf("Size %d", size))

		// Decode at Bob's side
		a, _ := netip.ParseAddr("127.0.0.1")
		remoteAddr := netip.AddrPortFrom(a, uint16(8080))

		connBob, m, err := lBob.decode(encoded, remoteAddr)
		require.NoError(t, err, fmt.Sprintf("Size %d", size))

		// Only process payload if we have data
		if size > 0 || m.MsgType == InitCryptoRcv {
			s, err := connBob.decode(m.PayloadRaw, 0, 0)
			require.NoError(t, err, fmt.Sprintf("Size %d", size))

			if size > 0 {
				_, rb := s.conn.rcv.RemoveOldestInOrder(s.streamID)
				assert.Equal(t, testData, rb, fmt.Sprintf("Data mismatch for Size %d", size))
			}
		}
	}
}

// Test full handshake flow
func TestFullHandshakeFlow(t *testing.T) {
	// Setup listeners
	lAlice := &Listener{
		connMap:  NewLinkedMap[uint64, *Connection](),
		prvKeyId: prvIdAlice,
	}
	lBob := &Listener{
		connMap:  NewLinkedMap[uint64, *Connection](),
		prvKeyId: prvIdBob,
	}

	a, _ := netip.ParseAddr("127.0.0.1")
	remoteAddr := netip.AddrPortFrom(a, uint16(8080))

	// Test InitHandshakeS0 -> InitHandshakeR0 flow
	connAlice := &Connection{
		connId: Uint64(prvEpAlice.PublicKey().Bytes()),
		state: ConnectionState{
			isSender: true,
		},
		snCrypto: 0,
		mtu:      1400,
		keys: ConnectionKeys{
			prvKeyEpSnd:     prvEpAlice,
			prvKeyEpSndRoll: prvEpAliceRoll,
		},
		listener: lAlice,
		rcv:    NewReceiveBuffer(1000),
		streams:  NewLinkedMap[uint32, *Stream](),
	}
	lAlice.connMap.Put(connAlice.connId, connAlice)

	streamAlice := &Stream{conn: connAlice}

	// Alice encodes InitHandshakeS0
	encoded, err := streamAlice.encode(nil, 0, nil, streamAlice.msgType())
	require.NoError(t, err)
	require.NotNil(t, encoded)

	// Bob receives and decodes InitHandshakeS0
	connBob, msgS0, err := lBob.decode(encoded, remoteAddr)
	require.NoError(t, err)
	require.NotNil(t, connBob)
	require.Equal(t, InitSnd, msgS0.MsgType)

	// Bob responds with InitHandshakeR0
	streamBob := &Stream{conn: connBob}
	testData := []byte("handshake response")
	encodedR0, err := streamBob.encode(testData, 0, nil, streamBob.msgType())
	require.NoError(t, err)
	require.NotNil(t, encodedR0)

	// Alice receives and decodes InitHandshakeR0
	c, m, err := lAlice.decode(encodedR0, remoteAddr)
	require.NoError(t, err)
	s, err := c.decode(m.PayloadRaw, 0, 0)
	require.NoError(t, err)
	_, rb := s.conn.rcv.RemoveOldestInOrder(s.streamID)
	require.Equal(t, InitRcv, m.MsgType)
	require.Equal(t, testData, rb)

	// Test Data message flow after handshake
	connId := binary.LittleEndian.Uint64(prvIdAlice.PublicKey().Bytes()) ^ binary.LittleEndian.Uint64(prvIdBob.PublicKey().Bytes())

	// Setup established connections
	connAlice.state.isHandshakeComplete = true
	connAlice.keys.pubKeyIdRcv = prvIdBob.PublicKey()
	connAlice.keys.pubKeyEpRcv = prvEpBob.PublicKey()
	connAlice.sharedSecret = seed1[:]
	lAlice.connMap.Put(connId, connAlice)

	connBob.state.isHandshakeComplete = true
	connBob.sharedSecret = seed1[:]
	lBob.connMap.Put(connId, connBob)

	// Alice sends Data message
	dataMsg := []byte("data message")
	encoded, err = streamAlice.encode(dataMsg, 0, nil, streamAlice.msgType())
	require.NoError(t, err)
	require.NotNil(t, encoded)

	// Bob receives and decodes Data message
	c, msg, err := lBob.decode(encoded, remoteAddr)
	require.NoError(t, err)
	require.NotNil(t, c)
	require.Equal(t, Data, msg.MsgType)

	s, err = c.decode(msg.PayloadRaw, 0, 0)
	require.NoError(t, err)
	_, rb = s.conn.rcv.RemoveOldestInOrder(s.streamID)
	require.Equal(t, dataMsg, rb)
}

// Test msgType() function
func TestStreamMsgType(t *testing.T) {
	testCases := []struct {
		isHandshakeComplete bool
		withCrypto          bool
		isSender            bool
		isRollover          bool
		expected            MsgType
	}{
		{false, true, true, false, InitCryptoSnd},
		{false, true, false, false, InitCryptoRcv},
		{false, false, true, false, InitSnd},
		{false, false, false, false, InitRcv},
		{true, false, false, true, DataRoll},
		{true, false, false, false, Data},
	}

	for _, tc := range testCases {
		conn := &Connection{
			state: ConnectionState{
				isHandshakeComplete: tc.isHandshakeComplete,
				withCrypto:          tc.withCrypto,
				isSender:            tc.isSender,
				isRoll:              tc.isRollover,
			},
		}
		stream := &Stream{conn: conn}
		assert.Equal(t, tc.expected, stream.msgType())
	}
}

// Test Overhead calculations
func TestOverheadCalculations(t *testing.T) {
	testCases := []struct {
		ack        *Ack
		dataOffset uint64
		msgType    MsgType
		mtu        uint16
		maxData    uint16
	}{
		{nil, 100, InitSnd, 1400, 0},
		{nil, 100, InitRcv, 1400, uint16(1400 - CalcProtoOverhead(false, false) - MinInitRcvSize)},
		{&Ack{offset: 0xFFFFFF + 1}, 100, Data, 1400, uint16(1400 - CalcProtoOverhead(true, true) - MinDataSize)},
		{nil, 0xFFFFFF + 1, Data, 1400, uint16(1400 - CalcProtoOverhead(false, true) - MinDataSize)},
	}

	for i, tc := range testCases {
		o := &Overhead{
			ack:        tc.ack,
			dataOffset: tc.dataOffset,
			msgType:    tc.msgType,
			currentMtu: tc.mtu,
		}
		maxData := o.CalcMaxData()
		assert.Equal(t, tc.maxData, maxData, fmt.Sprintf("Test case %d", i))
	}
}
