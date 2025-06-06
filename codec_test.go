package tomtp

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

func TestStreamEncode_StreamClosed(t *testing.T) {
	// Setup
	conn := &Connection{
		rbRcv:               NewReceiveBuffer(1000),
		pubKeyEpRcv:         prvEpBob.PublicKey(),
		prvKeyEpSnd:         prvEpAlice,
		pubKeyIdRcv:         prvIdAlice.PublicKey(),
		prvKeyEpSndRollover: prvEpAliceRoll,
		listener:            &Listener{prvKeyId: prvIdAlice},
		streams:             newStreamHashMap()}
	stream := conn.Stream(1)
	stream.Close()

	// Test
	output, _, err := stream.encode([]byte("test data"), 0, nil, stream.msgType())

	// Verify
	assert.NotNil(t, output)
	assert.Nil(t, err)
}

func TestStreamEncode_ConnectionClosed(t *testing.T) {
	// Setup
	conn := &Connection{
		rbRcv:               NewReceiveBuffer(1000),
		pubKeyEpRcv:         prvEpBob.PublicKey(),
		prvKeyEpSnd:         prvEpAlice,
		pubKeyIdRcv:         prvIdAlice.PublicKey(),
		prvKeyEpSndRollover: prvEpAliceRoll,
		sharedSecret:        bytes.Repeat([]byte{1}, 32),
		listener:            &Listener{prvKeyId: prvIdAlice},
		streams:             newStreamHashMap()}
	stream := conn.Stream(1)
	stream.conn.Close()

	// Test
	output, _, err := stream.encode([]byte("test data"), 0, nil, stream.msgType())

	// Verify
	assert.NotNil(t, output)
	assert.Nil(t, err)
}

func TestStreamEncode_InitialSenderPacket(t *testing.T) {
	// Setup
	conn := &Connection{
		isSender:            true,
		snCrypto:            0,
		mtu:                 1400,
		pubKeyIdRcv:         prvIdBob.PublicKey(),
		prvKeyEpSnd:         prvEpAlice,
		prvKeyEpSndRollover: prvEpAliceRoll,
		listener: &Listener{
			prvKeyId: prvIdAlice,
		},
		rbRcv: NewReceiveBuffer(1000),
	}
	stream := &Stream{conn: conn}
	input := []byte("test data")

	// Test
	output, _, err := stream.encode(input, 0, nil, stream.msgType())

	// Verify
	assert.NoError(t, err)
	assert.NotNil(t, output)
}

func TestStreamEncode_InitialHandshakeS0(t *testing.T) {
	// Setup
	conn := &Connection{
		isSender:            true,
		snCrypto:            0,
		mtu:                 1400,
		prvKeyEpSnd:         prvEpAlice,
		prvKeyEpSndRollover: prvEpAliceRoll,
		listener: &Listener{
			prvKeyId: prvIdAlice,
		},
		rbRcv: NewReceiveBuffer(1000),
	}
	stream := &Stream{conn: conn}

	// Test
	output, _, err := stream.encode(nil, 0, nil, stream.msgType())

	// Verify
	assert.NoError(t, err)
	assert.NotNil(t, output)

	// Verify it's an InitHandshakeS0 message
	_, msgType, err := decodeHeader(output)
	assert.NoError(t, err)
	assert.Equal(t, InitHandshakeS0MsgType, msgType)
}

func TestStreamEncode_InitialHandshakeR0(t *testing.T) {
	// Setup
	conn := &Connection{
		isSender:            false,
		snCrypto:            0,
		mtu:                 1400,
		pubKeyIdRcv:         prvIdAlice.PublicKey(),
		prvKeyEpSnd:         prvEpBob,
		prvKeyEpSndRollover: prvEpBobRoll,
		pubKeyEpRcv:         prvEpAlice.PublicKey(),
		listener: &Listener{
			prvKeyId: prvIdBob,
		},
		rbRcv: NewReceiveBuffer(1000),
	}
	stream := &Stream{conn: conn}
	input := []byte("handshake response")

	// Test
	output, _, err := stream.encode(input, 0, nil, stream.msgType())

	// Verify
	assert.NoError(t, err)
	assert.NotNil(t, output)

	// Verify it's an InitHandshakeR0 message
	_, msgType, err := decodeHeader(output)
	assert.NoError(t, err)
	assert.Equal(t, InitHandshakeR0MsgType, msgType)
}

func TestEndToEndCodec(t *testing.T) {
	// Setup listener
	lAlice := &Listener{
		connMap:  newConnHashMap(),
		prvKeyId: prvIdAlice,
	}

	// Create a test stream
	connAlice := &Connection{
		isSender:            true,
		withCrypto:          true,
		snCrypto:            0,
		mtu:                 1400,
		pubKeyIdRcv:         prvIdBob.PublicKey(),
		prvKeyEpSnd:         prvEpAlice,
		prvKeyEpSndRollover: prvEpAliceRoll,
		listener:            lAlice,
		rbRcv:               NewReceiveBuffer(1000),
	}

	streamAlice := &Stream{
		conn: connAlice,
	}

	lBob := &Listener{
		connMap:  newConnHashMap(),
		prvKeyId: prvIdBob,
	}

	// Test encoding and decoding
	testData := []byte("test message")
	encoded, _, err := streamAlice.encode(testData, 0, nil, streamAlice.msgType())
	require.NoError(t, err)
	require.NotNil(t, encoded)

	a, _ := netip.ParseAddr("127.0.0.1")
	remoteAddr := netip.AddrPortFrom(a, uint16(8080))

	c, m, err := lBob.decode(encoded, remoteAddr)
	require.NoError(t, err)
	s, err := c.decode(m.PayloadRaw, 0, 0)
	require.NoError(t, err)

	_, rb := s.conn.rbRcv.RemoveOldestInOrder(s.streamId)
	assert.Equal(t, testData, rb.data)
}

func TestEndToEndCodecLargeData(t *testing.T) {
	// Test with various dataToSend sizes
	dataSizes := []int{100, 1000, 2000, 10000}
	for _, size := range dataSizes {
		// Create Alice's connection and stream

		// Setup listeners
		lAlice := &Listener{
			connMap:  newConnHashMap(),
			prvKeyId: prvIdAlice,
		}
		lBob := &Listener{
			connMap:  newConnHashMap(),
			prvKeyId: prvIdBob,
		}

		connAlice := &Connection{
			isSender:            true,
			withCrypto:          true,
			snCrypto:            0,
			mtu:                 1400,
			pubKeyIdRcv:         prvIdBob.PublicKey(),
			prvKeyEpSnd:         prvEpAlice,
			prvKeyEpSndRollover: prvEpAliceRoll,
			listener:            lAlice,
			rbSnd:               NewSendBuffer(initBufferCapacity),
			rbRcv:               NewReceiveBuffer(12000),
			streams:             newStreamHashMap(),
		}
		connId := binary.LittleEndian.Uint64(prvEpAlice.PublicKey().Bytes())
		lAlice.connMap.Put(connId, connAlice)
		connAlice.connId = connId

		streamAlice := &Stream{
			conn: connAlice,
		}

		a, _ := netip.ParseAddr("127.0.0.1")
		remoteAddr := netip.AddrPortFrom(a, uint16(8080))

		t.Run(fmt.Sprintf("Size_%d", size), func(t *testing.T) {
			testData := make([]byte, size)
			for i := 0; i < len(testData); i++ {
				testData[i] = byte(i % 256)
			}

			remainingData := testData
			var decodedData []byte

			encoded, _, err := streamAlice.encode(remainingData, 0, nil, streamAlice.msgType())
			require.NoError(t, err)
			require.NotNil(t, encoded)

			connBob, m, err := lBob.decode(encoded, remoteAddr)
			require.NoError(t, err)
			s, err := connBob.decode(m.PayloadRaw, 0, 0)
			require.NoError(t, err)
			_, rb := s.conn.rbRcv.RemoveOldestInOrder(s.streamId)
			decodedData = append(decodedData, rb.data...)

			streamBob := connBob.Stream(s.streamId)
			encoded, _, err = streamBob.encode([]byte{}, 0, nil, streamBob.msgType())
			require.NoError(t, err)
			require.NotNil(t, encoded)

			connAlice, m, err = lAlice.decode(encoded, remoteAddr)
			require.NoError(t, err)
			s, err = connAlice.decode(m.PayloadRaw, 0, 0)
			require.NoError(t, err)
			//rb, err = s.ReadBytes()
			//require.NoError(t, err)

			assert.Equal(t, testData, decodedData, "Data mismatch for Size %d", size)
		})
	}
}

func TestFullHandshakeFlow(t *testing.T) {
	// Setup listeners
	lAlice := &Listener{
		connMap:  newConnHashMap(),
		prvKeyId: prvIdAlice,
	}
	lBob := &Listener{
		connMap:  newConnHashMap(),
		prvKeyId: prvIdBob,
	}

	// Test InitHandshakeS0 -> InitHandshakeR0 flow
	t.Run("Initial Handshake Flow", func(t *testing.T) {
		// Alice creates initial handshake

		connAlice := &Connection{
			connId:              Uint64(prvEpAlice.PublicKey().Bytes()),
			isSender:            true,
			snCrypto:            0,
			mtu:                 1400,
			prvKeyEpSnd:         prvEpAlice,
			prvKeyEpSndRollover: prvEpAliceRoll,
			listener:            lAlice,
			rbRcv:               NewReceiveBuffer(1000),
			streams:             newStreamHashMap(),
		}
		lAlice.connMap.Put(connAlice.connId, connAlice)

		streamAlice := &Stream{
			conn: connAlice,
		}

		// Alice encodes InitHandshakeS0
		encoded, _, err := streamAlice.encode(nil, 0, nil, streamAlice.msgType())
		require.NoError(t, err)
		require.NotNil(t, encoded)

		// Bob receives and decodes InitHandshakeS0
		a, _ := netip.ParseAddr("127.0.0.1")
		remoteAddr := netip.AddrPortFrom(a, uint16(8080))

		connBob, msgS0, err := lBob.decode(encoded, remoteAddr)
		require.NoError(t, err)
		require.NotNil(t, connBob)
		require.Equal(t, InitHandshakeS0MsgType, msgS0.MsgType)

		// Bob responds with InitHandshakeR0
		streamBob := &Stream{
			conn: connBob,
		}

		// Bob encodes InitHandshakeR0
		testData := []byte("handshake response")
		encodedR0, _, err := streamBob.encode(testData, 0, nil, streamBob.msgType())
		require.NoError(t, err)
		require.NotNil(t, encodedR0)

		// Alice receives and decodes InitHandshakeR0
		c, m, err := lAlice.decode(encodedR0, remoteAddr)
		require.NoError(t, err)
		s, err := c.decode(m.PayloadRaw, 0, 0)
		require.NoError(t, err)
		_, rb := s.conn.rbRcv.RemoveOldestInOrder(s.streamId)
		require.Equal(t, InitHandshakeR0MsgType, m.MsgType)
		require.Equal(t, testData, rb.data)
	})

	// Test Data0 message flow
	t.Run("Data0 Message Flow", func(t *testing.T) {
		connId := binary.LittleEndian.Uint64(prvIdAlice.PublicKey().Bytes()) ^ binary.LittleEndian.Uint64(prvIdBob.PublicKey().Bytes())

		// Setup established connection
		connAlice := &Connection{
			isHandshakeComplete: true,
			isSender:            true,
			snCrypto:            1,
			mtu:                 1400,
			pubKeyIdRcv:         prvIdBob.PublicKey(),
			prvKeyEpSnd:         prvEpAlice,
			prvKeyEpSndRollover: prvEpAliceRoll,
			pubKeyEpRcv:         prvEpBob.PublicKey(),
			listener:            lAlice,
			rbRcv:               NewReceiveBuffer(1000),
			isRollover:          false,
			sharedSecret:        seed1[:],
			streams:             newStreamHashMap(),
		}
		lAlice.connMap.Put(connId, connAlice)

		connBob := &Connection{
			isHandshakeComplete: true,
			isSender:            false,
			snCrypto:            1,
			mtu:                 1400,
			pubKeyIdRcv:         prvIdAlice.PublicKey(),
			prvKeyEpSnd:         prvEpBob,
			prvKeyEpSndRollover: prvEpBobRoll,
			pubKeyEpRcv:         prvEpAlice.PublicKey(),
			listener:            lBob,
			rbRcv:               NewReceiveBuffer(1000),
			isRollover:          false,
			sharedSecret:        seed1[:],
			streams:             newStreamHashMap(),
		}
		lBob.connMap.Put(connId, connBob)

		streamAlice := &Stream{
			conn: connAlice,
		}

		// Alice sends Data0
		testData := []byte("data0 message")
		encoded, _, err := streamAlice.encode(testData, 0, nil, streamAlice.msgType())
		require.NoError(t, err)
		require.NotNil(t, encoded)

		// Bob receives and decodes Data0
		a, _ := netip.ParseAddr("127.0.0.1")
		remoteAddr := netip.AddrPortFrom(a, uint16(8080))

		c, msg, err := lBob.decode(encoded, remoteAddr)
		require.NoError(t, err)
		require.NotNil(t, c)
		require.Equal(t, DataMsgType, msg.MsgType)

		s, err := c.decode(msg.PayloadRaw, 0, 0)
		require.NoError(t, err)
		_, rb := s.conn.rbRcv.RemoveOldestInOrder(s.streamId)
		require.Equal(t, testData, rb.data)
	})
}
