package qotp

import (
	"bytes"
	"crypto/ecdh"
	"encoding/binary"
	"github.com/stretchr/testify/assert"
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

// Helper functions
func createTestConnection(isSender, withCrypto, handshakeDone bool) *Connection {
	conn := &Connection{
		state: ConnectionState{
			isSenderOnInit:         isSender,
			isWithCryptoOnInit:     withCrypto,
			isHandshakeDoneOnRcv:   handshakeDone,
		},
		snCrypto: 0,
		mtu:      1400,
		keys: ConnectionKeys{
			pubKeyIdRcv: prvIdBob.PublicKey(),
			prvKeyEpSnd: prvEpAlice,
		},
		listener:     &Listener{prvKeyId: prvIdAlice},
		rcv:          NewReceiveBuffer(1000),
		streams:      NewLinkedMap[uint32, *Stream](),
		sharedSecret: bytes.Repeat([]byte{1}, 32),
	}

	if !isSender {
		conn.keys.pubKeyIdRcv = prvIdAlice.PublicKey()
		conn.keys.pubKeyEpRcv = prvEpAlice.PublicKey()
	}

	if handshakeDone {
		conn.keys.pubKeyEpRcv = prvEpBob.PublicKey()
	}

	return conn
}

func createTestListeners() (*Listener, *Listener) {
	lAlice := &Listener{
		connMap:  NewLinkedMap[uint64, *Connection](),
		prvKeyId: prvIdAlice,
	}
	lBob := &Listener{
		connMap:  NewLinkedMap[uint64, *Connection](),
		prvKeyId: prvIdBob,
	}
	return lAlice, lBob
}

func createTestData(size int) []byte {
	testData := make([]byte, size)
	for i := 0; i < len(testData); i++ {
		testData[i] = byte(i % 256)
	}
	return testData
}

func getTestRemoteAddr() netip.AddrPort {
	a, _ := netip.ParseAddr("127.0.0.1")
	return netip.AddrPortFrom(a, uint16(8080))
}

// Closed States Tests
func TestCodecStreamClosed(t *testing.T) {
	conn := createTestConnection(true, false, true)
	stream := conn.Stream(1)
	stream.Close()
	
	output, err := stream.encode([]byte("test data"), 0, nil, stream.msgType())
	assert.NotNil(t, output)
	assert.NoError(t, err)
}

func TestCodecConnectionClosed(t *testing.T) {
	conn := createTestConnection(true, false, true)
	stream := conn.Stream(1)
	stream.conn.Close()
	
	output, err := stream.encode([]byte("test data"), 0, nil, stream.msgType())
	assert.NotNil(t, output)
	assert.NoError(t, err)
}

// Handshake Type Tests
func TestCodecInitSnd(t *testing.T) {
	conn := createTestConnection(true, false, false)
	stream := &Stream{conn: conn}

	output, err := stream.encode(nil, 0, nil, stream.msgType())
	assert.NoError(t, err)
	assert.NotNil(t, output)

	msgType, err := decodeHeader(output)
	assert.NoError(t, err)
	assert.Equal(t, InitSnd, msgType)
}

func TestCodecInitRcv(t *testing.T) {
	conn := createTestConnection(false, false, false)
	stream := &Stream{conn: conn}

	output, err := stream.encode([]byte("test data"), 0, nil, stream.msgType())
	assert.NoError(t, err)
	assert.NotNil(t, output)

	msgType, err := decodeHeader(output)
	assert.NoError(t, err)
	assert.Equal(t, InitRcv, msgType)
}

func TestCodecInitCryptoSnd(t *testing.T) {
	conn := createTestConnection(true, true, false)
	stream := &Stream{conn: conn}

	output, err := stream.encode([]byte("test data"), 0, nil, stream.msgType())
	assert.NoError(t, err)
	assert.NotNil(t, output)

	msgType, err := decodeHeader(output)
	assert.NoError(t, err)
	assert.Equal(t, InitCryptoSnd, msgType)
}

func TestCodecInitCryptoRcv(t *testing.T) {
	conn := createTestConnection(false, true, false)
	stream := &Stream{conn: conn}

	output, err := stream.encode([]byte("test data"), 0, nil, stream.msgType())
	assert.NoError(t, err)
	assert.NotNil(t, output)

	msgType, err := decodeHeader(output)
	assert.NoError(t, err)
	assert.Equal(t, InitCryptoRcv, msgType)
}

// Overhead Calculation Tests - Updated to use CalcMaxOverhead function
func TestCodecOverheadInitSndNoData(t *testing.T) {
	overhead := CalcMaxOverhead(InitSnd, nil, 100)
	assert.Equal(t, -1, overhead)
}

func TestCodecOverheadInitRcvNoAck(t *testing.T) {
	overhead := CalcMaxOverhead(InitRcv, nil, 100)
	expected := calcOverhead(false, false) + MinInitRcvSizeHdr + FooterDataSize
	assert.Equal(t, expected, overhead)
}

func TestCodecOverheadInitCryptoSnd(t *testing.T) {
	overhead := CalcMaxOverhead(InitCryptoSnd, nil, 100)
	expected := calcOverhead(false, false) + MinInitCryptoSndSizeHdr + FooterDataSize + MsgInitFillLenSize
	assert.Equal(t, expected, overhead)
}

func TestCodecOverheadInitCryptoRcv(t *testing.T) {
	overhead := CalcMaxOverhead(InitCryptoRcv, nil, 100)
	expected := calcOverhead(false, false) + MinInitCryptoRcvSizeHdr + FooterDataSize
	assert.Equal(t, expected, overhead)
}

func TestCodecOverheadDataLargeAckOffset(t *testing.T) {
	ack := &Ack{offset: 0xFFFFFF + 1}
	overhead := CalcMaxOverhead(Data, ack, 100)
	expected := calcOverhead(true, true) + MinDataSizeHdr + FooterDataSize
	assert.Equal(t, expected, overhead)
}

func TestCodecOverheadDataLargeDataOffset(t *testing.T) {
	overhead := CalcMaxOverhead(Data, nil, 0xFFFFFF+1)
	expected := calcOverhead(false, true) + MinDataSizeHdr + FooterDataSize
	assert.Equal(t, expected, overhead)
}

func TestCodecOverheadDataSmallOffsets(t *testing.T) {
	ack := &Ack{offset: 1000}
	overhead := CalcMaxOverhead(Data, ack, 2000)
	expected := calcOverhead(true, false) + MinDataSizeHdr + FooterDataSize
	assert.Equal(t, expected, overhead)
}

func TestCodecOverheadDataNoAck(t *testing.T) {
	overhead := CalcMaxOverhead(Data, nil, 2000)
	expected := calcOverhead(false, false) + MinDataSizeHdr + FooterDataSize
	assert.Equal(t, expected, overhead)
}

// Data Size Tests
func TestCodecDataSizeZero(t *testing.T) {
	lAlice, lBob := createTestListeners()
	
	connAlice := createTestConnection(true, true, false)
	connAlice.snd = NewSendBuffer(rcvBufferCapacity, nil)
	connAlice.rcv = NewReceiveBuffer(12000)
	
	connId := binary.LittleEndian.Uint64(prvEpAlice.PublicKey().Bytes())
	lAlice.connMap.Put(connId, connAlice)
	connAlice.connId = connId

	streamAlice := &Stream{conn: connAlice}
	testData := createTestData(0)

	encoded, err := streamAlice.encode(testData, 0, nil, streamAlice.msgType())
	assert.NoError(t, err)
	assert.NotNil(t, encoded)

	connBob, m, err := lBob.decode(encoded, getTestRemoteAddr())
	assert.NoError(t, err)

	if m.MsgType == InitCryptoRcv {
		s, err := connBob.decode(m.PayloadRaw, 0, 0)
		assert.NoError(t, err)
		assert.NotNil(t, s)
	}
}

func TestCodecDataSizeOne(t *testing.T) {
	lAlice, lBob := createTestListeners()
	
	connAlice := createTestConnection(true, true, false)
	connAlice.snd = NewSendBuffer(rcvBufferCapacity, nil)
	connAlice.rcv = NewReceiveBuffer(12000)
	
	connId := binary.LittleEndian.Uint64(prvEpAlice.PublicKey().Bytes())
	lAlice.connMap.Put(connId, connAlice)
	connAlice.connId = connId

	streamAlice := &Stream{conn: connAlice}
	testData := createTestData(1)

	encoded, err := streamAlice.encode(testData, 0, nil, streamAlice.msgType())
	assert.NoError(t, err)
	assert.NotNil(t, encoded)

	connBob, m, err := lBob.decode(encoded, getTestRemoteAddr())
	assert.NoError(t, err)

	s, err := connBob.decode(m.PayloadRaw, 0, 0)
	assert.NoError(t, err)
	_, rb := s.conn.rcv.RemoveOldestInOrder(s.streamID)
	assert.Equal(t, testData, rb)
}

func TestCodecDataSizeHundred(t *testing.T) {
	lAlice, lBob := createTestListeners()
	
	connAlice := createTestConnection(true, true, false)
	connAlice.snd = NewSendBuffer(rcvBufferCapacity, nil)
	connAlice.rcv = NewReceiveBuffer(12000)
	
	connId := binary.LittleEndian.Uint64(prvEpAlice.PublicKey().Bytes())
	lAlice.connMap.Put(connId, connAlice)
	connAlice.connId = connId

	streamAlice := &Stream{conn: connAlice}
	testData := createTestData(100)

	encoded, err := streamAlice.encode(testData, 0, nil, streamAlice.msgType())
	assert.NoError(t, err)
	assert.NotNil(t, encoded)

	connBob, m, err := lBob.decode(encoded, getTestRemoteAddr())
	assert.NoError(t, err)

	s, err := connBob.decode(m.PayloadRaw, 0, 0)
	assert.NoError(t, err)
	_, rb := s.conn.rcv.RemoveOldestInOrder(s.streamID)
	assert.Equal(t, testData, rb)
}

func TestCodecDataSizeThousand(t *testing.T) {
	lAlice, lBob := createTestListeners()
	
	connAlice := createTestConnection(true, true, false)
	connAlice.snd = NewSendBuffer(rcvBufferCapacity, nil)
	connAlice.rcv = NewReceiveBuffer(12000)
	
	connId := binary.LittleEndian.Uint64(prvEpAlice.PublicKey().Bytes())
	lAlice.connMap.Put(connId, connAlice)
	connAlice.connId = connId

	streamAlice := &Stream{conn: connAlice}
	testData := createTestData(1000)

	encoded, err := streamAlice.encode(testData, 0, nil, streamAlice.msgType())
	assert.NoError(t, err)
	assert.NotNil(t, encoded)

	connBob, m, err := lBob.decode(encoded, getTestRemoteAddr())
	assert.NoError(t, err)

	s, err := connBob.decode(m.PayloadRaw, 0, 0)
	assert.NoError(t, err)
	_, rb := s.conn.rcv.RemoveOldestInOrder(s.streamID)
	assert.Equal(t, testData, rb)
}

func TestCodecDataSizeLarge(t *testing.T) {
	lAlice, lBob := createTestListeners()
	
	connAlice := createTestConnection(true, true, false)
	connAlice.snd = NewSendBuffer(rcvBufferCapacity, nil)
	connAlice.rcv = NewReceiveBuffer(12000)
	
	connId := binary.LittleEndian.Uint64(prvEpAlice.PublicKey().Bytes())
	lAlice.connMap.Put(connId, connAlice)
	connAlice.connId = connId

	streamAlice := &Stream{conn: connAlice}
	testData := createTestData(1295)

	encoded, err := streamAlice.encode(testData, 0, nil, streamAlice.msgType())
	assert.NoError(t, err)
	assert.NotNil(t, encoded)

	connBob, m, err := lBob.decode(encoded, getTestRemoteAddr())
	assert.NoError(t, err)

	s, err := connBob.decode(m.PayloadRaw, 0, 0)
	assert.NoError(t, err)
	_, rb := s.conn.rcv.RemoveOldestInOrder(s.streamID)
	assert.Equal(t, testData, rb)
}

// Full Handshake Test
func TestCodecFullHandshake(t *testing.T) {
	lAlice, lBob := createTestListeners()
	remoteAddr := getTestRemoteAddr()

	// Alice's initial connection
	connAlice := &Connection{
		connId: Uint64(prvEpAlice.PublicKey().Bytes()),
		state: ConnectionState{
			isSenderOnInit: true,
		},
		snCrypto: 0,
		mtu:      1400,
		keys: ConnectionKeys{
			prvKeyEpSnd: prvEpAlice,
		},
		listener: lAlice,
		rcv:      NewReceiveBuffer(1000),
		streams:  NewLinkedMap[uint32, *Stream](),
	}
	lAlice.connMap.Put(connAlice.connId, connAlice)

	streamAlice := &Stream{conn: connAlice}

	// Step 1: Alice encodes InitSnd
	encoded, err := streamAlice.encode(nil, 0, nil, streamAlice.msgType())
	assert.NoError(t, err)
	assert.NotNil(t, encoded)

	// Step 2: Bob receives and decodes InitSnd
	connBob, msgS0, err := lBob.decode(encoded, remoteAddr)
	assert.NoError(t, err)
	assert.NotNil(t, connBob)
	assert.Equal(t, InitSnd, msgS0.MsgType)

	// Step 3: Bob responds with InitRcv
	streamBob := &Stream{conn: connBob}
	testData := []byte("handshake response")
	encodedR0, err := streamBob.encode(testData, 0, nil, streamBob.msgType())
	assert.NoError(t, err)
	assert.NotNil(t, encodedR0)

	// Step 4: Alice receives and decodes InitRcv
	c, m, err := lAlice.decode(encodedR0, remoteAddr)
	assert.NoError(t, err)
	assert.Equal(t, InitRcv, m.MsgType)
	
	s, err := c.decode(m.PayloadRaw, 0, 0)
	assert.NoError(t, err)
	_, rb := s.conn.rcv.RemoveOldestInOrder(s.streamID)
	assert.Equal(t, testData, rb)

	// Step 5: Setup for Data message flow after handshake
	connId := binary.LittleEndian.Uint64(prvIdAlice.PublicKey().Bytes()) ^ binary.LittleEndian.Uint64(prvIdBob.PublicKey().Bytes())

	connAlice.state.isHandshakeDoneOnRcv = true
	connAlice.keys.pubKeyIdRcv = prvIdBob.PublicKey()
	connAlice.keys.pubKeyEpRcv = prvEpBob.PublicKey()
	connAlice.sharedSecret = seed1[:]
	lAlice.connMap.Put(connId, connAlice)

	connBob.state.isHandshakeDoneOnRcv = true
	connBob.sharedSecret = seed1[:]
	lBob.connMap.Put(connId, connBob)

	// Step 6: Alice sends Data message
	dataMsg := []byte("data message")
	encoded, err = streamAlice.encode(dataMsg, 0, nil, streamAlice.msgType())
	assert.NoError(t, err)
	assert.NotNil(t, encoded)

	// Step 7: Bob receives and decodes Data message
	c, msg, err := lBob.decode(encoded, remoteAddr)
	assert.NoError(t, err)
	assert.NotNil(t, c)
	assert.Equal(t, Data, msg.MsgType)

	s, err = c.decode(msg.PayloadRaw, 0, 0)
	assert.NoError(t, err)
	_, rb = s.conn.rcv.RemoveOldestInOrder(s.streamID)
	assert.Equal(t, dataMsg, rb)
}

// Sequence Number Tests
func TestCodecSequenceNumberRollover(t *testing.T) {
	conn := createTestConnection(true, false, true)
	conn.snCrypto = (1 << 48) - 2 // Near rollover
	conn.epochCryptoSnd = 0

	stream := &Stream{conn: conn}

	// First encode should succeed and rollover snCrypto
	_, err := stream.encode([]byte("test"), 0, nil, Data)
	assert.NoError(t, err)
	assert.Equal(t, uint64((1<<48)-1), conn.snCrypto)

	// Second encode should trigger rollover
	_, err = stream.encode([]byte("test"), 0, nil, Data)
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), conn.snCrypto)
	assert.Equal(t, uint64(1), conn.epochCryptoSnd)
}

func TestCodecSequenceNumberExhaustion(t *testing.T) {
	conn := createTestConnection(true, false, true)
	conn.snCrypto = (1 << 48) - 1
	conn.epochCryptoSnd = (1 << 47) - 1 // Max epoch

	stream := &Stream{conn: conn}

	// Should fail with exhaustion error
	_, err := stream.encode([]byte("test"), 0, nil, Data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exhausted")
}

// Error Tests
func TestCodecInvalidMessageType(t *testing.T) {
	conn := createTestConnection(true, false, true)
	stream := &Stream{conn: conn}

	// Test with invalid message type
	_, err := stream.encode([]byte("test"), 0, nil, MsgType(99))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown message type")
}

func TestCodecDecodeEmptyBuffer(t *testing.T) {
	l := &Listener{
		connMap:  NewLinkedMap[uint64, *Connection](),
		prvKeyId: prvIdAlice,
	}
	
	_, _, err := l.decode([]byte{}, getTestRemoteAddr())
	assert.Error(t, err)
}

func TestCodecDecodeInvalidHeader(t *testing.T) {
	l := &Listener{
		connMap:  NewLinkedMap[uint64, *Connection](),
		prvKeyId: prvIdAlice,
	}
	
	_, _, err := l.decode([]byte{0xFF}, getTestRemoteAddr())
	assert.Error(t, err)
}

func TestCodecDecodeConnectionNotFoundInitRcv(t *testing.T) {
	l := &Listener{
		connMap:  NewLinkedMap[uint64, *Connection](),
		prvKeyId: prvIdAlice,
	}
	
	buffer := append([]byte{byte(InitRcv)}, make([]byte, 15)...)
	_, _, err := l.decode(buffer, getTestRemoteAddr())
	assert.Error(t, err)
}

func TestCodecDecodeConnectionNotFoundData(t *testing.T) {
	l := &Listener{
		connMap:  NewLinkedMap[uint64, *Connection](),
		prvKeyId: prvIdAlice,
	}
	
	buffer := append([]byte{byte(Data)}, make([]byte, 15)...)
	_, _, err := l.decode(buffer, getTestRemoteAddr())
	assert.Error(t, err)
}

// Message Type Logic Tests
func TestCodecMsgTypeInitCryptoSnd(t *testing.T) {
	conn := createTestConnection(true, true, false)
	stream := &Stream{conn: conn}
	
	msgType := stream.msgType()
	assert.Equal(t, InitCryptoSnd, msgType)
}

func TestCodecMsgTypeInitCryptoRcv(t *testing.T) {
	conn := createTestConnection(false, true, false)
	stream := &Stream{conn: conn}
	
	msgType := stream.msgType()
	assert.Equal(t, InitCryptoRcv, msgType)
}

func TestCodecMsgTypeInitSnd(t *testing.T) {
	conn := createTestConnection(true, false, false)
	stream := &Stream{conn: conn}
	
	msgType := stream.msgType()
	assert.Equal(t, InitSnd, msgType)
}

func TestCodecMsgTypeInitRcv(t *testing.T) {
	conn := createTestConnection(false, false, false)
	stream := &Stream{conn: conn}
	
	msgType := stream.msgType()
	assert.Equal(t, InitRcv, msgType)
}

func TestCodecMsgTypeData(t *testing.T) {
	conn := createTestConnection(true, false, true)
	stream := &Stream{conn: conn}
	
	msgType := stream.msgType()
	assert.Equal(t, Data, msgType)
}