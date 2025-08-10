package tomtp

import (
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func setupTest(t *testing.T) (connA *Connection, listenerB *Listener, connPair *ConnPair) {
    // Setup code   
    connPair = NewConnPair("alice", "bob")
   	listenerA, err := Listen(nil, WithNetworkConn(connPair.Conn1), WithPrvKeyId(testPrvKey1))
    assert.Nil(t, err)
	listenerB, err = Listen(nil, WithNetworkConn(connPair.Conn2), WithPrvKeyId(testPrvKey2))
	assert.Nil(t, err)
	pubKeyIdRcv, err := decodeHexPubKey(hexPubKey2)
	assert.Nil(t, err)
	connA, err = listenerA.DialWithCrypto(netip.AddrPort{}, pubKeyIdRcv)
	assert.Nil(t, err)
	assert.NotEmpty(t, connA)
	    
    // Register cleanup to run after test
    t.Cleanup(func() {
    	connPair.Conn1.Close()
     	connPair.Conn2.Close()
    })
    specificNano = 0
    return connA, listenerB, connPair
}

func TestOneStream(t *testing.T) {
	connA, listenerB, connPair := setupTest(t)

	// Send data from A to B
	a := []byte("hallo")
	streamA := connA.Stream(0)
	_, err := streamA.Write(a)
	assert.Nil(t, err)
	_, err = connA.listener.Flush(specificNano)
	assert.Nil(t, err)

	// Process and forward the data
	_, err = connPair.senderToRecipient(1)
	assert.Nil(t, err)

	// Received data
	streamB, err := listenerB.Listen(0, specificNano)
	assert.Nil(t, err)
	assert.True(t, streamB.state == StreamStateOpen)
	b, err := streamB.Read()
	assert.Nil(t, err)

	//Verification
	assert.Equal(t, a, b)
}

func TestTwoStream(t *testing.T) {
	connA, listenerB, connPair := setupTest(t)

	// Send data from A to B
	a1 := []byte("hallo1")
	streamA1 := connA.Stream(0)
	_, err := streamA1.Write(a1)
	assert.Nil(t, err)
	_, err = connA.listener.Flush(specificNano)
	assert.Nil(t, err)

	a2 := []byte("hallo22")
	streamA2 := connA.Stream(1)
	_, err = streamA2.Write(a2)
	assert.Nil(t, err)
	//this should not work, as we can only send 1 packet at the start, that we did with "hallo1"
	_, err = connA.listener.Flush(specificNano)
	assert.Nil(t, err)

	// we send one packet
	_, err = connPair.senderToRecipient(1)
	assert.Nil(t, err)

	// Received data, verification
	streamB1, err := listenerB.Listen(0, specificNano)
	assert.Nil(t, err)
	assert.True(t, streamB1.state == StreamStateOpen)
	b1, err := streamB1.Read()
	assert.Nil(t, err)
	assert.Equal(t, a1, b1)
	_, err = streamB1.Write(nil)
	assert.Nil(t, err)
	_, err = listenerB.Flush(specificNano)
	assert.Nil(t, err)

	_, err = connPair.recipientToSender(1)
	assert.Nil(t, err)

	_, err = connA.listener.Listen(0, specificNano)
	assert.Nil(t, err)
	//streamA2 = connA.Stream(1)
	//a2Test, err = streamA2.Write(a2)
	//assert.Nil(t, err)
	//assert.Equal(t, 0, len(a2Test))
	_, err = connA.listener.Flush(specificNano)
	assert.Nil(t, err)
	_, err = connA.listener.Flush(specificNano)
	assert.Nil(t, err)

	_, err = connPair.senderToRecipient(1)
	assert.Nil(t, err)

	streamB2, err := listenerB.Listen(0, specificNano)
	assert.Nil(t, err)
	assert.True(t, streamB2.state == StreamStateOpen)
	b2, err := streamB2.Read()
	assert.Nil(t, err)
	assert.Equal(t, a2, b2)
}

func TestTwoStreamFirstMessageTimeout(t *testing.T) {
	connA, listenerB, connPair := setupTest(t)

	// Send data from A to B
	a1 := []byte("hallo1")
	streamA1 := connA.Stream(0)
	_, err := streamA1.Write(a1)
	assert.Nil(t, err)
	_, err = connA.listener.Flush(specificNano)
	assert.Nil(t, err)

	a2 := []byte("hallo22")
	streamA2 := connA.Stream(1)
	_, err = streamA2.Write(a2)
	assert.Nil(t, err)
	setTime(201 * msNano)
	//this should not work, as we can only send 1 packet at the start, that we did with "hallo1"
	_, err = connA.listener.Flush(specificNano)
	assert.Nil(t, err)

	// we send one packet
	_, err = connPair.senderToRecipient(1)
	assert.Nil(t, err)

	// Received data, verification
	streamB1, err := listenerB.Listen(0, specificNano)
	assert.Nil(t, err)
	assert.True(t, streamB1.state == StreamStateOpen)
	b1, err := streamB1.Read()
	assert.Nil(t, err)
	assert.Equal(t, a1, b1)
	_, err = streamB1.Write(nil)
	assert.Nil(t, err)
	_, err = listenerB.Flush(specificNano)
	assert.Nil(t, err)

	_, err = connPair.recipientToSender(1)
	assert.Nil(t, err)
	_, err = connA.listener.Listen(0, specificNano)
	assert.Nil(t, err)
	//streamA2 = connA.Stream(1)
	//a2Test, err = streamA2.Write(a2)
	//assert.Nil(t, err)
	//assert.Equal(t, 0, len(a2Test))
	_, err = connA.listener.Flush(specificNano)
	assert.Nil(t, err)
	_, err = connA.listener.Flush(specificNano)
	assert.Nil(t, err)
	_, err = connPair.senderToRecipient(2)
	assert.Nil(t, err)

	//twice, as we receive a duplicate packet
	streamB2, err := listenerB.Listen(0, specificNano)
	streamB2, err = listenerB.Listen(0, specificNano)
	assert.Nil(t, err)
	assert.True(t, streamB2.state == StreamStateOpen)
	b2, err := streamB2.Read()
	assert.Nil(t, err)
	assert.Equal(t, a2, b2)
}

func TestRTO(t *testing.T) {
	connA, listenerB, connPair := setupTest(t)

	a1 := []byte("hallo1")
	streamA1 := connA.Stream(0)
	_, err := streamA1.Write(a1)
	assert.Nil(t, err)
	_, err = connA.listener.Flush(0)
	assert.Nil(t, err)

	_, err = connPair.senderToRecipient(-1)

	_, err = connA.listener.Flush((250*msNano) + 1)
	assert.Nil(t, err)

	_, err = connPair.senderToRecipient(1)

	streamB, err := listenerB.Listen(0, specificNano)
	assert.Nil(t, err)
	assert.True(t, streamB.state == StreamStateOpen)
}

func TestRTOTimes4Success(t *testing.T) {
	connA, listenerB, connPair := setupTest(t)
	
	a1 := []byte("hallo1")
	streamA1 := connA.Stream(0)
	_, err := streamA1.Write(a1)
	assert.Nil(t, err)
	_, err = connA.listener.Flush(0)
	assert.Nil(t, err)
	_, err = connPair.senderToRecipient(-1)
	_, err = connA.listener.Flush((200 * msNano) + 1)
	assert.Nil(t, err)
	_, err = connPair.senderToRecipient(-1)
	_, err = connA.listener.Flush(((200 + 400) * msNano) + 2)
	assert.Nil(t, err)
	_, err = connPair.senderToRecipient(-1)
	_, err = connA.listener.Flush(((200 + 400 + 800)* msNano) + 3)
	assert.Nil(t, err)
	_, err = connPair.senderToRecipient(-1)
	_, err = connA.listener.Flush(((200 + 400 + 800 + 1600)* msNano) + 4)
	assert.Nil(t, err)
	_, err = connPair.senderToRecipient(1)
	streamB, err := listenerB.Listen(0, specificNano)
	assert.Nil(t, err)
	assert.True(t, streamB.state == StreamStateOpen)
}

func TestRTOTimes4Fail(t *testing.T) {
	connA, _, connPair := setupTest(t)

	a1 := []byte("hallo1")
	streamA1 := connA.Stream(0)
	_, err := streamA1.Write(a1)
	assert.Nil(t, err)
	_, err = connA.listener.Flush(specificNano)
	slog.Debug("WWWWWW1", slog.Uint64("aeuaoeu", specificNano))
	assert.Nil(t, err)
	_, err = connPair.senderToRecipient(-1)
	_, err = connA.listener.Flush((200 * msNano) + 1)
	slog.Debug("WWWWWW2", slog.Uint64("aeuaoeu", specificNano))
	assert.Nil(t, err)
	_, err = connPair.senderToRecipient(-1)
	_, err = connA.listener.Flush(((200 + 400)* msNano) + 2)
	assert.Nil(t, err)
	_, err = connPair.senderToRecipient(-1)
	_, err = connA.listener.Flush(((200 + 400 + 800)* msNano) + 3)
	assert.Nil(t, err)
	_, err = connPair.senderToRecipient(-1)
	_, err = connA.listener.Flush(((200 + 400 + 800 + 1600)* msNano) + 4)
	assert.Nil(t, err)
	_, err = connPair.senderToRecipient(-1)
	_, err = connA.listener.Flush(((200 + 400 + 800 + 1600 + 3200)* msNano) + 5)
	assert.Nil(t, err)

	_, err = connA.listener.Flush((6210* msNano) + 5)
	assert.NotNil(t, err)
}

func TestCloseAWithInit(t *testing.T) {
	connA, listenerB, connPair := setupTest(t)
	
	streamA := connA.Stream(0)
	a1 := []byte("hallo1")
	_, err := streamA.Write(a1)
	assert.Nil(t, err)
	connA.Close()
	assert.True(t, streamA.state == StreamStateCloseRequest)

	_, err = connA.listener.Flush(specificNano)
	assert.Nil(t, err)

	// Simulate packet transfer (data packet with FIN flag)
	_, err = connPair.senderToRecipient(1)
	assert.Nil(t, err)

	// Listener B receives data
	streamB, err := listenerB.Listen(0, specificNano)
	assert.Nil(t, err)

	// Verify data received correctly
	buffer, err := streamB.Read()
	assert.Nil(t, err)

	assert.True(t, streamB.state == StreamStateCloseReceived)

	assert.Equal(t, a1, buffer)

	_, err = streamB.conn.listener.Flush(0)

	// B sends ACK back to A
	_, err = connPair.recipientToSender(1)
	assert.Nil(t, err)

	streamA, err = streamA.conn.listener.Listen(0, specificNano)
	assert.Nil(t, err)

	buffer, err = streamA.Read()

	assert.True(t, streamA.state == StreamStateClosed)

}

func TestCloseBWithInit(t *testing.T) {
	connA, listenerB, connPair := setupTest(t)
	
	streamA := connA.Stream(0)
	a1 := []byte("hallo1")
	_, err := streamA.Write(a1)
	assert.Nil(t, err)
	assert.True(t, streamA.state == StreamStateOpen)

	_, err = connA.listener.Flush(specificNano)
	assert.Nil(t, err)

	// Simulate packet transfer (data packet with FIN flag)
	_, err = connPair.senderToRecipient(1)
	assert.Nil(t, err)

	// Listener B receives data
	streamB, err := listenerB.Listen(0, specificNano)
	assert.Nil(t, err)
	streamB.conn.Close()
	assert.True(t, streamB.state == StreamStateCloseRequest)

	// Verify data received correctly
	buffer, err := streamB.Read()
	assert.Nil(t, err)

	assert.True(t, streamB.state == StreamStateCloseRequest)

	assert.Equal(t, a1, buffer)

	_, err = streamB.conn.listener.Flush(specificNano)

	// B sends ACK back to A
	_, err = connPair.recipientToSender(1)
	assert.Nil(t, err)

	streamA, err = streamA.conn.listener.Listen(0, specificNano)
	assert.Nil(t, err)

	buffer, err = streamA.Read()

	assert.True(t, streamA.state == StreamStateCloseReceived)
}

func TestGarbage1(t *testing.T) {
	connA, listenerB, connPair := setupTest(t)
	
	streamA := connA.Stream(0)
	a1 := []byte("hallo1")
	_, err := streamA.Write(a1)
	assert.Nil(t, err)
	assert.True(t, streamA.state == StreamStateOpen)
    
	_, err = connA.listener.Flush(0)
	assert.Nil(t, err)

	// Simulate packet transfer (data packet with FIN flag)
	data := make([]byte, 1400)
	err = connPair.senderRawToRecipient("tmp", data, 0)
	assert.Nil(t, err)

	// Listener B receives data
	_, err = listenerB.Listen(0, specificNano)
	assert.ErrorContains(t, err, "failed to decode InitHandshakeS0")
}

func TestGarbage2(t *testing.T) {
	connA, listenerB, connPair := setupTest(t)
	
	streamA := connA.Stream(0)
	a1 := []byte("hallo1")
	_, err := streamA.Write(a1)
	assert.Nil(t, err)
	assert.True(t, streamA.state == StreamStateOpen)

	_, err = connA.listener.Flush(0)
	assert.Nil(t, err)

	// Simulate packet transfer (data packet with FIN flag)
	_, err = connPair.senderToRecipient(1)
	assert.Nil(t, err)

	// Listener B receives data
	streamB, err := listenerB.Listen(0, specificNano)
	assert.Nil(t, err)

	_, err = streamB.Write([]byte("hallo"))
	assert.Nil(t, err)
	_, err = streamB.conn.listener.Flush(0)

	// Simulate packet transfer (data packet with FIN flag)
	data := make([]byte, 1400)
	err = connPair.recipientRawToSender("tmp", data, specificNano)
	assert.Nil(t, err)

	streamA, err = streamA.conn.listener.Listen(0, specificNano)
	assert.ErrorContains(t, err, "failed to decode InitHandshakeS0")
}

func TestBBR(t *testing.T) {
	connA, listenerB, connPair := setupTest(t)

	//write 64k
	streamA := connA.Stream(0)
	dataA := make([]byte, rcvBufferCapacity+1)
	dataARemaining, err := streamA.Write(dataA)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(dataARemaining))
	assert.Equal(t, 16777216, streamA.conn.sndBuf.size)
	streamA.conn.listener.Flush(specificNano)

	//send data
	assert.Equal(t, 1, connPair.nrOutgoingPacketsSender())
	_, err = connPair.senderToRecipientAll()
	assert.Nil(t, err)
	assert.Equal(t, 1, connPair.nrIncomingPacketsRecipient())

	//send 64 back
	streamB, err := listenerB.Listen(0, specificNano)
	assert.Nil(t, err)
	assert.Equal(t, uint64(0x1800000), streamB.conn.rcvWndSize)
	dataB1 := make([]byte, rcvBufferCapacity+1)
	dataB1Remaining, err := streamB.Write(dataB1)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(dataB1Remaining))
	streamB.conn.listener.Flush(specificNano)

	//send data
	assert.Equal(t, 1, connPair.nrOutgoingPacketsReceiver())
	_, err = connPair.recipientToSenderAll()
	assert.Nil(t, err)
	assert.Equal(t, 1, connPair.nrIncomingPacketsSender())
	streamA, err = connA.listener.Listen(0, specificNano)
	assert.Nil(t, err)
	assert.Equal(t, uint64(0xc00000), streamA.conn.rcvWndSize)

	for range 10 {
		_, err = streamA.conn.listener.Flush(specificNano)
		assert.Nil(t, err)
	}
	//respect pacing
	assert.Equal(t, 1, connPair.nrOutgoingPacketsSender())
}

func TestBBR2(t *testing.T) {
	t.SkipNow()
	connA, listenerB, connPair := setupTest(t)

	var totalBytesReceived uint64
	var mu sync.Mutex

	cancelA := connA.listener.Loop(func(s *Stream) {
		for {
			data, err := s.Read()
			if err != nil || len(data) == 0 {
				break
			}
			mu.Lock()
			totalBytesReceived += uint64(len(data))
			mu.Unlock()
		}
	})
	cancelB := listenerB.Loop(func(s *Stream) {
		for {
			data, err := s.Read()
			if err != nil || len(data) == 0 {
				break
			}
			mu.Lock()
			totalBytesReceived += uint64(len(data))
			mu.Unlock()
		}
	})

	streamA := connA.Stream(0)

	dataA := make([]byte, rcvBufferCapacity)
	_, err := streamA.Write(dataA)
	assert.Nil(t, err)

	start := time.Now()
	for {
		mu.Lock()
		received := totalBytesReceived
		mu.Unlock()

		if received >= rcvBufferCapacity {
			cancelA()
			cancelB()
			break
		}

		_, err = connPair.recipientToSenderAll()
		assert.Nil(t, err)

		_, err = connPair.senderToRecipientAll()
		assert.Nil(t, err)

		//time.Sleep(time.Duration(d1+d2) * time.Nanoecond)
		time.Sleep(100 * time.Millisecond)

		if time.Since(start) > 5*time.Second {
			cancelA()
			cancelB()
			break
		}
	}
}
