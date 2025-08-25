package qotp

import (
	"github.com/stretchr/testify/suite"
	"math"
	"testing"
)

type SendBufferTestSuite struct {
	suite.Suite
	sb *SendBuffer
}

func (s *SendBufferTestSuite) SetupTest() {
	s.T().Logf("SetupTest called for: %s", s.T().Name())
	s.sb = NewSendBuffer(1000, nil)
}

func TestSendBufferSuite(t *testing.T) {
	suite.Run(t, new(SendBufferTestSuite))
}

func (s *SendBufferTestSuite) TestInsert() {
	// Basic insert
	_, status := s.sb.QueueData(1, []byte("test"))
	s.Equal(InsertStatusOk, status)

	// Verify stream created correctly
	stream := s.sb.streams[1]

	s.Equal([]byte("test"), stream.userData)
	s.Equal(uint64(4), stream.unsentOffset)
	s.Equal(uint64(0), stream.sentOffset)
	s.Equal(uint64(0), stream.bias)

	// Test capacity limit
	sb := NewSendBuffer(3, nil)
	nr, status := sb.QueueData(1, []byte("test"))
	s.Equal(InsertStatusSndFull, status)
	s.Equal(3, nr)

	// Test 48-bit wrapping (using MaxUint64 as uint48 in go doesn't exist)
	sb = NewSendBuffer(1000, nil)
	stream = NewStreamBuffer()
	stream.unsentOffset = math.MaxUint64 - 2
	sb.streams[1] = stream
	_, status = sb.QueueData(1, []byte("test"))
	s.Equal(InsertStatusOk, status) // Should succeed now

	stream = sb.streams[1]
	//s.Equal(uint64(math.MaxUint64 + 2), stream.unsentOffset) // Rollover will occur. Because we are using unit64
	s.Equal(uint64(1), stream.unsentOffset) // Rollover will occur. Because we are using unit64
	s.Equal(uint64(0), stream.sentOffset)
}

func (s *SendBufferTestSuite) TestReadyToSend() {
	nowMillis2 := uint64(100)

	// Insert data
	s.sb.QueueData(1, []byte("test1"))
	s.sb.QueueData(2, []byte("test2"))

	// Basic send
	data, _ := s.sb.ReadyToSend(1, &Overhead{debug: 10}, nowMillis2)
	s.Equal([]byte("test1"), data)

	// Verify range tracking
	stream := s.sb.streams[1]

	rangePair, v, _ := stream.dataInFlightMap.First()
	s.NotNil(rangePair)
	s.Equal(uint16(5), rangePair.length())
	s.Equal(nowMillis2, v.sentTimeNano)

	s.sb.ReadyToSend(1, &Overhead{debug: 10}, nowMillis2)

	// Test MTU limiting
	s.sb.QueueData(3, []byte("toolongdata"))
	data, _ = s.sb.ReadyToSend(3, &Overhead{debug: 4}, nowMillis2)
	s.Equal([]byte("tool"), data)

	// test no data available
	data, _ = s.sb.ReadyToSend(4, &Overhead{debug: 10}, nowMillis2)
	s.Nil(data)
}

func (s *SendBufferTestSuite) TestReadyToRetransmit() {
	// Setup test data
	s.sb.QueueData(1, []byte("test1"))
	s.sb.QueueData(2, []byte("test2"))

	s.sb.ReadyToSend(1, &Overhead{debug: 10}, 100) // Initial send at time 100
	s.sb.ReadyToSend(2, &Overhead{debug: 10}, 100) // Initial send at time 100

	// Test basic retransmit
	data, _, err := s.sb.ReadyToRetransmit(1, &Overhead{debug: 10}, 50, 200) // RTO = 50, now = 200.  200-100 > 50
	s.Nil(err)
	s.Equal([]byte("test1"), data)

	data, _, err = s.sb.ReadyToRetransmit(2, &Overhead{debug: 10}, 100, 200) //RTO = 100, now = 200. 200-100 = 100, thus ok
	s.Nil(err)
	s.Nil(data)

	data, _, err = s.sb.ReadyToRetransmit(1, &Overhead{debug: 10}, 99, 399) // RTO = 99, now = 200. 200-100 > 99
	s.Nil(err)
	s.Equal([]byte("test1"), data)

	// Test MTU split
	sb := NewSendBuffer(1000, nil)
	sb.QueueData(1, []byte("testdata"))
	sb.ReadyToSend(1, &Overhead{debug: 100}, 100) // Initial send

	data, _, err = sb.ReadyToRetransmit(1, &Overhead{debug: 4}, 99, 200)
	s.Nil(err)
	s.Equal([]byte("test"), data)

	// Verify range split
	stream := sb.streams[1]

	s.Equal(2, stream.dataInFlightMap.Size())
	node, _, _ := stream.dataInFlightMap.First()
	s.Equal(uint16(4), node.length())
	s.Equal(uint64(4), node.offset())
}

func (s *SendBufferTestSuite) TestAcknowledgeRangeBasic() {
	s.sb.QueueData(1, []byte("testdata"))
	s.sb.ReadyToSend(1, &Overhead{debug: 4}, 100)
	stream := s.sb.streams[1]

	_, time := s.sb.AcknowledgeRange(&Ack{
		streamID: 1,
		offset:   0,
		len:      4,
	})
	s.Equal(uint64(100), time)
	s.Equal(4, len(stream.userData))
	s.Equal(uint64(4), stream.bias)
}

func (s *SendBufferTestSuite) TestAcknowledgeRangeNonExistentStream() {
	_, time := s.sb.AcknowledgeRange(&Ack{
		streamID: 1,
		offset:   0,
		len:      4,
	})
	s.Equal(uint64(0), time)
}

func (s *SendBufferTestSuite) TestAcknowledgeRangeNonExistentRange() {
	stream := NewStreamBuffer()
	s.sb.streams[1] = stream
	_, time := s.sb.AcknowledgeRange(&Ack{
		streamID: 1,
		offset:   0,
		len:      4,
	})
	s.Equal(uint64(0), time)
}