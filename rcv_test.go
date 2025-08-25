package qotp

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestReceiveBuffer_SingleSegment(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	status := rb.Insert(1, 0, []byte("data"))
	assert.Equal(t, RcvInsertOk, status)

	offset, data := rb.RemoveOldestInOrder(1)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("data"), data)

	// Verify empty after reading
	_, data = rb.RemoveOldestInOrder(1)
	require.Empty(t, data)
}

func TestReceiveBuffer_DuplicateSegment(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	status := rb.Insert(1, 0, []byte("data"))
	assert.Equal(t, RcvInsertOk, status)

	status = rb.Insert(1, 0, []byte("data"))
	assert.Equal(t, RcvInsertDuplicate, status)

	offset, data := rb.RemoveOldestInOrder(1)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("data"), data)
}

func TestReceiveBuffer_GapBetweenSegments(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	status := rb.Insert(1, 10, []byte("later"))
	assert.Equal(t, RcvInsertOk, status)

	status = rb.Insert(1, 0, []byte("early"))
	assert.Equal(t, RcvInsertOk, status)

	// Should get early segment first
	offset, data := rb.RemoveOldestInOrder(1)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("early"), data)

	// Then later segment
	offset, data = rb.RemoveOldestInOrder(1)
	assert.Equal(t, uint64(0), offset)
	assert.Nil(t, data)
}

func TestReceiveBuffer_MultipleStreams(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	// Insert segments from different streams
	status := rb.Insert(1, 0, []byte("stream1-first"))
	assert.Equal(t, RcvInsertOk, status)

	status = rb.Insert(2, 0, []byte("stream2-first"))
	assert.Equal(t, RcvInsertOk, status)

	status = rb.Insert(1, 13, []byte("stream1-second"))
	assert.Equal(t, RcvInsertOk, status)

	// Read from stream 1
	offset, data := rb.RemoveOldestInOrder(1)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("stream1-first"), data)

	// Read from stream 2
	offset, data = rb.RemoveOldestInOrder(2)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("stream2-first"), data)

	// Read second segment from stream 1
	offset, data = rb.RemoveOldestInOrder(1)
	assert.Equal(t, uint64(13), offset)
	assert.Equal(t, []byte("stream1-second"), data)
}

func TestReceiveBuffer_BufferFullExact(t *testing.T) {
	rb := NewReceiveBuffer(4)

	status := rb.Insert(1, 0, []byte("data"))
	assert.Equal(t, RcvInsertOk, status)

	status = rb.Insert(1, 4, []byte("more"))
	assert.Equal(t, RcvInsertBufferFull, status)

	offset, data := rb.RemoveOldestInOrder(1)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("data"), data)
}

func TestReceiveBuffer_RemoveWithHigherOffset(t *testing.T) {
	rb := NewReceiveBuffer(4)

	status := rb.Insert(1, 0, []byte("12345"))
	assert.Equal(t, RcvInsertBufferFull, status)

	offset, data := rb.RemoveOldestInOrder(1)
	assert.Equal(t, uint64(0), offset)
	assert.Nil(t, data)
}

func TestReceiveBuffer_RemoveWithHigherOffset_EmptyAfterLast(t *testing.T) {
	rb := NewReceiveBuffer(4)

	status := rb.Insert(1, 0, []byte("1"))
	assert.Equal(t, RcvInsertOk, status)

	offset, data := rb.RemoveOldestInOrder(1)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("1"), data)

	// Should be empty after reading
	_, data = rb.RemoveOldestInOrder(1)
	require.Empty(t, data)
}

func TestReceiveBuffer_PreviousOverlapPartialIntegrityViolation(t *testing.T) {
	rb := NewReceiveBuffer(1000)
	
	// Insert previous segment: offset=100, data="ABCDE"
	status := rb.Insert(1, 100, []byte("ABCDE"))
	assert.Equal(t, RcvInsertOk, status)
	
	// Insert overlapping segment with mismatched data - should panic
	assert.PanicsWithValue(t, "Previous segment overlap mismatch - data integrity violation", func() {
		rb.Insert(1, 102, []byte("CDFG")) // "CD" doesn't match "CD" from previous
	})
}

// Test cases for overlap edge cases


func TestReceiveBuffer_PreviousOverlapComplete(t *testing.T) {
	rb := NewReceiveBuffer(1000)
	
	// Insert previous segment: offset=100, data="ABCDEFGH"
	status := rb.Insert(1, 100, []byte("ABCDEFGH"))
	assert.Equal(t, RcvInsertOk, status)
	
	// Insert completely overlapped segment: offset=102, data="CD"
	status = rb.Insert(1, 102, []byte("CD"))
	assert.Equal(t, RcvInsertDuplicate, status)
	
	// Should still only have the original segment
	stream := rb.streams[1]
	data, exists := stream.segments.Get(100)
	assert.True(t, exists)
	assert.Equal(t, []byte("ABCDEFGH"), data)
	
	// Should not have created new segment
	_, exists = stream.segments.Get(102)
	assert.False(t, exists)
}

func TestReceiveBuffer_NextOverlapMismatchPanic(t *testing.T) {
	rb := NewReceiveBuffer(1000)
	
	// Insert next segment first: offset=105, data="EFGH"
	status := rb.Insert(1, 105, []byte("EFGH"))
	assert.Equal(t, RcvInsertOk, status)
	
	// Insert overlapping segment with mismatched overlap data - should panic
	// Next segment has "E" at position 105, but incoming has "F" at position 105
	assert.PanicsWithValue(t, "Next segment partial overlap mismatch - data integrity violation", func() {
		rb.Insert(1, 100, []byte("ABCDEF")) // "F" at position 105 doesn't match "E"
	})
}

func TestReceiveBuffer_NextOverlapPartial(t *testing.T) {
	rb := NewReceiveBuffer(1000)
	
	// Insert next segment first: offset=105, data="EFGH"
	status := rb.Insert(1, 105, []byte("EFGH"))
	assert.Equal(t, RcvInsertOk, status)
	
	// Insert overlapping segment: offset=100, data="ABCDEE"
	status = rb.Insert(1, 100, []byte("ABCDEE"))
	assert.Equal(t, RcvInsertOk, status)
	
	stream := rb.streams[1]
	
	// Should have shortened incoming segment to remove only the overlapping "E"
	// Keeps "ABCDE" (the non-overlapping portion)
	data, exists := stream.segments.Get(100)
	assert.True(t, exists)
	assert.Equal(t, []byte("ABCDE"), data)  // ← Fix: expect 5 bytes, not 4
	
	// Should still have next segment: offset=105, data="EFGH"
	data, exists = stream.segments.Get(105)
	assert.True(t, exists)
	assert.Equal(t, []byte("EFGH"), data)
}

func TestReceiveBuffer_NextOverlapCompleteMismatchPanic(t *testing.T) {
	rb := NewReceiveBuffer(1000)
	
	// Insert next segment first: offset=105, data="EF"
	status := rb.Insert(1, 105, []byte("EF"))
	assert.Equal(t, RcvInsertOk, status)
	
	// Insert segment with mismatched complete overlap data - should panic
	// Next segment has "EF" at positions 105-106, but incoming has "FG" at same positions
	assert.PanicsWithValue(t, "Next segment complete overlap mismatch - data integrity violation", func() {
		rb.Insert(1, 100, []byte("ABCDEFGH")) // "FG" at positions 105-106 doesn't match "EF"
	})
}

func TestReceiveBuffer_NextOverlapComplete(t *testing.T) {
	rb := NewReceiveBuffer(1000)
	
	// Insert next segment first: offset=105, data="EF"
	status := rb.Insert(1, 105, []byte("EF"))
	assert.Equal(t, RcvInsertOk, status)
	
	// Insert segment that completely covers the next with matching overlap data
	// Positions 105-106 should contain "EF" in both segments
	status = rb.Insert(1, 100, []byte("ABCDEEFGH"))
	assert.Equal(t, RcvInsertOk, status)
	
	stream := rb.streams[1]
	
	// Should have our full segment: offset=100, data="ABCDEEFGH"
	data, exists := stream.segments.Get(100)
	assert.True(t, exists)
	assert.Equal(t, []byte("ABCDEEFGH"), data)
	
	// Next segment should be removed (completely overlapped)
	_, exists = stream.segments.Get(105)
	assert.False(t, exists)
}

func TestReceiveBuffer_BothOverlaps(t *testing.T) {
	rb := NewReceiveBuffer(1000)
	
	// Insert previous segment: offset=90, data="12345"
	status := rb.Insert(1, 90, []byte("12345"))
	assert.Equal(t, RcvInsertOk, status)
	
	// Insert next segment: offset=105, data="WXYZ"
	status = rb.Insert(1, 105, []byte("WXYZ"))
	assert.Equal(t, RcvInsertOk, status)
	
	// Insert segment that overlaps both with matching data:
	// Previous overlap: "345" at positions 92-94
	// After adjustment, will be at offset 95 with remaining data
	// Must ensure positions 105-108 contain "WXYZ" to match next segment
	status = rb.Insert(1, 92, []byte("345ABCDEFGHIJWXYZUV"))
	assert.Equal(t, RcvInsertOk, status)
	
	stream := rb.streams[1]
	
	// Previous segment should stay unchanged (we don't shorten it)
	data, exists := stream.segments.Get(90)
	assert.True(t, exists)
	assert.Equal(t, []byte("12345"), data)
	
	// Adjusted incoming segment: offset=95, data="ABCDEFGHIJWXYZUV" 
	data, exists = stream.segments.Get(95)
	assert.True(t, exists)
	assert.Equal(t, []byte("ABCDEFGHIJWXYZUV"), data)
	
	// Next segment should be removed (completely overlapped)
	_, exists = stream.segments.Get(105)
	assert.False(t, exists)
}

func TestReceiveBuffer_ExactSameOffset_SmallerData(t *testing.T) {
	rb := NewReceiveBuffer(1000)
	
	// Insert larger segment first
	status := rb.Insert(1, 100, []byte("ABCDEFGH"))
	assert.Equal(t, RcvInsertOk, status)
	
	// Insert smaller segment at same offset - should be duplicate
	status = rb.Insert(1, 100, []byte("ABCD"))
	assert.Equal(t, RcvInsertDuplicate, status)
	
	stream := rb.streams[1]
	
	// Should keep the larger segment
	data, exists := stream.segments.Get(100)
	assert.True(t, exists)
	assert.Equal(t, []byte("ABCDEFGH"), data)
}

func TestReceiveBuffer_ExactSameOffset_LargerData(t *testing.T) {
	rb := NewReceiveBuffer(1000)
	
	// Insert smaller segment first
	status := rb.Insert(1, 100, []byte("ABCD"))
	assert.Equal(t, RcvInsertOk, status)
	
	// Insert larger segment at same offset - should replace
	status = rb.Insert(1, 100, []byte("ABCDEFGH"))
	assert.Equal(t, RcvInsertOk, status)
	
	stream := rb.streams[1]
	
	// Should have the larger segment
	data, exists := stream.segments.Get(100)
	assert.True(t, exists)
	assert.Equal(t, []byte("ABCDEFGH"), data)
}

func TestReceiveBuffer_AlreadyDeliveredSegment(t *testing.T) {
	rb := NewReceiveBuffer(1000)
	
	// Insert and read a segment to advance nextInOrderOffsetToWaitFor
	status := rb.Insert(1, 0, []byte("ABCD"))
	assert.Equal(t, RcvInsertOk, status)
	
	offset, data := rb.RemoveOldestInOrder(1)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("ABCD"), data)
	
	// Now nextInOrderOffsetToWaitFor should be 4
	stream := rb.streams[1]
	assert.Equal(t, uint64(4), stream.nextInOrderOffsetToWaitFor)
	
	// Try to insert segment that's completely before delivered data
	status = rb.Insert(1, 0, []byte("AB"))
	assert.Equal(t, RcvInsertDuplicate, status)
	
	// Try to insert segment that partially overlaps delivered data
	status = rb.Insert(1, 2, []byte("CD"))
	assert.Equal(t, RcvInsertDuplicate, status)
	
	// Insert segment that starts exactly at next expected offset
	status = rb.Insert(1, 4, []byte("EFGH"))
	assert.Equal(t, RcvInsertOk, status)
}

func TestReceiveBuffer_SizeAccountingCorrect(t *testing.T) {
	rb := NewReceiveBuffer(1000)
	
	// Insert first segment
	status := rb.Insert(1, 100, []byte("ABCDE")) // 5 bytes
	assert.Equal(t, RcvInsertOk, status)
	assert.Equal(t, 5, rb.Size())
	
	// Insert overlapping segment with matching overlap data
	status = rb.Insert(1, 102, []byte("CDEFG")) // overlaps with "CDE", matches exactly
	assert.Equal(t, RcvInsertOk, status)
	
	// Previous segment stays: "ABCDE" (5 bytes)
	// New segment adjusted: "FG" at offset 105 (2 bytes) 
	// Total: 5 + 2 = 7 bytes
	assert.Equal(t, 7, rb.Size())
	
	// Insert segment that completely covers the first segment but not the second
	status = rb.Insert(1, 90, []byte("1234567890ABCDEFGHIJK")) // 21 bytes
	assert.Equal(t, RcvInsertOk, status)
	
	// Final size: 21 bytes (new segment) + 2 bytes (remaining "FG" segment) = 23 bytes
	assert.Equal(t, 23, rb.Size())
}

func TestReceiveBuffer_OverlapDataMismatchPanic(t *testing.T) {
	rb := NewReceiveBuffer(1000)
	
	// Insert previous segment
	status := rb.Insert(1, 100, []byte("ABCDE"))
	assert.Equal(t, RcvInsertOk, status)
	
	// Try to insert overlapping segment with different data - should panic
	assert.Panics(t, func() {
		rb.Insert(1, 102, []byte("XXFG")) // "XX" doesn't match "CD"
	})
}