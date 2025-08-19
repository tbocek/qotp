package tomtp

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/suite"
)

type NestedIteratorTestSuite struct {
	suite.Suite
	connMap *LinkedMap[string, *ConnectionTest]
	c1, c2, c3 *ConnectionTest
}

// Mock types for testing
type ConnectionTest struct {
	id      string
	streams *LinkedMap[string, *StreamTest]
}

type StreamTest struct {
	id string
}

func (suite *NestedIteratorTestSuite) SetupTest() {
	suite.connMap = NewLinkedMap[string, *ConnectionTest]()
	
	// Create test connections with streams
	// c1 with s1, s2
	suite.c1 = &ConnectionTest{
		id:      "c1",
		streams: NewLinkedMap[string, *StreamTest](),
	}
	suite.c1.streams.Put("s1", &StreamTest{id: "s1"})
	suite.c1.streams.Put("s2", &StreamTest{id: "s2"})
	
	// c2 with s1, s2, s3
	suite.c2 = &ConnectionTest{
		id:      "c2",
		streams: NewLinkedMap[string, *StreamTest](),
	}
	suite.c2.streams.Put("s1", &StreamTest{id: "s1"})
	suite.c2.streams.Put("s2", &StreamTest{id: "s2"})
	suite.c2.streams.Put("s3", &StreamTest{id: "s3"})
	
	// c3 with s1
	suite.c3 = &ConnectionTest{
		id:      "c3",
		streams: NewLinkedMap[string, *StreamTest](),
	}
	suite.c3.streams.Put("s1", &StreamTest{id: "s1"})
	
	// Add connections to map in order
	suite.connMap.Put("c1", suite.c1)
	suite.connMap.Put("c2", suite.c2)
	suite.connMap.Put("c3", suite.c3)
}

func TestNestedIteratorTestSuite(t *testing.T) {
	suite.Run(t, new(NestedIteratorTestSuite))
}

// Test the specific examples from the requirements
func (suite *NestedIteratorTestSuite) TestExample1_C1S1() {
	// NewConnStreamIterator(c1,s1) -> c1/s2, c2/s1, c2/s2, c2/s3, c3/s1
	iter := NewNestedIterator(
		suite.connMap,
		func(conn *ConnectionTest) *LinkedMap[string, *StreamTest] {
			return conn.streams
		},
		"c1",
		"s1",
	)
	
	expected := []struct {
		connID   string
		streamID string
	}{
		{"c1", "s2"}, // c1/s2
		{"c2", "s1"}, // c2/s1
		{"c2", "s2"}, // c2/s2
		{"c2", "s3"}, // c2/s3
		{"c3", "s1"}, // c3/s1
	}
	
	for i, exp := range expected {
		conn, stream, cycleComplete := iter.Next()
		suite.NotNil(conn, "Expected connection at position %d", i)
		suite.NotNil(stream, "Expected stream at position %d", i)
		suite.Equal(exp.connID, conn.id, "Connection ID at position %d", i)
		suite.Equal(exp.streamID, stream.id, "Stream ID at position %d", i)
		suite.False(cycleComplete, "Should not be cycle complete at position %d", i)
	}
	
	// Next call should complete the cycle
	conn, stream, cycleComplete := iter.Next()
	suite.NotNil(conn, "Should return start item when cycle completes")
	suite.NotNil(stream, "Should return start item when cycle completes")
	suite.Equal("c1", conn.id, "Should return to start connection")
	suite.Equal("s1", stream.id, "Should return to start stream")
	suite.True(cycleComplete, "Should indicate cycle is complete")
}

func (suite *NestedIteratorTestSuite) TestExample2_C2S2() {
	// NewConnStreamIterator(c2,s2) -> c2/s3, c3/s1, c1/s1, c1/s2, c2/s1
	iter := NewNestedIterator(
		suite.connMap,
		func(conn *ConnectionTest) *LinkedMap[string, *StreamTest] {
			return conn.streams
		},
		"c2",
		"s2",
	)
	
	expected := []struct {
		connID   string
		streamID string
	}{
		{"c2", "s3"}, // c2/s3
		{"c3", "s1"}, // c3/s1
		{"c1", "s1"}, // c1/s1
		{"c1", "s2"}, // c1/s2
		{"c2", "s1"}, // c2/s1
	}
	
	for i, exp := range expected {
		conn, stream, cycleComplete := iter.Next()
		suite.NotNil(conn, "Expected connection at position %d", i)
		suite.NotNil(stream, "Expected stream at position %d", i)
		suite.Equal(exp.connID, conn.id, "Connection ID at position %d", i)
		suite.Equal(exp.streamID, stream.id, "Stream ID at position %d", i)
		suite.False(cycleComplete, "Should not be cycle complete at position %d", i)
	}
	
	// Next call should complete the cycle
	conn, stream, cycleComplete := iter.Next()
	suite.NotNil(conn, "Should return start item when cycle completes")
	suite.NotNil(stream, "Should return start item when cycle completes")
	suite.Equal("c2", conn.id, "Should return to start connection")
	suite.Equal("s2", stream.id, "Should return to start stream")
	suite.True(cycleComplete, "Should indicate cycle is complete")
}

func (suite *NestedIteratorTestSuite) TestExample3_C2S3() {
	// NewConnStreamIterator(c2,s3) -> c3/s1, c1/s1, c1/s2, c2/s1, c2/s2
	iter := NewNestedIterator(
		suite.connMap,
		func(conn *ConnectionTest) *LinkedMap[string, *StreamTest] {
			return conn.streams
		},
		"c2",
		"s3",
	)
	
	expected := []struct {
		connID   string
		streamID string
	}{
		{"c3", "s1"}, // c3/s1
		{"c1", "s1"}, // c1/s1
		{"c1", "s2"}, // c1/s2
		{"c2", "s1"}, // c2/s1
		{"c2", "s2"}, // c2/s2
	}
	
	for i, exp := range expected {
		conn, stream, cycleComplete := iter.Next()
		suite.NotNil(conn, "Expected connection at position %d", i)
		suite.NotNil(stream, "Expected stream at position %d", i)
		suite.Equal(exp.connID, conn.id, "Connection ID at position %d", i)
		suite.Equal(exp.streamID, stream.id, "Stream ID at position %d", i)
		suite.False(cycleComplete, "Should not be cycle complete at position %d", i)
	}
	
	// Next call should complete the cycle
	conn, stream, cycleComplete := iter.Next()
	suite.NotNil(conn, "Should return start item when cycle completes")
	suite.NotNil(stream, "Should return start item when cycle completes")
	suite.Equal("c2", conn.id, "Should return to start connection")
	suite.Equal("s3", stream.id, "Should return to start stream")
	suite.True(cycleComplete, "Should indicate cycle is complete")
}

// Test edge cases
func (suite *NestedIteratorTestSuite) TestEmptyMap() {
	emptyMap := NewLinkedMap[string, *ConnectionTest]()
	iter := NewNestedIterator(
		emptyMap,
		func(conn *ConnectionTest) *LinkedMap[string, *StreamTest] {
			return conn.streams
		},
		"c1",
		"s1",
	)
	
	conn, stream, cycleComplete := iter.Next()
	suite.Nil(conn, "Should return nil for empty map")
	suite.Nil(stream, "Should return nil for empty map")
	suite.False(cycleComplete, "Should return false for empty map")
}

func (suite *NestedIteratorTestSuite) TestInvalidStartPosition() {
	// Start with non-existent connection
	iter := NewNestedIterator(
		suite.connMap,
		func(conn *ConnectionTest) *LinkedMap[string, *StreamTest] {
			return conn.streams
		},
		"c999",
		"s1",
	)
	
	// Should start from beginning
	conn, stream, cycleComplete := iter.Next()
	suite.NotNil(conn)
	suite.NotNil(stream)
	suite.Equal("c1", conn.id)
	suite.Equal("s1", stream.id)
	suite.False(cycleComplete)
}

func (suite *NestedIteratorTestSuite) TestInvalidStartStream() {
	// Start with valid connection but invalid stream
	iter := NewNestedIterator(
		suite.connMap,
		func(conn *ConnectionTest) *LinkedMap[string, *StreamTest] {
			return conn.streams
		},
		"c1",
		"s999",
	)
	
	// Should start from beginning
	conn, stream, cycleComplete := iter.Next()
	suite.NotNil(conn)
	suite.NotNil(stream)
	suite.Equal("c1", conn.id)
	suite.Equal("s1", stream.id)
	suite.False(cycleComplete)
}

func (suite *NestedIteratorTestSuite) TestSingleConnectionSingleStream() {
	singleMap := NewLinkedMap[string, *ConnectionTest]()
	singleConn := &ConnectionTest{
		id:      "c1",
		streams: NewLinkedMap[string, *StreamTest](),
	}
	singleConn.streams.Put("s1", &StreamTest{id: "s1"})
	singleMap.Put("c1", singleConn)
	
	iter := NewNestedIterator(
		singleMap,
		func(conn *ConnectionTest) *LinkedMap[string, *StreamTest] {
			return conn.streams
		},
		"c1",
		"s1",
	)
	
	// Should return the item with cycleComplete=true since it's back to start
	conn, stream, cycleComplete := iter.Next()
	suite.NotNil(conn, "Should return the single item")
	suite.NotNil(stream, "Should return the single item")
	suite.Equal("c1", conn.id)
	suite.Equal("s1", stream.id)
	suite.True(cycleComplete, "Should indicate cycle complete for single item")
}

func (suite *NestedIteratorTestSuite) TestStartAtLastItem() {
	// Start at c3/s1 (the last item)
	iter := NewNestedIterator(
		suite.connMap,
		func(conn *ConnectionTest) *LinkedMap[string, *StreamTest] {
			return conn.streams
		},
		"c3",
		"s1",
	)
	
	// Should wrap around and return everything except c3/s1
	expected := []struct {
		connID   string
		streamID string
	}{
		{"c1", "s1"}, // c1/s1
		{"c1", "s2"}, // c1/s2
		{"c2", "s1"}, // c2/s1
		{"c2", "s2"}, // c2/s2
		{"c2", "s3"}, // c2/s3
	}
	
	for i, exp := range expected {
		conn, stream, cycleComplete := iter.Next()
		suite.NotNil(conn, "Expected connection at position %d", i)
		suite.NotNil(stream, "Expected stream at position %d", i)
		suite.Equal(exp.connID, conn.id, "Connection ID at position %d", i)
		suite.Equal(exp.streamID, stream.id, "Stream ID at position %d", i)
		suite.False(cycleComplete, "Should not be cycle complete at position %d", i)
	}
	
	// Next call should complete the cycle (return to c3/s1)
	conn, stream, cycleComplete := iter.Next()
	suite.NotNil(conn, "Should return start item when cycle completes")
	suite.NotNil(stream, "Should return start item when cycle completes")
	suite.Equal("c3", conn.id, "Should return to start connection")
	suite.Equal("s1", stream.id, "Should return to start stream")
	suite.True(cycleComplete, "Should indicate cycle is complete")
}

// Test with different generic types
func (suite *NestedIteratorTestSuite) TestGenericStringString() {
	// Create test data with string keys and string values
	type StringContainer struct {
		inner *LinkedMap[string, string]
	}
	
	outerMap := NewLinkedMap[string, *StringContainer]()
	
	// Create outer1 with inner1, inner2
	outer1 := &StringContainer{inner: NewLinkedMap[string, string]()}
	outer1.inner.Put("inner1", "value1")
	outer1.inner.Put("inner2", "value2")
	
	// Create outer2 with inner1, inner2, inner3
	outer2 := &StringContainer{inner: NewLinkedMap[string, string]()}
	outer2.inner.Put("inner1", "value1")
	outer2.inner.Put("inner2", "value2")
	outer2.inner.Put("inner3", "value3")
	
	outerMap.Put("outer1", outer1)
	outerMap.Put("outer2", outer2)
	
	iter := NewNestedIterator(
		outerMap,
		func(container *StringContainer) *LinkedMap[string, string] {
			return container.inner
		},
		"outer1",
		"inner1",
	)
	
	// Should start from outer1/inner2
	container, value, cycleComplete := iter.Next()
	suite.NotNil(container)
	suite.Equal("value2", value) // outer1/inner2
	suite.False(cycleComplete)
	
	container, value, cycleComplete = iter.Next()
	suite.NotNil(container)
	suite.Equal("value1", value) // outer2/inner1
	suite.False(cycleComplete)
	
	container, value, cycleComplete = iter.Next()
	suite.NotNil(container)
	suite.Equal("value2", value) // outer2/inner2
	suite.False(cycleComplete)
	
	container, value, cycleComplete = iter.Next()
	suite.NotNil(container)
	suite.Equal("value3", value) // outer2/inner3
	suite.False(cycleComplete)
	
	// Should complete cycle by returning to outer1/inner1
	container, value, cycleComplete = iter.Next()
	suite.NotNil(container)
	suite.Equal("value1", value) // outer1/inner1
	suite.True(cycleComplete)
}

func (suite *NestedIteratorTestSuite) TestGenericIntInt() {
	// Test with integer types
	type IntContainer struct {
		inner *LinkedMap[int, int]
	}
	
	outerMap := NewLinkedMap[int, *IntContainer]()
	
	// Create 10 with 1, 2
	container10 := &IntContainer{inner: NewLinkedMap[int, int]()}
	container10.inner.Put(1, 100)
	container10.inner.Put(2, 200)
	
	// Create 20 with 1, 2
	container20 := &IntContainer{inner: NewLinkedMap[int, int]()}
	container20.inner.Put(1, 101)
	container20.inner.Put(2, 201)
	
	outerMap.Put(10, container10)
	outerMap.Put(20, container20)
	
	iter := NewNestedIterator(
		outerMap,
		func(container *IntContainer) *LinkedMap[int, int] {
			return container.inner
		},
		10,
		1,
	)
	
	// Should start from 10/2
	container, value, cycleComplete := iter.Next()
	suite.NotNil(container)
	suite.Equal(200, value) // 10/2
	suite.False(cycleComplete)
	
	container, value, cycleComplete = iter.Next()
	suite.NotNil(container)
	suite.Equal(101, value) // 20/1
	suite.False(cycleComplete)
	
	container, value, cycleComplete = iter.Next()
	suite.NotNil(container)
	suite.Equal(201, value) // 20/2
	suite.False(cycleComplete)
	
	// Should complete cycle by returning to 10/1
	container, value, cycleComplete = iter.Next()
	suite.NotNil(container)
	suite.Equal(100, value) // 10/1
	suite.True(cycleComplete)
}

func (suite *NestedIteratorTestSuite) TestConnectionsWithEmptyStreams() {
	// Test when some connections have no streams
	emptyConnMap := NewLinkedMap[string, *ConnectionTest]()
	
	// c1 with streams
	c1 := &ConnectionTest{id: "c1", streams: NewLinkedMap[string, *StreamTest]()}
	c1.streams.Put("s1", &StreamTest{id: "s1"})
	
	// c2 with no streams
	c2 := &ConnectionTest{id: "c2", streams: NewLinkedMap[string, *StreamTest]()}
	
	// c3 with streams
	c3 := &ConnectionTest{id: "c3", streams: NewLinkedMap[string, *StreamTest]()}
	c3.streams.Put("s1", &StreamTest{id: "s1"})
	
	emptyConnMap.Put("c1", c1)
	emptyConnMap.Put("c2", c2)
	emptyConnMap.Put("c3", c3)
	
	iter := NewNestedIterator(
		emptyConnMap,
		func(conn *ConnectionTest) *LinkedMap[string, *StreamTest] {
			return conn.streams
		},
		"c1",
		"s1",
	)
	
	// Should skip c2 (empty streams) and return c3/s1
	conn, stream, cycleComplete := iter.Next()
	suite.NotNil(conn)
	suite.NotNil(stream)
	suite.Equal("c3", conn.id)
	suite.Equal("s1", stream.id)
	suite.False(cycleComplete)
	
	// Should complete cycle by returning to c1/s1
	conn, stream, cycleComplete = iter.Next()
	suite.NotNil(conn)
	suite.NotNil(stream)
	suite.Equal("c1", conn.id)
	suite.Equal("s1", stream.id)
	suite.True(cycleComplete)
}

func (suite *NestedIteratorTestSuite) TestCycling3Times_C1S1() {
	// Test that the iterator can cycle through the results 3 times
	// Starting from c1/s1, expected sequence: c1/s2, c2/s1, c2/s2, c2/s3, c3/s1
	iter := NewNestedIterator(
		suite.connMap,
		func(conn *ConnectionTest) *LinkedMap[string, *StreamTest] {
			return conn.streams
		},
		"c1",
		"s1",
	)
	
	expected := []struct {
		connID   string
		streamID string
	}{
		{"c1", "s2"}, // c1/s2
		{"c2", "s1"}, // c2/s1
		{"c2", "s2"}, // c2/s2
		{"c2", "s3"}, // c2/s3
		{"c3", "s1"}, // c3/s1
	}
	
	// Cycle 1: First complete iteration
	suite.T().Log("=== Cycle 1 ===")
	for i, exp := range expected {
		conn, stream, cycleComplete := iter.Next()
		suite.NotNil(conn, "Cycle 1: Expected connection at position %d", i)
		suite.NotNil(stream, "Cycle 1: Expected stream at position %d", i)
		suite.Equal(exp.connID, conn.id, "Cycle 1: Connection ID at position %d", i)
		suite.Equal(exp.streamID, stream.id, "Cycle 1: Stream ID at position %d", i)
		suite.False(cycleComplete, "Cycle 1: Should not be complete at position %d", i)
		suite.T().Logf("Cycle 1, Position %d: %s/%s", i, conn.id, stream.id)
	}
	
	// Should complete cycle when returning to c1/s1
	conn, stream, cycleComplete := iter.Next()
	suite.NotNil(conn, "Cycle 1: Should return start item when cycle completes")
	suite.NotNil(stream, "Cycle 1: Should return start item when cycle completes")
	suite.Equal("c1", conn.id, "Cycle 1: Should return to start connection")
	suite.Equal("s1", stream.id, "Cycle 1: Should return to start stream")
	suite.True(cycleComplete, "Cycle 1: Should indicate cycle is complete")
	suite.T().Log("Cycle 1: Complete - returned c1/s1 with cycleComplete=true")
	
	// Cycle 2: Should continue and repeat the same sequence
	suite.T().Log("=== Cycle 2 ===")
	for i, exp := range expected {
		conn, stream, cycleComplete := iter.Next()
		suite.NotNil(conn, "Cycle 2: Expected connection at position %d", i)
		suite.NotNil(stream, "Cycle 2: Expected stream at position %d", i)
		suite.Equal(exp.connID, conn.id, "Cycle 2: Connection ID at position %d", i)
		suite.Equal(exp.streamID, stream.id, "Cycle 2: Stream ID at position %d", i)
		suite.False(cycleComplete, "Cycle 2: Should not be complete at position %d", i)
		suite.T().Logf("Cycle 2, Position %d: %s/%s", i, conn.id, stream.id)
	}
	
	// Should complete second cycle
	conn, stream, cycleComplete = iter.Next()
	suite.NotNil(conn, "Cycle 2: Should return start item when cycle completes")
	suite.NotNil(stream, "Cycle 2: Should return start item when cycle completes")
	suite.Equal("c1", conn.id, "Cycle 2: Should return to start connection")
	suite.Equal("s1", stream.id, "Cycle 2: Should return to start stream")
	suite.True(cycleComplete, "Cycle 2: Should indicate cycle is complete")
	suite.T().Log("Cycle 2: Complete - returned c1/s1 with cycleComplete=true")
	
	// Cycle 3: Should continue and repeat the same sequence again
	suite.T().Log("=== Cycle 3 ===")
	for i, exp := range expected {
		conn, stream, cycleComplete := iter.Next()
		suite.NotNil(conn, "Cycle 3: Expected connection at position %d", i)
		suite.NotNil(stream, "Cycle 3: Expected stream at position %d", i)
		suite.Equal(exp.connID, conn.id, "Cycle 3: Connection ID at position %d", i)
		suite.Equal(exp.streamID, stream.id, "Cycle 3: Stream ID at position %d", i)
		suite.False(cycleComplete, "Cycle 3: Should not be complete at position %d", i)
		suite.T().Logf("Cycle 3, Position %d: %s/%s", i, conn.id, stream.id)
	}
	
	// Should complete third cycle
	conn, stream, cycleComplete = iter.Next()
	suite.NotNil(conn, "Cycle 3: Should return start item when cycle completes")
	suite.NotNil(stream, "Cycle 3: Should return start item when cycle completes")
	suite.Equal("c1", conn.id, "Cycle 3: Should return to start connection")
	suite.Equal("s1", stream.id, "Cycle 3: Should return to start stream")
	suite.True(cycleComplete, "Cycle 3: Should indicate cycle is complete")
	suite.T().Log("Cycle 3: Complete - returned c1/s1 with cycleComplete=true")
	
	// Verify we can continue even more cycles
	suite.T().Log("=== Cycle 4 (partial) ===")
	conn, stream, cycleComplete = iter.Next()
	suite.NotNil(conn, "Cycle 4: Should continue cycling")
	suite.NotNil(stream, "Cycle 4: Should continue cycling")
	suite.Equal("c1", conn.id, "Cycle 4: Should start with c1")
	suite.Equal("s2", stream.id, "Cycle 4: Should start with s2")
	suite.False(cycleComplete, "Cycle 4: Should not be complete at first position")
	suite.T().Logf("Cycle 4, Position 0: %s/%s", conn.id, stream.id)
}

func (suite *NestedIteratorTestSuite) TestExternalLoopUsage() {
	// Demonstrate how to use the iterator in an external loop
	iter := NewNestedIterator(
		suite.connMap,
		func(conn *ConnectionTest) *LinkedMap[string, *StreamTest] {
			return conn.streams
		},
		"c2",
		"s2",
	)
	
	suite.T().Log("=== External loop usage example ===")
	
	var results []string
	for {
		conn, stream, cycleComplete := iter.Next()
		if conn == nil {
			suite.T().Log("Iterator returned nil - stopping")
			break
		}
		
		result := fmt.Sprintf("%s/%s", conn.id, stream.id)
		results = append(results, result)
		suite.T().Logf("Got: %s (cycleComplete=%t)", result, cycleComplete)
		
		if cycleComplete {
			suite.T().Log("Cycle completed - stopping external loop")
			break
		}
	}
	
	expected := []string{"c2/s3", "c3/s1", "c1/s1", "c1/s2", "c2/s1", "c2/s2"}
	suite.Equal(expected, results, "Should get expected sequence including the completing item")
}

func (suite *NestedIteratorTestSuite) TestSimpleCycleExample() {
	// Test one complete cycle starting from c2/s1
	// Expected: c2/s2, c2/s3, c3/s1, c1/s1, c1/s2, then back to c2/s1 (cycleComplete=true)
	iter := NewNestedIterator(
		suite.connMap,
		func(conn *ConnectionTest) *LinkedMap[string, *StreamTest] {
			return conn.streams
		},
		"c2",
		"s1",
	)
	
	// First item: c2/s2
	conn, stream, cycleComplete := iter.Next()
	suite.Equal("c2", conn.id)
	suite.Equal("s2", stream.id)
	suite.False(cycleComplete)
	
	// Second item: c2/s3
	conn, stream, cycleComplete = iter.Next()
	suite.Equal("c2", conn.id)
	suite.Equal("s3", stream.id)
	suite.False(cycleComplete)
	
	// Third item: c3/s1
	conn, stream, cycleComplete = iter.Next()
	suite.Equal("c3", conn.id)
	suite.Equal("s1", stream.id)
	suite.False(cycleComplete)
	
	// Fourth item: c1/s1
	conn, stream, cycleComplete = iter.Next()
	suite.Equal("c1", conn.id)
	suite.Equal("s1", stream.id)
	suite.False(cycleComplete)
	
	// Fifth item: c1/s2
	conn, stream, cycleComplete = iter.Next()
	suite.Equal("c1", conn.id)
	suite.Equal("s2", stream.id)
	suite.False(cycleComplete)
	
	// Cycle complete: back to c2/s1
	conn, stream, cycleComplete = iter.Next()
	suite.Equal("c2", conn.id)
	suite.Equal("s1", stream.id)
	suite.True(cycleComplete) // Cycle is now complete!
}

func (suite *NestedIteratorTestSuite) TestTwoItemCycle() {
	// Create a simple map with only one connection having two streams
	simpleMap := NewLinkedMap[string, *ConnectionTest]()
	
	// c1 with only s1, s2
	c1 := &ConnectionTest{
		id:      "c1",
		streams: NewLinkedMap[string, *StreamTest](),
	}
	c1.streams.Put("s1", &StreamTest{id: "s1"})
	c1.streams.Put("s2", &StreamTest{id: "s2"})
	
	simpleMap.Put("c1", c1)
	
	// Test 1: Input c1/s1, should give c1/s2
	suite.T().Log("=== Test 1: Start from c1/s1 ===")
	iter1 := NewNestedIterator(
		simpleMap,
		func(conn *ConnectionTest) *LinkedMap[string, *StreamTest] {
			return conn.streams
		},
		"c1",
		"s1",
	)
	
	// Should return c1/s2
	conn, stream, cycleComplete := iter1.Next()
	suite.NotNil(conn, "Should return connection")
	suite.NotNil(stream, "Should return stream")
	suite.Equal("c1", conn.id, "Should return c1")
	suite.Equal("s2", stream.id, "Should return s2")
	suite.False(cycleComplete, "Should not be cycle complete yet")
	suite.T().Logf("Got: %s/%s (cycleComplete=%t)", conn.id, stream.id, cycleComplete)
	
	// Next call should complete the cycle by returning c1/s1
	conn, stream, cycleComplete = iter1.Next()
	suite.NotNil(conn, "Should return start item when cycle completes")
	suite.NotNil(stream, "Should return start item when cycle completes")
	suite.Equal("c1", conn.id, "Should return to start connection")
	suite.Equal("s1", stream.id, "Should return to start stream")
	suite.True(cycleComplete, "Should indicate cycle is complete")
	suite.T().Logf("Cycle complete: %s/%s (cycleComplete=%t)", conn.id, stream.id, cycleComplete)
	
	// Test 2: Input c1/s2, should give c1/s1
	suite.T().Log("=== Test 2: Start from c1/s2 ===")
	iter2 := NewNestedIterator(
		simpleMap,
		func(conn *ConnectionTest) *LinkedMap[string, *StreamTest] {
			return conn.streams
		},
		"c1",
		"s2",
	)
	
	// Should return c1/s1 (wraps around since s2 is the last)
	conn, stream, cycleComplete = iter2.Next()
	suite.NotNil(conn, "Should return connection")
	suite.NotNil(stream, "Should return stream")
	suite.Equal("c1", conn.id, "Should return c1")
	suite.Equal("s1", stream.id, "Should return s1")
	suite.False(cycleComplete, "Should not be cycle complete yet")
	suite.T().Logf("Got: %s/%s (cycleComplete=%t)", conn.id, stream.id, cycleComplete)
	
	// Next call should complete the cycle by returning c1/s2
	conn, stream, cycleComplete = iter2.Next()
	suite.NotNil(conn, "Should return start item when cycle completes")
	suite.NotNil(stream, "Should return start item when cycle completes")
	suite.Equal("c1", conn.id, "Should return to start connection")
	suite.Equal("s2", stream.id, "Should return to start stream")
	suite.True(cycleComplete, "Should indicate cycle is complete")
	suite.T().Logf("Cycle complete: %s/%s (cycleComplete=%t)", conn.id, stream.id, cycleComplete)
}