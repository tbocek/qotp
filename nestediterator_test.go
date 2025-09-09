package qotp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Helper function to create string pointer
func stringPtr(s string) *string {
	return &s
}

// Mock types for testing - using string pointers as values
type ConnectionTest struct {
	id      string
	streams *LinkedMap[string, *string]
}

func TestNestedIterator_StatefulIteration(t *testing.T) {
	connMap := NewLinkedMap[string, *ConnectionTest]()
	
	// Create test connections with streams
	// c1 with s1, s2
	c1 := &ConnectionTest{
		id:      "c1",
		streams: NewLinkedMap[string, *string](),
	}
	s1 := "s1"
	s2 := "s2"
	c1.streams.Put("s1", &s1)
	c1.streams.Put("s2", &s2)
	
	// c2 with s1, s2, s3
	c2 := &ConnectionTest{
		id:      "c2",
		streams: NewLinkedMap[string, *string](),
	}
	s2_1 := "s1"
	s2_2 := "s2"
	s2_3 := "s3"
	c2.streams.Put("s1", &s2_1)
	c2.streams.Put("s2", &s2_2)
	c2.streams.Put("s3", &s2_3)
	
	// c3 with s1
	c3 := &ConnectionTest{
		id:      "c3",
		streams: NewLinkedMap[string, *string](),
	}
	s3_1 := "s1"
	c3.streams.Put("s1", &s3_1)
	
	// Add connections to map in order
	connMap.Put("c1", c1)
	connMap.Put("c2", c2)
	connMap.Put("c3", c3)
	
	// Test complete iteration cycle
	expectedSequence := []struct {
		connID, streamID string
	}{
		{"c1", "s1"},
		{"c1", "s2"},
		{"c2", "s1"},
		{"c2", "s2"},
		{"c2", "s3"},
		{"c3", "s1"},
	}
	
	i := 0
	for conn, stream := range NestedIterator(connMap, func(conn *ConnectionTest) *LinkedMap[string, *string] {
		return conn.streams
	}) {
		if i >= len(expectedSequence) {
			break // Stop after one full cycle
		}
		assert.Equal(t, expectedSequence[i].connID, conn.id, "Wrong connection at step %d", i)
		assert.NotNil(t, stream, "Stream should not be nil at step %d", i)
		assert.Equal(t, expectedSequence[i].streamID, *stream, "Wrong stream at step %d", i)
		i++
	}
	assert.Equal(t, len(expectedSequence), i, "Should have iterated through all expected items")
}

func TestNestedIterator_EmptyMaps(t *testing.T) {
	// Create empty maps
	emptyConnMap := NewLinkedMap[string, *ConnectionTest]()
	
	count := 0
	for conn, stream := range NestedIterator(emptyConnMap, func(conn *ConnectionTest) *LinkedMap[string, *string] {
		return conn.streams
	}) {
		_ = conn
		_ = stream
		count++
	}
	assert.Equal(t, 0, count, "Should not iterate over empty map")
}

func TestNestedIterator_ConnectionWithNoStreams(t *testing.T) {
	// Create connection with no streams
	emptyConn := &ConnectionTest{
		id:      "empty",
		streams: NewLinkedMap[string, *string](),
	}
	
	// Create map with only empty connection
	emptyConnMap := NewLinkedMap[string, *ConnectionTest]()
	emptyConnMap.Put("empty", emptyConn)
	
	count := 0
	for conn, stream := range NestedIterator(emptyConnMap, func(conn *ConnectionTest) *LinkedMap[string, *string] {
		return conn.streams
	}) {
		_ = conn
		_ = stream
		count++
	}
	// With the new iterator, empty inner maps are skipped
	assert.Equal(t, 0, count, "Should skip connections with no streams")
}

func TestNestedIterator_SingleConnectionSingleStream(t *testing.T) {
	// Test with only one connection and one stream
	singleConnMap := NewLinkedMap[string, *ConnectionTest]()
	singleConn := &ConnectionTest{
		id:      "single",
		streams: NewLinkedMap[string, *string](),
	}
	s1 := "s1"
	singleConn.streams.Put("s1", &s1)
	singleConnMap.Put("single", singleConn)
	
	count := 0
	for conn, stream := range NestedIterator(singleConnMap, func(conn *ConnectionTest) *LinkedMap[string, *string] {
		return conn.streams
	}) {
		assert.Equal(t, "single", conn.id)
		assert.NotNil(t, stream)
		assert.Equal(t, "s1", *stream)
		count++
		if count >= 3 {
			break // Test that we can iterate multiple times (but stop after 3 for testing)
		}
	}
	assert.Equal(t, 1, count, "Should iterate once over single item")
}

func TestNestedIterator_MultipleConnections(t *testing.T) {
	connMap := NewLinkedMap[string, *ConnectionTest]()
	
	// c1 with s1, s2
	c1 := &ConnectionTest{
		id:      "c1",
		streams: NewLinkedMap[string, *string](),
	}
	s1 := "s1"
	s2 := "s2"
	c1.streams.Put("s1", &s1)
	c1.streams.Put("s2", &s2)
	
	// c2 with s1, s2, s3
	c2 := &ConnectionTest{
		id:      "c2",
		streams: NewLinkedMap[string, *string](),
	}
	s2_1 := "s1"
	s2_2 := "s2"
	s2_3 := "s3"
	c2.streams.Put("s1", &s2_1)
	c2.streams.Put("s2", &s2_2)
	c2.streams.Put("s3", &s2_3)
	
	// c3 with s1
	c3 := &ConnectionTest{
		id:      "c3",
		streams: NewLinkedMap[string, *string](),
	}
	s3_1 := "s1"
	c3.streams.Put("s1", &s3_1)
	
	connMap.Put("c1", c1)
	connMap.Put("c2", c2)
	connMap.Put("c3", c3)
	
	// Test iteration through multiple connections
	positions := []struct {
		expectedConn, expectedStream string
	}{
		{"c1", "s1"},
		{"c1", "s2"},
		{"c2", "s1"},
		{"c2", "s2"},
		{"c2", "s3"},
		{"c3", "s1"},
	}
	
	i := 0
	for conn, stream := range NestedIterator(connMap, func(conn *ConnectionTest) *LinkedMap[string, *string] {
		return conn.streams
	}) {
		if i >= len(positions) {
			break
		}
		assert.Equal(t, positions[i].expectedConn, conn.id, "Wrong connection at iteration %d", i)
		assert.NotNil(t, stream, "Stream should not be nil at iteration %d", i)
		assert.Equal(t, positions[i].expectedStream, *stream, "Wrong stream at iteration %d", i)
		i++
	}
	assert.Equal(t, len(positions), i, "Should iterate through all positions")
}

func TestNestedIterator_SkipsEmptyConnections(t *testing.T) {
	// Create a new setup with an empty connection in the middle
	mixedConnMap := NewLinkedMap[string, *ConnectionTest]()
	
	// c1 with streams
	c1 := &ConnectionTest{
		id:      "c1",
		streams: NewLinkedMap[string, *string](),
	}
	s1 := "s1"
	c1.streams.Put("s1", &s1)
	
	// c2 with NO streams (empty)
	c2Empty := &ConnectionTest{
		id:      "c2",
		streams: NewLinkedMap[string, *string](),
	}
	
	// c3 with streams
	c3 := &ConnectionTest{
		id:      "c3",
		streams: NewLinkedMap[string, *string](),
	}
	s3 := "s1"
	c3.streams.Put("s1", &s3)
	
	mixedConnMap.Put("c1", c1)
	mixedConnMap.Put("c2", c2Empty)
	mixedConnMap.Put("c3", c3)
	
	// Collect results
	var results []string
	for conn, stream := range NestedIterator(mixedConnMap, func(conn *ConnectionTest) *LinkedMap[string, *string] {
		return conn.streams
	}) {
		if stream != nil {
			results = append(results, conn.id+"/"+*stream)
		} else {
			results = append(results, conn.id+"/nil")
		}
		if len(results) >= 5 {
			break // Stop after 5 iterations for testing
		}
	}
	
	// With the new iterator, empty connections are skipped
	expected := []string{"c1/s1", "c3/s1"}
	assert.Equal(t, expected, results[:len(expected)], "Should skip empty connection c2")
}

func TestNestedIterator_ConsistentState(t *testing.T) {
	connMap := NewLinkedMap[string, *ConnectionTest]()
	
	// c1 with s1, s2
	c1 := &ConnectionTest{
		id:      "c1",
		streams: NewLinkedMap[string, *string](),
	}
	s1 := "s1"
	s2 := "s2"
	c1.streams.Put("s1", &s1)
	c1.streams.Put("s2", &s2)
	
	// c2 with s1, s2, s3
	c2 := &ConnectionTest{
		id:      "c2",
		streams: NewLinkedMap[string, *string](),
	}
	s2_1 := "s1"
	s2_2 := "s2"
	s2_3 := "s3"
	c2.streams.Put("s1", &s2_1)
	c2.streams.Put("s2", &s2_2)
	c2.streams.Put("s3", &s2_3)
	
	connMap.Put("c1", c1)
	connMap.Put("c2", c2)
	
	// Test that the iterator maintains consistent order
	var results []string
	count := 0
	for conn, stream := range NestedIterator(connMap, func(conn *ConnectionTest) *LinkedMap[string, *string] {
		return conn.streams
	}) {
		results = append(results, conn.id+"/"+*stream)
		count++
		if count >= 5 {
			break
		}
	}
	
	expected := []string{
		"c1/s1",
		"c1/s2",
		"c2/s1",
		"c2/s2",
		"c2/s3",
	}
	assert.Equal(t, expected, results, "Should maintain consistent iteration order")
}

func TestNestedIterator_BreakEarly(t *testing.T) {
	connMap := NewLinkedMap[string, *ConnectionTest]()
	
	// Create multiple connections
	for i := 0; i < 3; i++ {
		conn := &ConnectionTest{
			id:      string(rune('a' + i)),
			streams: NewLinkedMap[string, *string](),
		}
		for j := 0; j < 3; j++ {
			s := string(rune('0' + j))
			conn.streams.Put(s, &s)
		}
		connMap.Put(conn.id, conn)
	}
	
	// Test early break
	count := 0
	for conn, stream := range NestedIterator(connMap, func(conn *ConnectionTest) *LinkedMap[string, *string] {
		return conn.streams
	}) {
		_ = conn
		_ = stream
		count++
		if count == 5 {
			break
		}
	}
	assert.Equal(t, 5, count, "Should be able to break early from iteration")
}

func TestNestedIterator_NilInnerMap(t *testing.T) {
	connMap := NewLinkedMap[string, *ConnectionTest]()
	
	// Create connections, some with nil streams map
	c1 := &ConnectionTest{
		id:      "c1",
		streams: NewLinkedMap[string, *string](),
	}
	s1 := "s1"
	c1.streams.Put("s1", &s1)
	
	c2 := &ConnectionTest{
		id:      "c2",
		streams: nil, // nil streams map
	}
	
	c3 := &ConnectionTest{
		id:      "c3",
		streams: NewLinkedMap[string, *string](),
	}
	s3 := "s1"
	c3.streams.Put("s1", &s3)
	
	connMap.Put("c1", c1)
	connMap.Put("c2", c2)
	connMap.Put("c3", c3)
	
	// Should handle nil inner maps gracefully
	var results []string
	for conn, stream := range NestedIterator(connMap, func(conn *ConnectionTest) *LinkedMap[string, *string] {
		return conn.streams
	}) {
		results = append(results, conn.id+"/"+*stream)
	}
	
	// Should skip c2 which has nil streams
	expected := []string{"c1/s1", "c3/s1"}
	assert.Equal(t, expected, results, "Should skip connections with nil inner map")
}

func TestNestedIterator_ComplexNesting(t *testing.T) {
	// Test with more complex data structure
	type Department struct {
		name      string
		employees *LinkedMap[string, *string]
	}
	
	deptMap := NewLinkedMap[string, *Department]()
	
	// Engineering department
	eng := &Department{
		name:      "Engineering",
		employees: NewLinkedMap[string, *string](),
	}
	alice := "Alice"
	bob := "Bob"
	eng.employees.Put("e1", &alice)
	eng.employees.Put("e2", &bob)
	
	// Marketing department
	mkt := &Department{
		name:      "Marketing",
		employees: NewLinkedMap[string, *string](),
	}
	charlie := "Charlie"
	mkt.employees.Put("m1", &charlie)
	
	// HR department (empty)
	hr := &Department{
		name:      "HR",
		employees: NewLinkedMap[string, *string](),
	}
	
	deptMap.Put("eng", eng)
	deptMap.Put("mkt", mkt)
	deptMap.Put("hr", hr)
	
	// Collect all employees
	var employees []string
	for dept, emp := range NestedIterator(deptMap, func(d *Department) *LinkedMap[string, *string] {
		return d.employees
	}) {
		employees = append(employees, dept.name+":"+*emp)
	}
	
	expected := []string{
		"Engineering:Alice",
		"Engineering:Bob",
		"Marketing:Charlie",
	}
	assert.Equal(t, expected, employees, "Should iterate through all departments and employees")
}