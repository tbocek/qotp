package tomtp

import (
	"github.com/stretchr/testify/suite"
	"sync"
	"testing"
)

type SortedHashMapTestSuite struct {
	suite.Suite
	shm *SortedMap[int, string]
}

func (s *SortedHashMapTestSuite) SetupTest() {
	s.shm = NewSortedMap[int, string](func(a, b int) bool { return a < b })
}

func TestSortedHashMapSuite(t *testing.T) {
	suite.Run(t, new(SortedHashMapTestSuite))
}

func (s *SortedHashMapTestSuite) TestBasicOperations() {
	// Test empty map
	s.NotNil(s.shm)
	s.Equal(0, s.shm.Size())
	
	minKey, minVal := s.shm.Min()
	s.Equal(0, minKey)    // zero value for int
	s.Equal("", minVal)   // zero value for string

	// Test basic Put and Get
	s.shm.Put(1, "one")
	value := s.shm.Get(1)
	s.Equal("one", value)

	// Test updating existing key
	s.shm.Put(1, "ONE")
	value = s.shm.Get(1)
	s.Equal("ONE", value)
	s.Equal(1, s.shm.Size())

	// Test non-existent key
	value = s.shm.Get(999)
	s.Equal("", value) // zero value for string
}

func (s *SortedHashMapTestSuite) TestContainsOperation() {
	// Test empty map
	s.False(s.shm.Contains(1))

	// Add some values
	s.shm.Put(1, "one")
	s.shm.Put(2, "two")

	// Test existing keys
	s.True(s.shm.Contains(1))
	s.True(s.shm.Contains(2))

	// Test non-existing key
	s.False(s.shm.Contains(3))

	// Test after removal
	s.shm.Remove(1)
	s.False(s.shm.Contains(1))
	s.True(s.shm.Contains(2))
}

func (s *SortedHashMapTestSuite) TestTreeOperations() {
	values := []struct {
		key   int
		value string
	}{
		{5, "five"},
		{3, "three"},
		{7, "seven"},
		{1, "one"},
		{9, "nine"},
		{4, "four"},
		{6, "six"},
	}

	// Insert values
	for _, v := range values {
		s.shm.Put(v.key, v.value)
	}

	// Test ordered traversal using Next(key) method
	expected := []int{1, 3, 4, 5, 6, 7, 9}
	
	// Start from minimum and traverse
	currentKey, currentVal := s.shm.Min()
	s.Equal(1, currentKey)
	s.Equal("one", currentVal)
	
	for i, exp := range expected {
		s.Equal(exp, currentKey, "Unexpected key at position %d", i)
		
		// Get next key for next iteration
		if i < len(expected)-1 {
			currentKey, _ = s.shm.Next(currentKey)
		}
	}
	
	// Verify no next after last element (should return zero values)
	nextKey, nextVal := s.shm.Next(currentKey)
	s.Equal(0, nextKey)   // zero value for int
	s.Equal("", nextVal)  // zero value for string
}

func (s *SortedHashMapTestSuite) TestRemoveOperations() {
	// Test removing from empty map
	value := s.shm.Remove(1)
	s.Equal("", value) // zero value

	// Build a complex map
	values := []int{8, 4, 12, 2, 6, 10, 14, 1, 3, 5, 7, 9, 11, 13, 15}
	for _, v := range values {
		s.shm.Put(v, "value")
	}

	// Test removing elements
	value = s.shm.Remove(15)
	s.Equal("value", value)
	s.Equal("", s.shm.Get(15)) // Should be gone

	value = s.shm.Remove(14)
	s.Equal("value", value)
	
	// Check that 13 is now accessible (since 14 and 15 are gone)
	s.True(s.shm.Contains(13))

	value = s.shm.Remove(8)
	s.Equal("value", value)

	// Verify some remaining elements
	s.True(s.shm.Contains(1))
	s.True(s.shm.Contains(13))
	s.False(s.shm.Contains(8))
	s.False(s.shm.Contains(14))
	s.False(s.shm.Contains(15))
}

func (s *SortedHashMapTestSuite) TestMinOperations() {
	// Test empty map
	minKey, minVal := s.shm.Min()
	s.Equal(0, minKey)
	s.Equal("", minVal)

	// Add items in non-sorted order
	values := map[int]string{
		5: "five",
		3: "three",
		7: "seven",
		1: "one",
		9: "nine",
	}
	for k, v := range values {
		s.shm.Put(k, v)
	}

	// Test minimum
	minKey, minVal = s.shm.Min()
	s.Equal(1, minKey)
	s.Equal("one", minVal)

	// Test after removing minimum
	s.shm.Remove(1)
	minKey, minVal = s.shm.Min()
	s.Equal(3, minKey)
	s.Equal("three", minVal)
}

func (s *SortedHashMapTestSuite) TestNextOperations() {
	// Test Next on empty map
	nextKey, nextVal := s.shm.Next(1)
	s.Equal(0, nextKey)
	s.Equal("", nextVal)

	// Test Next with single element
	s.shm.Put(1, "one")
	minKey, minVal := s.shm.Min()
	s.Equal(1, minKey)
	s.Equal("one", minVal)
	
	// Should have no next
	nextKey, nextVal = s.shm.Next(1)
	s.Equal(0, nextKey)
	s.Equal("", nextVal)

	// Test Next with multiple elements
	s.shm.Put(2, "two")
	s.shm.Put(3, "three")

	// Test traversal
	key, val := s.shm.Min()
	s.Equal(1, key)
	s.Equal("one", val)
	
	key, val = s.shm.Next(key)
	s.Equal(2, key)
	s.Equal("two", val)
	
	key, val = s.shm.Next(key)
	s.Equal(3, key)
	s.Equal("three", val)
	
	// No more elements
	key, val = s.shm.Next(key)
	s.Equal(0, key)
	s.Equal("", val)
}

func (s *SortedHashMapTestSuite) TestNextFromKey() {
	// Add some values
	values := []int{1, 3, 5, 7, 9}
	for _, v := range values {
		s.shm.Put(v, "value")
	}

	// Test Next from existing key
	nextKey, nextValue := s.shm.Next(3)
	s.Equal(5, nextKey)
	s.Equal("value", nextValue)

	// Test Next from non-existing key
	nextKey, nextValue = s.shm.Next(4)
	s.Equal(5, nextKey)
	s.Equal("value", nextValue)

	// Test Next from last key (should return zero values)
	nextKey, nextValue = s.shm.Next(9)
	s.Equal(0, nextKey)
	s.Equal("", nextValue)

	// Test Next from key larger than all keys
	nextKey, nextValue = s.shm.Next(10)
	s.Equal(0, nextKey)
	s.Equal("", nextValue)
}

func (s *SortedHashMapTestSuite) TestHasNextOperation() {
	// Test empty map
	s.False(s.shm.HasNext(1))

	// Add some values
	values := []int{1, 3, 5, 7, 9}
	for _, v := range values {
		s.shm.Put(v, "value")
	}

	// Test HasNext with existing keys
	s.True(s.shm.HasNext(1))
	s.True(s.shm.HasNext(3))
	s.True(s.shm.HasNext(5))
	s.True(s.shm.HasNext(7))
	s.False(s.shm.HasNext(9)) // last element

	// Test HasNext with non-existing keys
	s.True(s.shm.HasNext(2))  // between 1 and 3
	s.True(s.shm.HasNext(4))  // between 3 and 5
	s.False(s.shm.HasNext(10)) // beyond last element
	s.True(s.shm.HasNext(0))   // before first element
}

func (s *SortedHashMapTestSuite) TestConcurrentOperations() {
	var wg sync.WaitGroup
	numGoroutines := 10
	numOperations := 100

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				val := base*numOperations + j
				s.shm.Put(val, "value")
			}
		}(i)
	}

	// Concurrent reads and removes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				if j%2 == 0 {
					s.shm.Get(j)
				} else {
					s.shm.Remove(j)
				}
			}
		}()
	}

	wg.Wait()
}

func (s *SortedHashMapTestSuite) TestCustomComparators() {
	// Test with reverse order comparator
	reverseMap := NewSortedMap[int, string](func(a, b int) bool { return a > b })
	values := []int{5, 3, 7, 1, 9}
	for _, v := range values {
		reverseMap.Put(v, "value")
	}

	// Verify reverse order by traversing from min
	expected := []int{9, 7, 5, 3, 1}
	currentKey, _ := reverseMap.Min()
	for _, exp := range expected {
		s.Equal(exp, currentKey)
		if exp != 1 { // not the last element
			currentKey, _ = reverseMap.Next(currentKey)
		}
	}

	// Test with custom struct keys
	type CustomKey struct {
		value int
	}
	customMap := NewSortedMap[CustomKey, string](
		func(a, b CustomKey) bool { return a.value < b.value },
	)
	customMap.Put(CustomKey{1}, "one")
	customMap.Put(CustomKey{2}, "two")
	
	minKey, minVal := customMap.Min()
	s.Equal(CustomKey{1}, minKey)
	s.Equal("one", minVal)
}

func (s *SortedHashMapTestSuite) TestEdgeCases() {
	// Test updating value for existing key
	s.shm.Put(1, "original")
	s.Equal("original", s.shm.Get(1))
	s.Equal(1, s.shm.Size())
	
	s.shm.Put(1, "updated")
	s.Equal("updated", s.shm.Get(1))
	s.Equal(1, s.shm.Size()) // Size shouldn't change

	// Test removing non-existent key
	removedVal := s.shm.Remove(999)
	s.Equal("", removedVal)

	// Test Contains after operations
	s.shm.Put(5, "five")
	s.True(s.shm.Contains(5))
	s.shm.Remove(5)
	s.False(s.shm.Contains(5))
}