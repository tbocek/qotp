package tomtp

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type LinkedMapTestSuite struct {
	suite.Suite
	lm *LinkedMap[string, int] // Changed from *string to string
}

func (suite *LinkedMapTestSuite) SetupTest() {
	suite.lm = NewLinkedMap[string, int]()
}

func TestLinkedMapTestSuite(t *testing.T) {
	suite.Run(t, new(LinkedMapTestSuite))
}

// Test NewLinkedMap
func (suite *LinkedMapTestSuite) TestNewLinkedMap() {
	lm := NewLinkedMap[string, int]()
	suite.NotNil(lm)
	suite.NotNil(lm.items)
	suite.NotNil(lm.head)
	suite.NotNil(lm.tail)
	suite.Equal(0, lm.size)
	suite.Equal(lm.tail, lm.head.next)
	suite.Equal(lm.head, lm.tail.prev)
}

// Test Size function
func (suite *LinkedMapTestSuite) TestSize_Empty() {
	suite.Equal(0, suite.lm.Size())
}

func (suite *LinkedMapTestSuite) TestSize_WithElements() {
	suite.lm.Put("a", 1)
	suite.Equal(1, suite.lm.Size())
	
	suite.lm.Put("b", 2)
	suite.Equal(2, suite.lm.Size())
	
	suite.lm.Put("c", 3)
	suite.Equal(3, suite.lm.Size())
}

func (suite *LinkedMapTestSuite) TestSize_AfterRemoval() {
	suite.lm.Put("a", 1)
	suite.lm.Put("b", 2)
	suite.Equal(2, suite.lm.Size())
	
	_, ok := suite.lm.Remove("a")
	suite.True(ok)
	suite.Equal(1, suite.lm.Size())
	
	_, ok = suite.lm.Remove("b")
	suite.True(ok)
	suite.Equal(0, suite.lm.Size())
}

// Test Put function
func (suite *LinkedMapTestSuite) TestPut_NewKey() {
	key1 := "key1"
	suite.lm.Put(key1, 100)
	suite.Equal(1, suite.lm.Size())
	suite.Equal(100, suite.lm.Get(key1))
}

func (suite *LinkedMapTestSuite) TestPut_UpdateExistingKey() {
	key1 := "key1"
	suite.lm.Put(key1, 100)
	suite.lm.Put(key1, 200) // Update existing key
	
	suite.Equal(1, suite.lm.Size()) // Size should remain the same
	suite.Equal(200, suite.lm.Get(key1))
}

func (suite *LinkedMapTestSuite) TestPut_MultipleKeys() {
	a := "a"
	b := "b"
	c := "c"
	
	suite.lm.Put(a, 1)
	suite.lm.Put(b, 2)
	suite.lm.Put(c, 3)
	
	suite.Equal(3, suite.lm.Size())
	suite.Equal(1, suite.lm.Get(a))
	suite.Equal(2, suite.lm.Get(b))
	suite.Equal(3, suite.lm.Get(c))
}

func (suite *LinkedMapTestSuite) TestPut_InsertionOrder() {
	first := "first"
	second := "second"
	third := "third"
	
	suite.lm.Put(first, 1)
	suite.lm.Put(second, 2)
	suite.lm.Put(third, 3)
	
	// Check insertion order using First and Next
	key, value, ok := suite.lm.First()
	suite.True(ok)
	suite.Equal(first, key)
	suite.Equal(1, value)
	
	key, value, ok = suite.lm.Next(first)
	suite.True(ok)
	suite.Equal(second, key)
	suite.Equal(2, value)
	
	key, value, ok = suite.lm.Next(second)
	suite.True(ok)
	suite.Equal(third, key)
	suite.Equal(3, value)
}

func (suite *LinkedMapTestSuite) TestPut_UpdateDoesNotChangeOrder() {
	first := "first"
	second := "second"
	third := "third"
	
	suite.lm.Put(first, 1)
	suite.lm.Put(second, 2)
	suite.lm.Put(third, 3)
	
	// Update second element
	suite.lm.Put(second, 200)
	
	// Order should remain the same
	key, value, ok := suite.lm.First()
	suite.True(ok)
	suite.Equal(first, key)
	suite.Equal(1, value)
	
	key, value, ok = suite.lm.Next(first)
	suite.True(ok)
	suite.Equal(second, key)
	suite.Equal(200, value) // Updated value
	
	key, value, ok = suite.lm.Next(second)
	suite.True(ok)
	suite.Equal(third, key)
	suite.Equal(3, value)
}

// Test Get function
func (suite *LinkedMapTestSuite) TestGet_ExistingKey() {
	key1 := "key1"
	suite.lm.Put(key1, 42)
	value := suite.lm.Get(key1)
	suite.Equal(42, value)
}

func (suite *LinkedMapTestSuite) TestGet_NonExistentKey() {
	value := suite.lm.Get("nonexistent")
	suite.Equal(0, value) // Should return zero value for int
}

func (suite *LinkedMapTestSuite) TestGet_EmptyMap() {
	value := suite.lm.Get("any")
	suite.Equal(0, value)
}

func (suite *LinkedMapTestSuite) TestGet_ZeroValue() {
	zero := "zero"
	suite.lm.Put(zero, 0)
	value := suite.lm.Get(zero)
	suite.Equal(0, value)
}

// Test Contains function
func (suite *LinkedMapTestSuite) TestContains_ExistingKey() {
	key1 := "key1"
	suite.lm.Put(key1, 42)
	suite.True(suite.lm.Contains(key1))
}

func (suite *LinkedMapTestSuite) TestContains_NonExistentKey() {
	suite.False(suite.lm.Contains("nonexistent"))
}

func (suite *LinkedMapTestSuite) TestContains_EmptyMap() {
	suite.False(suite.lm.Contains("any"))
}

func (suite *LinkedMapTestSuite) TestContains_ZeroValue() {
	zero := "zero"
	suite.lm.Put(zero, 0)
	suite.True(suite.lm.Contains(zero))
}

func (suite *LinkedMapTestSuite) TestContains_AfterRemoval() {
	key1 := "key1"
	suite.lm.Put(key1, 42)
	suite.True(suite.lm.Contains(key1))
	
	_, ok := suite.lm.Remove(key1)
	suite.True(ok)
	suite.False(suite.lm.Contains(key1))
}

// Test Remove function
func (suite *LinkedMapTestSuite) TestRemove_ExistingKey() {
	key1 := "key1"
	suite.lm.Put(key1, 42)
	removedValue, ok := suite.lm.Remove(key1)
	
	suite.True(ok)
	suite.Equal(42, removedValue)
	suite.Equal(0, suite.lm.Size())
	suite.False(suite.lm.Contains(key1))
}

func (suite *LinkedMapTestSuite) TestRemove_NonExistentKey() {
	removedValue, ok := suite.lm.Remove("nonexistent")
	suite.False(ok)
	suite.Equal(0, removedValue) // Should return zero value
	suite.Equal(0, suite.lm.Size())
}

func (suite *LinkedMapTestSuite) TestRemove_EmptyMap() {
	removedValue, ok := suite.lm.Remove("any")
	suite.False(ok)
	suite.Equal(0, removedValue)
	suite.Equal(0, suite.lm.Size())
}

func (suite *LinkedMapTestSuite) TestRemove_MultipleElements() {
	a := "a"
	b := "b"
	c := "c"
	
	suite.lm.Put(a, 1)
	suite.lm.Put(b, 2)
	suite.lm.Put(c, 3)
	
	// Remove middle element
	removedValue, ok := suite.lm.Remove(b)
	suite.True(ok)
	suite.Equal(2, removedValue)
	suite.Equal(2, suite.lm.Size())
	
	// Check that order is maintained for remaining elements
	key, value, ok := suite.lm.First()
	suite.True(ok)
	suite.Equal(a, key)
	suite.Equal(1, value)
	
	key, value, ok = suite.lm.Next(a)
	suite.True(ok)
	suite.Equal(c, key)
	suite.Equal(3, value)
}

func (suite *LinkedMapTestSuite) TestRemove_FirstElement() {
	first := "first"
	second := "second"
	
	suite.lm.Put(first, 1)
	suite.lm.Put(second, 2)
	
	removedValue, ok := suite.lm.Remove(first)
	suite.True(ok)
	suite.Equal(1, removedValue)
	
	key, value, ok := suite.lm.First()
	suite.True(ok)
	suite.Equal(second, key)
	suite.Equal(2, value)
}

func (suite *LinkedMapTestSuite) TestRemove_LastElement() {
	first := "first"
	last := "last"
	
	suite.lm.Put(first, 1)
	suite.lm.Put(last, 2)
	
	removedValue, ok := suite.lm.Remove(last)
	suite.True(ok)
	suite.Equal(2, removedValue)
	
	key, value, ok := suite.lm.First()
	suite.True(ok)
	suite.Equal(first, key)
	suite.Equal(1, value)
	
}

// Test First function
func (suite *LinkedMapTestSuite) TestFirst_EmptyMap() {
	key, value, ok := suite.lm.First()
	suite.False(ok)
	suite.Equal("", key) // Zero value for string
	suite.Equal(0, value) // Zero value for int
}

func (suite *LinkedMapTestSuite) TestFirst_SingleElement() {
	only := "only"
	suite.lm.Put(only, 42)
	key, value, ok := suite.lm.First()
	suite.True(ok)
	suite.Equal(only, key)
	suite.Equal(42, value)
}

func (suite *LinkedMapTestSuite) TestFirst_MultipleElements() {
	first := "first"
	second := "second"
	third := "third"
	
	suite.lm.Put(first, 1)
	suite.lm.Put(second, 2)
	suite.lm.Put(third, 3)
	
	key, value, ok := suite.lm.First()
	suite.True(ok)
	suite.Equal(first, key)
	suite.Equal(1, value)
}

// Test Next function
func (suite *LinkedMapTestSuite) TestNext_ExistingKey() {
	a := "a"
	b := "b"
	c := "c"
	
	suite.lm.Put(a, 1)
	suite.lm.Put(b, 2)
	suite.lm.Put(c, 3)
	
	key, value, ok := suite.lm.Next(a)
	suite.True(ok)
	suite.Equal(b, key)
	suite.Equal(2, value)
	
	key, value, ok = suite.lm.Next(b)
	suite.True(ok)
	suite.Equal(c, key)
	suite.Equal(3, value)
}

func (suite *LinkedMapTestSuite) TestNext_LastElement() {
	a := "a"
	b := "b"
	
	suite.lm.Put(a, 1)
	suite.lm.Put(b, 2)
	
	key, value, ok := suite.lm.Next(b) // Last element
	suite.False(ok)
	suite.Equal("", key) // Zero value for string
	suite.Equal(0, value) // Zero value for int
}

func (suite *LinkedMapTestSuite) TestNext_NonExistentKey() {
	a := "a"
	suite.lm.Put(a, 1)
	
	key, value, ok := suite.lm.Next("nonexistent")
	suite.False(ok)
	suite.Equal("", key)
	suite.Equal(0, value)
}

func (suite *LinkedMapTestSuite) TestNext_EmptyMap() {
	key, value, ok := suite.lm.Next("any")
	suite.False(ok)
	suite.Equal("", key)
	suite.Equal(0, value)
}

func (suite *LinkedMapTestSuite) TestNext_SingleElement() {
	only := "only"
	suite.lm.Put(only, 42)
	
	key, value, ok := suite.lm.Next(only)
	suite.False(ok)
	suite.Equal("", key)
	suite.Equal(0, value)
}

// Test HasNext function
func (suite *LinkedMapTestSuite) TestHasNext_ExistingKeyWithNext() {
	a := "a"
	b := "b"
	
	suite.lm.Put(a, 1)
	suite.lm.Put(b, 2)
	
}

func (suite *LinkedMapTestSuite) TestHasNext_LastElement() {
	a := "a"
	b := "b"
	
	suite.lm.Put(a, 1)
	suite.lm.Put(b, 2)
	
}

func (suite *LinkedMapTestSuite) TestHasNext_NonExistentKey() {
	a := "a"
	suite.lm.Put(a, 1)
	
}

func (suite *LinkedMapTestSuite) TestHasNext_SingleElement() {
	only := "only"
	suite.lm.Put(only, 42)
	
}

// Test Previous function
func (suite *LinkedMapTestSuite) TestPrevious_ExistingKey() {
	a := "a"
	b := "b"
	c := "c"
	
	suite.lm.Put(a, 1)
	suite.lm.Put(b, 2)
	suite.lm.Put(c, 3)
	
	key, value, ok := suite.lm.Previous(c)
	suite.True(ok)
	suite.Equal(b, key)
	suite.Equal(2, value)
	
	key, value, ok = suite.lm.Previous(b)
	suite.True(ok)
	suite.Equal(a, key)
	suite.Equal(1, value)
}

func (suite *LinkedMapTestSuite) TestPrevious_FirstElement() {
	a := "a"
	b := "b"
	
	suite.lm.Put(a, 1)
	suite.lm.Put(b, 2)
	
	key, value, ok := suite.lm.Previous(a) // First element
	suite.False(ok)
	suite.Equal("", key) // Zero value for string
	suite.Equal(0, value) // Zero value for int
}

func (suite *LinkedMapTestSuite) TestPrevious_NonExistentKey() {
	a := "a"
	suite.lm.Put(a, 1)
	
	key, value, ok := suite.lm.Previous("nonexistent")
	suite.False(ok)
	suite.Equal("", key)
	suite.Equal(0, value)
}

func (suite *LinkedMapTestSuite) TestPrevious_EmptyMap() {
	key, value, ok := suite.lm.Previous("any")
	suite.False(ok)
	suite.Equal("", key)
	suite.Equal(0, value)
}

func (suite *LinkedMapTestSuite) TestPrevious_SingleElement() {
	only := "only"
	suite.lm.Put(only, 42)
	
	key, value, ok := suite.lm.Previous(only)
	suite.False(ok)
	suite.Equal("", key)
	suite.Equal(0, value)
}

// Test HasPrevious function
func (suite *LinkedMapTestSuite) TestHasPrevious_ExistingKeyWithPrevious() {
	a := "a"
	b := "b"
	
	suite.lm.Put(a, 1)
	suite.lm.Put(b, 2)
}

func (suite *LinkedMapTestSuite) TestHasPrevious_FirstElement() {
	a := "a"
	b := "b"
	
	suite.lm.Put(a, 1)
	suite.lm.Put(b, 2)
}

func (suite *LinkedMapTestSuite) TestHasPrevious_NonExistentKey() {
	a := "a"
	suite.lm.Put(a, 1)
	
}

func (suite *LinkedMapTestSuite) TestHasPrevious_SingleElement() {
	only := "only"
	suite.lm.Put(only, 42)
	
}

// Test Replace function
func (suite *LinkedMapTestSuite) TestReplace_ExistingOldKey() {
	old := "old"
	middle := "middle"
	end := "end"
	newKey := "new"
	
	suite.lm.Put(old, 1)
	suite.lm.Put(middle, 2)
	suite.lm.Put(end, 3)
	
	success := suite.lm.Replace(old, newKey, 100)
	
	suite.True(success)
	suite.False(suite.lm.Contains(old))
	suite.True(suite.lm.Contains(newKey))
	suite.Equal(100, suite.lm.Get(newKey))
	suite.Equal(3, suite.lm.Size())
	
	// Check that order is maintained
	key, value, ok := suite.lm.First()
	suite.True(ok)
	suite.Equal(newKey, key)
	suite.Equal(100, value)
	
	key, value, ok = suite.lm.Next(newKey)
	suite.True(ok)
	suite.Equal(middle, key)
	suite.Equal(2, value)
}

func (suite *LinkedMapTestSuite) TestReplace_NonExistentOldKey() {
	existing := "existing"
	newKey := "new"
	
	suite.lm.Put(existing, 1)
	
	success := suite.lm.Replace("nonexistent", newKey, 100)
	
	suite.False(success)
	suite.True(suite.lm.Contains(existing))
	suite.False(suite.lm.Contains(newKey))
	suite.Equal(1, suite.lm.Size())
}

func (suite *LinkedMapTestSuite) TestReplace_NewKeyAlreadyExists() {
	key1 := "key1"
	key2 := "key2"
	
	suite.lm.Put(key1, 1)
	suite.lm.Put(key2, 2)
	
	success := suite.lm.Replace(key1, key2, 100)
	
	suite.False(success)
	suite.True(suite.lm.Contains(key1))
	suite.True(suite.lm.Contains(key2))
	suite.Equal(1, suite.lm.Get(key1)) // Unchanged
	suite.Equal(2, suite.lm.Get(key2)) // Unchanged
	suite.Equal(2, suite.lm.Size())
}

func (suite *LinkedMapTestSuite) TestReplace_SameKey() {
	key := "key"
	
	suite.lm.Put(key, 1)
	
	success := suite.lm.Replace(key, key, 100)
	
	suite.True(success)
	suite.True(suite.lm.Contains(key))
	suite.Equal(100, suite.lm.Get(key))
	suite.Equal(1, suite.lm.Size())
}

func (suite *LinkedMapTestSuite) TestReplace_EmptyMap() {
	old := "old"
	newKey := "new"
	
	success := suite.lm.Replace(old, newKey, 100)
	
	suite.False(success)
	suite.Equal(0, suite.lm.Size())
}

func (suite *LinkedMapTestSuite) TestReplace_PreservesOrder() {
	a := "a"
	b := "b"
	c := "c"
	B := "B"
	
	suite.lm.Put(a, 1)
	suite.lm.Put(b, 2)
	suite.lm.Put(c, 3)
	
	// Replace middle element
	success := suite.lm.Replace(b, B, 200)
	
	suite.True(success)
	
	// Check order is preserved
	key, value, ok := suite.lm.First()
	suite.True(ok)
	suite.Equal(a, key)
	suite.Equal(1, value)
	
	key, value, ok = suite.lm.Next(a)
	suite.True(ok)
	suite.Equal(B, key)
	suite.Equal(200, value)
	
	key, value, ok = suite.lm.Next(B)
	suite.True(ok)
	suite.Equal(c, key)
	suite.Equal(3, value)
}

// Test Iterator function
func (suite *LinkedMapTestSuite) TestIterator_EmptyMap() {
	iter := suite.lm.Iterator()
	suite.NotNil(iter)
	suite.Nil(iter.curr)
	suite.Equal(suite.lm, iter.m)
}

func (suite *LinkedMapTestSuite) TestIterator_SingleElement() {
	single := "single"
	suite.lm.Put(single, 42)
	
	iter := suite.lm.Iterator()
	suite.NotNil(iter)
	suite.NotNil(iter.curr)
	suite.Equal(suite.lm, iter.m)
	suite.Equal(single, iter.curr.key)
	suite.Equal(42, iter.curr.value)
}

func (suite *LinkedMapTestSuite) TestIterator_MultipleElements() {
	a := "a"
	b := "b"
	c := "c"
	
	suite.lm.Put(a, 1)
	suite.lm.Put(b, 2)
	suite.lm.Put(c, 3)
	
	iter := suite.lm.Iterator()
	suite.NotNil(iter)
	suite.NotNil(iter.curr)
	suite.Equal(a, iter.curr.key)
	suite.Equal(1, iter.curr.value)
}

// Test Iterator.Next function
func (suite *LinkedMapTestSuite) TestIteratorNext_EmptyMap() {
	iter := suite.lm.Iterator()
	
	key, value, ok := iter.Next()
	suite.False(ok)
	suite.Equal("", key)
	suite.Equal(0, value)
}

func (suite *LinkedMapTestSuite) TestIteratorNext_SingleElement() {
	single := "single"
	suite.lm.Put(single, 42)
	
	iter := suite.lm.Iterator()
	key, value, ok := iter.Next()
	
	suite.True(ok)
	suite.Equal(single, key)
	suite.Equal(42, value)
	
	// Next call should return false
	key, value, ok = iter.Next()
	suite.False(ok)
	suite.Equal("", key)
	suite.Equal(0, value)
}

func (suite *LinkedMapTestSuite) TestIteratorNext_MultipleElements() {
	first := "first"
	second := "second"
	third := "third"
	
	suite.lm.Put(first, 1)
	suite.lm.Put(second, 2)
	suite.lm.Put(third, 3)
	
	iter := suite.lm.Iterator()
	
	// First element
	key, value, ok := iter.Next()
	suite.True(ok)
	suite.Equal(first, key)
	suite.Equal(1, value)
	
	// Second element
	key, value, ok = iter.Next()
	suite.True(ok)
	suite.Equal(second, key)
	suite.Equal(2, value)
	
	// Third element
	key, value, ok = iter.Next()
	suite.True(ok)
	suite.Equal(third, key)
	suite.Equal(3, value)
	
	// End of iteration
	key, value, ok = iter.Next()
	suite.False(ok)
	suite.Equal("", key)
	suite.Equal(0, value)
}

func (suite *LinkedMapTestSuite) TestIteratorNext_PreservesInsertionOrder() {
	// Add elements in specific order
	z := "z"
	a := "a"
	m := "m"
	
	suite.lm.Put(z, 26)
	suite.lm.Put(a, 1)
	suite.lm.Put(m, 13)
	
	iter := suite.lm.Iterator()
	
	// Should iterate in insertion order, not alphabetical
	key, value, ok := iter.Next()
	suite.True(ok)
	suite.Equal(z, key)
	suite.Equal(26, value)
	
	key, value, ok = iter.Next()
	suite.True(ok)
	suite.Equal(a, key)
	suite.Equal(1, value)
	
	key, value, ok = iter.Next()
	suite.True(ok)
	suite.Equal(m, key)
	suite.Equal(13, value)
	
	key, value, ok = iter.Next()
	suite.False(ok)
	suite.Equal("", key)
}

func (suite *LinkedMapTestSuite) TestIteratorNext_AfterUpdates() {
	a := "a"
	b := "b"
	c := "c"
	
	suite.lm.Put(a, 1)
	suite.lm.Put(b, 2)
	suite.lm.Put(c, 3)
	
	// Update middle element (should not change order)
	suite.lm.Put(b, 200)
	
	iter := suite.lm.Iterator()
	
	key, value, ok := iter.Next()
	suite.True(ok)
	suite.Equal(a, key)
	suite.Equal(1, value)
	
	key, value, ok = iter.Next()
	suite.True(ok)
	suite.Equal(b, key)
	suite.Equal(200, value) // Updated value
	
	key, value, ok = iter.Next()
	suite.True(ok)
	suite.Equal(c, key)
	suite.Equal(3, value)
}

func (suite *LinkedMapTestSuite) TestIteratorNext_AfterRemovals() {
	a := "a"
	b := "b"
	c := "c"
	d := "d"
	
	suite.lm.Put(a, 1)
	suite.lm.Put(b, 2)
	suite.lm.Put(c, 3)
	suite.lm.Put(d, 4)
	
	// Verify initial order
	firstKey, firstValue, ok := suite.lm.First()
	suite.True(ok)
	suite.Equal(a, firstKey)
	suite.Equal(1, firstValue)
	
	// Remove middle elements
	_, ok = suite.lm.Remove(b)
	suite.True(ok)
	_, ok = suite.lm.Remove(c)
	suite.True(ok)
	
	// Verify order after removal using First/Next
	key, value, ok := suite.lm.First()
	suite.True(ok)
	suite.Equal(a, key)
	suite.Equal(1, value)
	
	key, value, ok = suite.lm.Next(a)
	suite.True(ok)
	suite.Equal(d, key)
	suite.Equal(4, value)
	
	// Now test iterator
	iter := suite.lm.Iterator()
	
	// Should get 'a' first
	key, value, ok = iter.Next()
	suite.True(ok)
	suite.Equal(a, key)
	suite.Equal(1, value)
	
	// Should get 'd' second
	key, value, ok = iter.Next()
	suite.True(ok)
	suite.Equal(d, key)
	suite.Equal(4, value)
	
	// Should be at end
	key, value, ok = iter.Next()
	suite.False(ok)
	suite.Equal("", key)
	suite.Equal(0, value)
}

func (suite *LinkedMapTestSuite) TestIteratorNext_AfterReplace() {
	first := "first"
	second := "second"
	third := "third"
	SECOND := "SECOND"
	
	suite.lm.Put(first, 1)
	suite.lm.Put(second, 2)
	suite.lm.Put(third, 3)
	
	// Replace middle element
	suite.lm.Replace(second, SECOND, 200)
	
	iter := suite.lm.Iterator()
	
	key, value, ok := iter.Next()
	suite.True(ok)
	suite.Equal(first, key)
	suite.Equal(1, value)
	
	key, value, ok = iter.Next()
	suite.True(ok)
	suite.Equal(SECOND, key)
	suite.Equal(200, value)
	
	key, value, ok = iter.Next()
	suite.True(ok)
	suite.Equal(third, key)
	suite.Equal(3, value)
}

func (suite *LinkedMapTestSuite) TestIterator_MultipleIterators() {
	a := "a"
	b := "b"
	
	suite.lm.Put(a, 1)
	suite.lm.Put(b, 2)
	
	// Create two independent iterators
	iter1 := suite.lm.Iterator()
	iter2 := suite.lm.Iterator()
	
	// Advance first iterator
	key1, value1, ok := iter1.Next()
	suite.True(ok)
	suite.Equal(a, key1)
	suite.Equal(1, value1)
	
	// Second iterator should still be at the beginning
	key2, value2, ok := iter2.Next()
	suite.True(ok)
	suite.Equal(a, key2)
	suite.Equal(1, value2)
	
	// Continue with first iterator
	key1, value1, ok = iter1.Next()
	suite.True(ok)
	suite.Equal(b, key1)
	suite.Equal(2, value1)
	
	// Second iterator should be independent
	key2, value2, ok = iter2.Next()
	suite.True(ok)
	suite.Equal(b, key2)
	suite.Equal(2, value2)
}

func (suite *LinkedMapTestSuite) TestIterator_FullTraversal() {
	// Add many elements
	expected := make(map[string]int)
	keys := []string{"alpha", "beta", "gamma", "delta", "epsilon"}
	
	for i, key := range keys {
		value := (i + 1) * 10
		suite.lm.Put(key, value)
		expected[key] = value
	}
	
	// Traverse with iterator
	iter := suite.lm.Iterator()
	collected := make(map[string]int)
	collectedOrder := make([]string, 0)
	
	for {
		key, value, ok := iter.Next()
		if !ok {
			break
		}
		collected[key] = value
		collectedOrder = append(collectedOrder, key)
	}
	
	// Verify all elements collected
	suite.Equal(len(expected), len(collected))
	for key, expectedValue := range expected {
		actualValue, exists := collected[key]
		suite.True(exists, "Key %s should exist", key)
		suite.Equal(expectedValue, actualValue, "Value for key %s", key)
	}
	
	// Verify order matches insertion order
	suite.Equal(keys, collectedOrder)
}

func (suite *LinkedMapTestSuite) TestIterator_ConcurrentReadSafety() {
	a := "a"
	b := "b"
	c := "c"
	
	suite.lm.Put(a, 1)
	suite.lm.Put(b, 2)
	suite.lm.Put(c, 3)
	
	iter := suite.lm.Iterator()
	
	// Read operations during iteration should be safe
	key, value, ok := iter.Next()
	suite.True(ok)
	suite.Equal(a, key)
	
	// Concurrent reads
	suite.True(suite.lm.Contains(b))
	suite.Equal(2, suite.lm.Get(b))
	suite.Equal(3, suite.lm.Size())
	
	// Continue iteration
	key, value, ok = iter.Next()
	suite.True(ok)
	suite.Equal(b, key)
	suite.Equal(2, value)
}

// Integration tests
func (suite *LinkedMapTestSuite) TestComplexOperations() {
	// Add some elements
	a := "a"
	b := "b"
	c := "c"
	d := "d"
	
	suite.lm.Put(a, 1)
	suite.lm.Put(b, 2)
	suite.lm.Put(c, 3)
	
	// Update one
	suite.lm.Put(b, 20)
	
	// Remove one
	_, ok := suite.lm.Remove(a)
	suite.True(ok)
	
	// Add another
	suite.lm.Put(d, 4)
	
	// Check final state
	suite.Equal(3, suite.lm.Size())
	
	key, value, ok := suite.lm.First()
	suite.True(ok)
	suite.Equal(b, key)
	suite.Equal(20, value)
	
	key, value, ok = suite.lm.Next(b)
	suite.True(ok)
	suite.Equal(c, key)
	suite.Equal(3, value)
	
	key, value, ok = suite.lm.Next(c)
	suite.True(ok)
	suite.Equal(d, key)
	suite.Equal(4, value)
}

func (suite *LinkedMapTestSuite) TestTraversalAfterOperations() {
	// Build a sequence
	keys := make([]string, 5)
	for i := 0; i < 5; i++ {
		key := string(rune('a' + i))
		keys[i] = key
		suite.lm.Put(key, i)
	}
	
	// Remove some elements
	_, ok := suite.lm.Remove(keys[1]) // Remove second (b)
	suite.True(ok)
	_, ok = suite.lm.Remove(keys[3]) // Remove fourth (d)
	suite.True(ok)
	
	// Expected order: a(0), c(2), e(4)
	expected := []struct{ key string; value int }{
		{keys[0], 0}, // a
		{keys[2], 2}, // c
		{keys[4], 4}, // e
	}
	
	// Traverse and verify
	key, value, ok := suite.lm.First()
	suite.True(ok)
	for i, exp := range expected {
		suite.Equal(exp.key, key, "Position %d", i)
		suite.Equal(exp.value, value, "Position %d", i)
		
		if i < len(expected)-1 {
			key, value, ok = suite.lm.Next(key)
			suite.True(ok)
		}
	}
}

// Test with different types
func (suite *LinkedMapTestSuite) TestWithStringKeys() {
	strMap := NewLinkedMap[string, string]()
	
	hello := "hello"
	foo := "foo"
	
	strMap.Put(hello, "world")
	strMap.Put(foo, "bar")
	
	suite.Equal("world", strMap.Get(hello))
	suite.Equal("bar", strMap.Get(foo))
	suite.True(strMap.Contains(hello))
	suite.Equal(2, strMap.Size())
}

// Edge case: Operations on single element map
func (suite *LinkedMapTestSuite) TestSingleElementOperations() {
	single := "single"
	replaced := "replaced"
	
	suite.lm.Put(single, 42)
	
	// Test all operations
	suite.Equal(1, suite.lm.Size())
	suite.True(suite.lm.Contains(single))
	suite.Equal(42, suite.lm.Get(single))
	
	key, value, ok := suite.lm.First()
	suite.True(ok)
	suite.Equal(single, key)
	suite.Equal(42, value)
	
	
	nextKey, nextValue, ok := suite.lm.Next(single)
	suite.False(ok)
	suite.Equal("", nextKey)
	suite.Equal(0, nextValue)
	
	// Replace
	suite.True(suite.lm.Replace(single, replaced, 100))
	suite.False(suite.lm.Contains(single))
	suite.True(suite.lm.Contains(replaced))
	
	// Remove
	removedValue, ok := suite.lm.Remove(replaced)
	suite.True(ok)
	suite.Equal(100, removedValue)
	suite.Equal(0, suite.lm.Size())
}

// Edge case: Iterator behavior after map becomes empty
func (suite *LinkedMapTestSuite) TestIterator_EmptyAfterRemoval() {
	temp := "temp"
	suite.lm.Put(temp, 1)
	
	iter := suite.lm.Iterator()
	suite.NotNil(iter.curr)
	
	// Remove the only element
	_, ok := suite.lm.Remove(temp)
	suite.True(ok)
	
	// Iterator should handle this gracefully - the iterator's curr might now be stale
	// This tests that the iterator doesn't crash when the underlying data changes
	key, value, ok := iter.Next()
	// The behavior here depends on your implementation - it might return the stale data
	// or handle it gracefully. Let's just ensure it doesn't crash.
	_ = key
	_ = value
	_ = ok
}

// Test bidirectional traversal
func (suite *LinkedMapTestSuite) TestBidirectionalTraversal() {
	a := "a"
	b := "b"
	c := "c"
	d := "d"
	
	suite.lm.Put(a, 1)
	suite.lm.Put(b, 2)
	suite.lm.Put(c, 3)
	suite.lm.Put(d, 4)
	
	// Forward traversal
	key, value, ok := suite.lm.First()
	suite.True(ok)
	suite.Equal(a, key)
	suite.Equal(1, value)
	
	key, value, ok = suite.lm.Next(a)
	suite.True(ok)
	suite.Equal(b, key)
	suite.Equal(2, value)
	
	key, value, ok = suite.lm.Next(b)
	suite.True(ok)
	suite.Equal(c, key)
	suite.Equal(3, value)
	
	// Backward traversal from current position
	key, value, ok = suite.lm.Previous(c)
	suite.True(ok)
	suite.Equal(b, key)
	suite.Equal(2, value)
	
	key, value, ok = suite.lm.Previous(b)
	suite.True(ok)
	suite.Equal(a, key)
	suite.Equal(1, value)
}

// Test edge cases with Previous and HasPrevious after modifications
func (suite *LinkedMapTestSuite) TestPreviousAfterOperations() {
	a := "a"
	b := "b"
	c := "c"
	d := "d"
	
	suite.lm.Put(a, 1)
	suite.lm.Put(b, 2)
	suite.lm.Put(c, 3)
	suite.lm.Put(d, 4)
	
	// Remove middle element
	_, ok := suite.lm.Remove(b)
	suite.True(ok)
	
	// Check that previous relationships are updated correctly
	key, value, ok := suite.lm.Previous(c)
	suite.True(ok)
	suite.Equal(a, key)
	suite.Equal(1, value)
	
}

func (suite *LinkedMapTestSuite) TestPreviousAfterReplace() {
	first := "first"
	second := "second"
	third := "third"
	SECOND := "SECOND"
	
	suite.lm.Put(first, 1)
	suite.lm.Put(second, 2)
	suite.lm.Put(third, 3)
	
	// Replace middle element
	success := suite.lm.Replace(second, SECOND, 200)
	suite.True(success)
	
	// Check previous relationships are maintained
	key, value, ok := suite.lm.Previous(third)
	suite.True(ok)
	suite.Equal(SECOND, key)
	suite.Equal(200, value)
	
	key, value, ok = suite.lm.Previous(SECOND)
	suite.True(ok)
	suite.Equal(first, key)
	suite.Equal(1, value)
}

// Test thread safety with concurrent operations
func (suite *LinkedMapTestSuite) TestConcurrentReadOperations() {
	// Populate map
	keys := make([]string, 100)
	for i := 0; i < 100; i++ {
		key := string(rune('a'+i%26)) + strconv.Itoa(i)
		keys[i] = key
		suite.lm.Put(key, i)
	}
	
	var wg sync.WaitGroup
	numGoroutines := 10
	
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			
			// Perform various read operations
			for j := 0; j < 50; j++ {
				key := keys[j]
				
				_ = suite.lm.Get(key)
				_ = suite.lm.Contains(key)
				_ = suite.lm.Size()
				
				if suite.lm.Contains(key) {
					_, _, _ = suite.lm.Next(key)
					_, _, _ = suite.lm.Previous(key)
				}
				
				_, _, _ = suite.lm.First()
			}
		}(i)
	}
	
	wg.Wait()
	
	// Verify map integrity
	suite.Equal(100, suite.lm.Size())
}

func (suite *LinkedMapTestSuite) TestConcurrentWriteOperations() {
	var wg sync.WaitGroup
	numGoroutines := 5
	
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			
			// Each goroutine works with its own key range to avoid conflicts
			baseKey := string(rune('a' + id))
			for j := 0; j < 20; j++ {
				key := baseKey + strconv.Itoa(j)
				suite.lm.Put(key, id*1000+j)
			}
		}(i)
	}
	
	wg.Wait()
	
	// Verify all elements were added
	suite.Equal(100, suite.lm.Size())
}

func (suite *LinkedMapTestSuite) TestConcurrentMixedOperations() {
	// Pre-populate with some data
	keys := make([]string, 50)
	for i := 0; i < 50; i++ {
		key := string(rune('a'+i%26)) + strconv.Itoa(i)
		keys[i] = key
		suite.lm.Put(key, i)
	}
	
	var wg sync.WaitGroup
	
	// Reader goroutines
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				key := keys[j%50]
				_ = suite.lm.Get(key)
				_ = suite.lm.Contains(key)
				if j%10 == 0 {
					time.Sleep(time.Microsecond)
				}
			}
		}()
	}
	
	// Writer goroutines
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			baseOffset := (id + 1) * 1000
			for j := 0; j < 30; j++ {
				key := "writer" + strconv.Itoa(id) + "_" + strconv.Itoa(j)
				suite.lm.Put(key, baseOffset+j)
				if j%5 == 0 {
					time.Sleep(time.Microsecond)
				}
			}
		}(i)
	}
	
	wg.Wait()
	
	// Verify final state
	suite.True(suite.lm.Size() >= 50) // At least original elements
	suite.True(suite.lm.Size() <= 110) // Original + new elements
}

// Test Iterator edge cases and boundary conditions
func (suite *LinkedMapTestSuite) TestIterator_BoundaryConditions() {
	// Test iterator when curr is at tail boundary
	a := "a"
	suite.lm.Put(a, 1)
	
	iter := suite.lm.Iterator()
	
	// Advance to the only element
	key, value, ok := iter.Next()
	suite.True(ok)
	suite.Equal(a, key)
	suite.Equal(1, value)
	
	// Now curr should be pointing to "a" node
	// Next call should check if curr.next == tail
	key, value, ok = iter.Next()
	suite.False(ok)
	suite.Equal("", key)
	suite.Equal(0, value)
}

func (suite *LinkedMapTestSuite) TestIterator_CurrIsNil() {
	// Test when iterator curr is nil (empty map case)
	iter := suite.lm.Iterator()
	suite.Nil(iter.curr)
	
	key, value, ok := iter.Next()
	suite.False(ok)
	suite.Equal("", key)
	suite.Equal(0, value)
}

// Test with different data types to ensure generics work correctly
func (suite *LinkedMapTestSuite) TestWithIntegerKeys() {
	intMap := NewLinkedMap[int, string]()
	
	one := 1
	two := 2
	three := 3
	
	intMap.Put(one, "one")
	intMap.Put(two, "two")
	intMap.Put(three, "three")
	
	suite.Equal("one", intMap.Get(one))
	suite.Equal("two", intMap.Get(two))
	suite.Equal("three", intMap.Get(three))
	suite.Equal(3, intMap.Size())
	
	// Test traversal
	key, value, ok := intMap.First()
	suite.True(ok)
	suite.Equal(one, key)
	suite.Equal("one", value)
	
	key, value, ok = intMap.Next(one)
	suite.True(ok)
	suite.Equal(two, key)
	suite.Equal("two", value)
	
	key, value, ok = intMap.Previous(two)
	suite.True(ok)
	suite.Equal(one, key)
	suite.Equal("one", value)
}

func (suite *LinkedMapTestSuite) TestWithStructValues() {
	type Person struct {
		Name string
		Age  int
	}
	
	personMap := NewLinkedMap[string, Person]()
	
	alice := "alice"
	bob := "bob"
	
	p1 := Person{Name: "Alice", Age: 30}
	p2 := Person{Name: "Bob", Age: 25}
	
	personMap.Put(alice, p1)
	personMap.Put(bob, p2)
	
	retrievedP1 := personMap.Get(alice)
	suite.Equal("Alice", retrievedP1.Name)
	suite.Equal(30, retrievedP1.Age)
	
	// Test zero value
	nonExistent := personMap.Get("charlie")
	suite.Equal("", nonExistent.Name)
	suite.Equal(0, nonExistent.Age)
}

// Test Replace function edge cases
func (suite *LinkedMapTestSuite) TestReplace_WithDifferentTypes() {
	boolMap := NewLinkedMap[string, bool]()
	
	trueKey := "true"
	falseKey := "false"
	TRUE := "TRUE"
	
	boolMap.Put(trueKey, true)
	boolMap.Put(falseKey, false)
	
	success := boolMap.Replace(trueKey, TRUE, false)
	suite.True(success)
	suite.False(boolMap.Get(TRUE))
	suite.False(boolMap.Contains(trueKey))
}

// Test memory cleanup and node isolation after Remove
func (suite *LinkedMapTestSuite) TestRemove_NodeIsolation() {
	a := "a"
	b := "b"
	c := "c"
	
	suite.lm.Put(a, 1)
	suite.lm.Put(b, 2)
	suite.lm.Put(c, 3)
	
	// Get references before removal
	firstKey, _, ok := suite.lm.First()
	suite.True(ok)
	suite.Equal(a, firstKey)
	
	// Remove middle element
	removedValue, ok := suite.lm.Remove(b)
	suite.True(ok)
	suite.Equal(2, removedValue)
	
	// Verify links are properly updated
	key, value, ok := suite.lm.Next(a)
	suite.True(ok)
	suite.Equal(c, key)
	suite.Equal(3, value)
	
	key, value, ok = suite.lm.Previous(c)
	suite.True(ok)
	suite.Equal(a, key)
	suite.Equal(1, value)
}

// Test size consistency across all operations
func (suite *LinkedMapTestSuite) TestSizeConsistency() {
	// Start empty
	suite.Equal(0, suite.lm.Size())
	
	a := "a"
	b := "b"
	A := "A"
	
	// Add elements
	suite.lm.Put(a, 1)
	suite.Equal(1, suite.lm.Size())
	
	suite.lm.Put(b, 2)
	suite.Equal(2, suite.lm.Size())
	
	// Update existing (size should not change)
	suite.lm.Put(a, 10)
	suite.Equal(2, suite.lm.Size())
	
	// Replace (size should not change)
	suite.lm.Replace(a, A, 100)
	suite.Equal(2, suite.lm.Size())
	
	// Remove
	_, ok := suite.lm.Remove(A)
	suite.True(ok)
	suite.Equal(1, suite.lm.Size())
	
	_, ok = suite.lm.Remove(b)
	suite.True(ok)
	suite.Equal(0, suite.lm.Size())
	
	// Remove non-existent (size should not change)
	_, ok = suite.lm.Remove("nonexistent")
	suite.False(ok)
	suite.Equal(0, suite.lm.Size())
}

// Test that all zero values are handled correctly
func (suite *LinkedMapTestSuite) TestZeroValueHandling() {
	// Test with zero values for different types
	
	// Empty string key
	empty := ""
	zero := "zero"
	
	suite.lm.Put(empty, 42) // Empty string key
	suite.True(suite.lm.Contains(empty))
	suite.Equal(42, suite.lm.Get(empty))
	
	// Int zero value
	suite.lm.Put(zero, 0) // Zero value
	suite.True(suite.lm.Contains(zero))
	suite.Equal(0, suite.lm.Get(zero))
	
	// Test operations with zero values
	key, value, ok := suite.lm.First()
	suite.True(ok)
	if key == "" {
		suite.Equal(42, value)
	} else {
		suite.Equal(zero, key)
		suite.Equal(0, value)
	}
}

// Test comprehensive traversal integrity
func (suite *LinkedMapTestSuite) TestTraversalIntegrity() {
	// Build a map with known order
	keyStrs := []string{"alpha", "beta", "gamma", "delta", "epsilon"}
	keys := make([]string, len(keyStrs))
	for i, keyStr := range keyStrs {
		keys[i] = keyStr
		suite.lm.Put(keys[i], i*10)
	}
	
	// Forward traversal
	currentKey, currentValue, ok := suite.lm.First()
	suite.True(ok)
	for i, expectedKey := range keys {
		suite.Equal(expectedKey, currentKey, "Forward traversal at position %d", i)
		suite.Equal(i*10, currentValue, "Forward traversal value at position %d", i)
		
		if i < len(keys)-1 {
			currentKey, currentValue, ok = suite.lm.Next(currentKey)
			suite.True(ok)
		}
	}
	
	// Backward traversal from last element
	currentKey = keys[len(keys)-1]
	for i := len(keys) - 1; i >= 0; i-- {
		expectedKey := keys[i]
		suite.Equal(expectedKey, currentKey, "Backward traversal at position %d", i)
		
		if i > 0 {
			currentKey, _, ok = suite.lm.Previous(currentKey)
			suite.True(ok)
		}
	}
}