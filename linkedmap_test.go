package qotp

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLinkedMap_NewLinkedMap(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	assert.NotNil(t, lm)
	assert.NotNil(t, lm.items)
	assert.NotNil(t, lm.head)
	assert.NotNil(t, lm.tail)
	assert.Equal(t, 0, lm.size)
	assert.Equal(t, lm.tail, lm.head.next)
	assert.Equal(t, lm.head, lm.tail.prev)
}

func TestLinkedMap_Size_Empty(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	assert.Equal(t, 0, lm.Size())
}

func TestLinkedMap_Size_WithElements(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("a", 1)
	assert.Equal(t, 1, lm.Size())
	
	lm.Put("b", 2)
	assert.Equal(t, 2, lm.Size())
	
	lm.Put("c", 3)
	assert.Equal(t, 3, lm.Size())
}

func TestLinkedMap_Size_AfterRemoval(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("a", 1)
	lm.Put("b", 2)
	assert.Equal(t, 2, lm.Size())
	
	_, ok := lm.Remove("a")
	assert.True(t, ok)
	assert.Equal(t, 1, lm.Size())
	
	_, ok = lm.Remove("b")
	assert.True(t, ok)
	assert.Equal(t, 0, lm.Size())
}

func TestLinkedMap_Put_NewKey(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	key1 := "key1"
	lm.Put(key1, 100)
	assert.Equal(t, 1, lm.Size())
	assert.Equal(t, 100, lm.Get(key1))
}

func TestLinkedMap_Put_UpdateExistingKey(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	key1 := "key1"
	lm.Put(key1, 100)
	lm.Put(key1, 200) // Update existing key
	
	assert.Equal(t, 1, lm.Size()) // Size should remain the same
	assert.Equal(t, 200, lm.Get(key1))
}

func TestLinkedMap_Put_MultipleKeys(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	a := "a"
	b := "b"
	c := "c"
	
	lm.Put(a, 1)
	lm.Put(b, 2)
	lm.Put(c, 3)
	
	assert.Equal(t, 3, lm.Size())
	assert.Equal(t, 1, lm.Get(a))
	assert.Equal(t, 2, lm.Get(b))
	assert.Equal(t, 3, lm.Get(c))
}

func TestLinkedMap_Put_InsertionOrder(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	first := "first"
	second := "second"
	third := "third"
	
	lm.Put(first, 1)
	lm.Put(second, 2)
	lm.Put(third, 3)
	
	// Check insertion order using First and Next
	key, value, ok := lm.First()
	assert.True(t, ok)
	assert.Equal(t, first, key)
	assert.Equal(t, 1, value)
	
	key, value, ok = lm.Next(first)
	assert.True(t, ok)
	assert.Equal(t, second, key)
	assert.Equal(t, 2, value)
	
	key, value, ok = lm.Next(second)
	assert.True(t, ok)
	assert.Equal(t, third, key)
	assert.Equal(t, 3, value)
}

func TestLinkedMap_Put_UpdateDoesNotChangeOrder(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	first := "first"
	second := "second"
	third := "third"
	
	lm.Put(first, 1)
	lm.Put(second, 2)
	lm.Put(third, 3)
	
	// Update second element
	lm.Put(second, 200)
	
	// Order should remain the same
	key, value, ok := lm.First()
	assert.True(t, ok)
	assert.Equal(t, first, key)
	assert.Equal(t, 1, value)
	
	key, value, ok = lm.Next(first)
	assert.True(t, ok)
	assert.Equal(t, second, key)
	assert.Equal(t, 200, value) // Updated value
	
	key, value, ok = lm.Next(second)
	assert.True(t, ok)
	assert.Equal(t, third, key)
	assert.Equal(t, 3, value)
}

func TestLinkedMap_Get_ExistingKey(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	key1 := "key1"
	lm.Put(key1, 42)
	value := lm.Get(key1)
	assert.Equal(t, 42, value)
}

func TestLinkedMap_Get_NonExistentKey(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	value := lm.Get("nonexistent")
	assert.Equal(t, 0, value) // Should return zero value for int
}

func TestLinkedMap_Get_EmptyMap(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	value := lm.Get("any")
	assert.Equal(t, 0, value)
}

func TestLinkedMap_Get_ZeroValue(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	zero := "zero"
	lm.Put(zero, 0)
	value := lm.Get(zero)
	assert.Equal(t, 0, value)
}

func TestLinkedMap_Contains_ExistingKey(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	key1 := "key1"
	lm.Put(key1, 42)
	assert.True(t, lm.Contains(key1))
}

func TestLinkedMap_Contains_NonExistentKey(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	assert.False(t, lm.Contains("nonexistent"))
}

func TestLinkedMap_Contains_EmptyMap(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	assert.False(t, lm.Contains("any"))
}

func TestLinkedMap_Contains_ZeroValue(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	zero := "zero"
	lm.Put(zero, 0)
	assert.True(t, lm.Contains(zero))
}

func TestLinkedMap_Contains_AfterRemoval(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	key1 := "key1"
	lm.Put(key1, 42)
	assert.True(t, lm.Contains(key1))
	
	_, ok := lm.Remove(key1)
	assert.True(t, ok)
	assert.False(t, lm.Contains(key1))
}

func TestLinkedMap_Remove_ExistingKey(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	key1 := "key1"
	lm.Put(key1, 42)
	removedValue, ok := lm.Remove(key1)
	
	assert.True(t, ok)
	assert.Equal(t, 42, removedValue)
	assert.Equal(t, 0, lm.Size())
	assert.False(t, lm.Contains(key1))
}

func TestLinkedMap_Remove_NonExistentKey(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	removedValue, ok := lm.Remove("nonexistent")
	assert.False(t, ok)
	assert.Equal(t, 0, removedValue) // Should return zero value
	assert.Equal(t, 0, lm.Size())
}

func TestLinkedMap_Remove_EmptyMap(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	removedValue, ok := lm.Remove("any")
	assert.False(t, ok)
	assert.Equal(t, 0, removedValue)
	assert.Equal(t, 0, lm.Size())
}

func TestLinkedMap_Remove_MultipleElements(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	a := "a"
	b := "b"
	c := "c"
	
	lm.Put(a, 1)
	lm.Put(b, 2)
	lm.Put(c, 3)
	
	// Remove middle element
	removedValue, ok := lm.Remove(b)
	assert.True(t, ok)
	assert.Equal(t, 2, removedValue)
	assert.Equal(t, 2, lm.Size())
	
	// Check that order is maintained for remaining elements
	key, value, ok := lm.First()
	assert.True(t, ok)
	assert.Equal(t, a, key)
	assert.Equal(t, 1, value)
	
	key, value, ok = lm.Next(a)
	assert.True(t, ok)
	assert.Equal(t, c, key)
	assert.Equal(t, 3, value)
}

func TestLinkedMap_Remove_FirstElement(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	first := "first"
	second := "second"
	
	lm.Put(first, 1)
	lm.Put(second, 2)
	
	removedValue, ok := lm.Remove(first)
	assert.True(t, ok)
	assert.Equal(t, 1, removedValue)
	
	key, value, ok := lm.First()
	assert.True(t, ok)
	assert.Equal(t, second, key)
	assert.Equal(t, 2, value)
}

func TestLinkedMap_Remove_LastElement(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	first := "first"
	last := "last"
	
	lm.Put(first, 1)
	lm.Put(last, 2)
	
	removedValue, ok := lm.Remove(last)
	assert.True(t, ok)
	assert.Equal(t, 2, removedValue)
	
	key, value, ok := lm.First()
	assert.True(t, ok)
	assert.Equal(t, first, key)
	assert.Equal(t, 1, value)
}

func TestLinkedMap_First_EmptyMap(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	key, value, ok := lm.First()
	assert.False(t, ok)
	assert.Equal(t, "", key) // Zero value for string
	assert.Equal(t, 0, value) // Zero value for int
}

func TestLinkedMap_First_SingleElement(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	only := "only"
	lm.Put(only, 42)
	key, value, ok := lm.First()
	assert.True(t, ok)
	assert.Equal(t, only, key)
	assert.Equal(t, 42, value)
}

func TestLinkedMap_First_MultipleElements(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	first := "first"
	second := "second"
	third := "third"
	
	lm.Put(first, 1)
	lm.Put(second, 2)
	lm.Put(third, 3)
	
	key, value, ok := lm.First()
	assert.True(t, ok)
	assert.Equal(t, first, key)
	assert.Equal(t, 1, value)
}

func TestLinkedMap_Next_ExistingKey(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	a := "a"
	b := "b"
	c := "c"
	
	lm.Put(a, 1)
	lm.Put(b, 2)
	lm.Put(c, 3)
	
	key, value, ok := lm.Next(a)
	assert.True(t, ok)
	assert.Equal(t, b, key)
	assert.Equal(t, 2, value)
	
	key, value, ok = lm.Next(b)
	assert.True(t, ok)
	assert.Equal(t, c, key)
	assert.Equal(t, 3, value)
}

func TestLinkedMap_Next_LastElement(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	a := "a"
	b := "b"
	
	lm.Put(a, 1)
	lm.Put(b, 2)
	
	key, value, ok := lm.Next(b) // Last element
	assert.False(t, ok)
	assert.Equal(t, "", key) // Zero value for string
	assert.Equal(t, 0, value) // Zero value for int
}

func TestLinkedMap_Next_NonExistentKey(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	a := "a"
	lm.Put(a, 1)
	
	key, value, ok := lm.Next("nonexistent")
	assert.False(t, ok)
	assert.Equal(t, "", key)
	assert.Equal(t, 0, value)
}

func TestLinkedMap_Next_EmptyMap(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	key, value, ok := lm.Next("any")
	assert.False(t, ok)
	assert.Equal(t, "", key)
	assert.Equal(t, 0, value)
}

func TestLinkedMap_Next_SingleElement(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	only := "only"
	lm.Put(only, 42)
	
	key, value, ok := lm.Next(only)
	assert.False(t, ok)
	assert.Equal(t, "", key)
	assert.Equal(t, 0, value)
}

func TestLinkedMap_Previous_ExistingKey(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	a := "a"
	b := "b"
	c := "c"
	
	lm.Put(a, 1)
	lm.Put(b, 2)
	lm.Put(c, 3)
	
	key, value, ok := lm.Previous(c)
	assert.True(t, ok)
	assert.Equal(t, b, key)
	assert.Equal(t, 2, value)
	
	key, value, ok = lm.Previous(b)
	assert.True(t, ok)
	assert.Equal(t, a, key)
	assert.Equal(t, 1, value)
}

func TestLinkedMap_Previous_FirstElement(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	a := "a"
	b := "b"
	
	lm.Put(a, 1)
	lm.Put(b, 2)
	
	key, value, ok := lm.Previous(a) // First element
	assert.False(t, ok)
	assert.Equal(t, "", key) // Zero value for string
	assert.Equal(t, 0, value) // Zero value for int
}

func TestLinkedMap_Previous_NonExistentKey(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	a := "a"
	lm.Put(a, 1)
	
	key, value, ok := lm.Previous("nonexistent")
	assert.False(t, ok)
	assert.Equal(t, "", key)
	assert.Equal(t, 0, value)
}

func TestLinkedMap_Previous_EmptyMap(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	key, value, ok := lm.Previous("any")
	assert.False(t, ok)
	assert.Equal(t, "", key)
	assert.Equal(t, 0, value)
}

func TestLinkedMap_Previous_SingleElement(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	only := "only"
	lm.Put(only, 42)
	
	key, value, ok := lm.Previous(only)
	assert.False(t, ok)
	assert.Equal(t, "", key)
	assert.Equal(t, 0, value)
}

func TestLinkedMap_Replace_ExistingOldKey(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	old := "old"
	middle := "middle"
	end := "end"
	newKey := "new"
	
	lm.Put(old, 1)
	lm.Put(middle, 2)
	lm.Put(end, 3)
	
	success := lm.Replace(old, newKey, 100)
	
	assert.True(t, success)
	assert.False(t, lm.Contains(old))
	assert.True(t, lm.Contains(newKey))
	assert.Equal(t, 100, lm.Get(newKey))
	assert.Equal(t, 3, lm.Size())
	
	// Check that order is maintained
	key, value, ok := lm.First()
	assert.True(t, ok)
	assert.Equal(t, newKey, key)
	assert.Equal(t, 100, value)
	
	key, value, ok = lm.Next(newKey)
	assert.True(t, ok)
	assert.Equal(t, middle, key)
	assert.Equal(t, 2, value)
}

func TestLinkedMap_Replace_NonExistentOldKey(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	existing := "existing"
	newKey := "new"
	
	lm.Put(existing, 1)
	
	success := lm.Replace("nonexistent", newKey, 100)
	
	assert.False(t, success)
	assert.True(t, lm.Contains(existing))
	assert.False(t, lm.Contains(newKey))
	assert.Equal(t, 1, lm.Size())
}

func TestLinkedMap_Replace_NewKeyAlreadyExists(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	key1 := "key1"
	key2 := "key2"
	
	lm.Put(key1, 1)
	lm.Put(key2, 2)
	
	success := lm.Replace(key1, key2, 100)
	
	assert.False(t, success)
	assert.True(t, lm.Contains(key1))
	assert.True(t, lm.Contains(key2))
	assert.Equal(t, 1, lm.Get(key1)) // Unchanged
	assert.Equal(t, 2, lm.Get(key2)) // Unchanged
	assert.Equal(t, 2, lm.Size())
}

func TestLinkedMap_Replace_SameKey(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	key := "key"
	
	lm.Put(key, 1)
	
	success := lm.Replace(key, key, 100)
	
	assert.True(t, success)
	assert.True(t, lm.Contains(key))
	assert.Equal(t, 100, lm.Get(key))
	assert.Equal(t, 1, lm.Size())
}

func TestLinkedMap_Replace_EmptyMap(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	old := "old"
	newKey := "new"
	
	success := lm.Replace(old, newKey, 100)
	
	assert.False(t, success)
	assert.Equal(t, 0, lm.Size())
}

func TestLinkedMap_Replace_PreservesOrder(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	a := "a"
	b := "b"
	c := "c"
	B := "B"
	
	lm.Put(a, 1)
	lm.Put(b, 2)
	lm.Put(c, 3)
	
	// Replace middle element
	success := lm.Replace(b, B, 200)
	
	assert.True(t, success)
	
	// Check order is preserved
	key, value, ok := lm.First()
	assert.True(t, ok)
	assert.Equal(t, a, key)
	assert.Equal(t, 1, value)
	
	key, value, ok = lm.Next(a)
	assert.True(t, ok)
	assert.Equal(t, B, key)
	assert.Equal(t, 200, value)
	
	key, value, ok = lm.Next(B)
	assert.True(t, ok)
	assert.Equal(t, c, key)
	assert.Equal(t, 3, value)
}

func TestLinkedMap_Iterator_EmptyMap(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	count := 0
	for range lm.Iterator() {
		count++
	}
	assert.Equal(t, 0, count)
}

func TestLinkedMap_Iterator_SingleElement(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	single := "single"
	lm.Put(single, 42)
	
	count := 0
	for key, value := range lm.Iterator() {
		assert.Equal(t, single, key)
		assert.Equal(t, 42, value)
		count++
	}
	assert.Equal(t, 1, count)
}

func TestLinkedMap_Iterator_MultipleElements(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	first := "first"
	second := "second"
	third := "third"
	
	lm.Put(first, 1)
	lm.Put(second, 2)
	lm.Put(third, 3)
	
	expected := []struct{ key string; value int }{
		{first, 1},
		{second, 2},
		{third, 3},
	}
	
	i := 0
	for key, value := range lm.Iterator() {
		assert.Equal(t, expected[i].key, key)
		assert.Equal(t, expected[i].value, value)
		i++
	}
	assert.Equal(t, 3, i)
}

func TestLinkedMap_Iterator_PreservesInsertionOrder(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	// Add elements in specific order
	z := "z"
	a := "a"
	m := "m"
	
	lm.Put(z, 26)
	lm.Put(a, 1)
	lm.Put(m, 13)
	
	// Should iterate in insertion order, not alphabetical
	expected := []struct{ key string; value int }{
		{z, 26},
		{a, 1},
		{m, 13},
	}
	
	i := 0
	for key, value := range lm.Iterator() {
		assert.Equal(t, expected[i].key, key)
		assert.Equal(t, expected[i].value, value)
		i++
	}
	assert.Equal(t, 3, i)
}

func TestLinkedMap_Iterator_AfterUpdates(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	a := "a"
	b := "b"
	c := "c"
	
	lm.Put(a, 1)
	lm.Put(b, 2)
	lm.Put(c, 3)
	
	// Update middle element (should not change order)
	lm.Put(b, 200)
	
	expected := []struct{ key string; value int }{
		{a, 1},
		{b, 200}, // Updated value
		{c, 3},
	}
	
	i := 0
	for key, value := range lm.Iterator() {
		assert.Equal(t, expected[i].key, key)
		assert.Equal(t, expected[i].value, value)
		i++
	}
	assert.Equal(t, 3, i)
}

func TestLinkedMap_Iterator_AfterRemovals(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	a := "a"
	b := "b"
	c := "c"
	d := "d"
	
	lm.Put(a, 1)
	lm.Put(b, 2)
	lm.Put(c, 3)
	lm.Put(d, 4)
	
	// Remove middle elements
	_, ok := lm.Remove(b)
	assert.True(t, ok)
	_, ok = lm.Remove(c)
	assert.True(t, ok)
	
	expected := []struct{ key string; value int }{
		{a, 1},
		{d, 4},
	}
	
	i := 0
	for key, value := range lm.Iterator() {
		assert.Equal(t, expected[i].key, key)
		assert.Equal(t, expected[i].value, value)
		i++
	}
	assert.Equal(t, 2, i)
}

func TestLinkedMap_Iterator_AfterReplace(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	first := "first"
	second := "second"
	third := "third"
	SECOND := "SECOND"
	
	lm.Put(first, 1)
	lm.Put(second, 2)
	lm.Put(third, 3)
	
	// Replace middle element
	lm.Replace(second, SECOND, 200)
	
	expected := []struct{ key string; value int }{
		{first, 1},
		{SECOND, 200},
		{third, 3},
	}
	
	i := 0
	for key, value := range lm.Iterator() {
		assert.Equal(t, expected[i].key, key)
		assert.Equal(t, expected[i].value, value)
		i++
	}
	assert.Equal(t, 3, i)
}

func TestLinkedMap_Iterator_BreakEarly(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	for i := 0; i < 10; i++ {
		lm.Put(strconv.Itoa(i), i)
	}
	
	count := 0
	for key, value := range lm.Iterator() {
		_ = key
		_ = value
		count++
		if count == 5 {
			break // Test early break
		}
	}
	assert.Equal(t, 5, count)
}

func TestLinkedMap_Iterator_FullTraversal(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	// Add many elements
	expected := make(map[string]int)
	keys := []string{"alpha", "beta", "gamma", "delta", "epsilon"}
	
	for i, key := range keys {
		value := (i + 1) * 10
		lm.Put(key, value)
		expected[key] = value
	}
	
	// Traverse with iterator
	collected := make(map[string]int)
	collectedOrder := make([]string, 0)
	
	for key, value := range lm.Iterator() {
		collected[key] = value
		collectedOrder = append(collectedOrder, key)
	}
	
	// Verify all elements collected
	assert.Equal(t, len(expected), len(collected))
	for key, expectedValue := range expected {
		actualValue, exists := collected[key]
		assert.True(t, exists, "Key %s should exist", key)
		assert.Equal(t, expectedValue, actualValue, "Value for key %s", key)
	}
	
	// Verify order matches insertion order
	assert.Equal(t, keys, collectedOrder)
}

func TestLinkedMap_ComplexOperations(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	// Add some elements
	a := "a"
	b := "b"
	c := "c"
	d := "d"
	
	lm.Put(a, 1)
	lm.Put(b, 2)
	lm.Put(c, 3)
	
	// Update one
	lm.Put(b, 20)
	
	// Remove one
	_, ok := lm.Remove(a)
	assert.True(t, ok)
	
	// Add another
	lm.Put(d, 4)
	
	// Check final state
	assert.Equal(t, 3, lm.Size())
	
	key, value, ok := lm.First()
	assert.True(t, ok)
	assert.Equal(t, b, key)
	assert.Equal(t, 20, value)
	
	key, value, ok = lm.Next(b)
	assert.True(t, ok)
	assert.Equal(t, c, key)
	assert.Equal(t, 3, value)
	
	key, value, ok = lm.Next(c)
	assert.True(t, ok)
	assert.Equal(t, d, key)
	assert.Equal(t, 4, value)
}

func TestLinkedMap_TraversalAfterOperations(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	// Build a sequence
	keys := make([]string, 5)
	for i := 0; i < 5; i++ {
		key := string(rune('a' + i))
		keys[i] = key
		lm.Put(key, i)
	}
	
	// Remove some elements
	_, ok := lm.Remove(keys[1]) // Remove second (b)
	assert.True(t, ok)
	_, ok = lm.Remove(keys[3]) // Remove fourth (d)
	assert.True(t, ok)
	
	// Expected order: a(0), c(2), e(4)
	expected := []struct{ key string; value int }{
		{keys[0], 0}, // a
		{keys[2], 2}, // c
		{keys[4], 4}, // e
	}
	
	// Traverse and verify
	key, value, ok := lm.First()
	assert.True(t, ok)
	for i, exp := range expected {
		assert.Equal(t, exp.key, key, "Position %d", i)
		assert.Equal(t, exp.value, value, "Position %d", i)
		
		if i < len(expected)-1 {
			key, value, ok = lm.Next(key)
			assert.True(t, ok)
		}
	}
}

func TestLinkedMap_WithStringKeys(t *testing.T) {
	strMap := NewLinkedMap[string, string]()
	
	hello := "hello"
	foo := "foo"
	
	strMap.Put(hello, "world")
	strMap.Put(foo, "bar")
	
	assert.Equal(t, "world", strMap.Get(hello))
	assert.Equal(t, "bar", strMap.Get(foo))
	assert.True(t, strMap.Contains(hello))
	assert.Equal(t, 2, strMap.Size())
}

func TestLinkedMap_SingleElementOperations(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	single := "single"
	replaced := "replaced"
	
	lm.Put(single, 42)
	
	// Test all operations
	assert.Equal(t, 1, lm.Size())
	assert.True(t, lm.Contains(single))
	assert.Equal(t, 42, lm.Get(single))
	
	key, value, ok := lm.First()
	assert.True(t, ok)
	assert.Equal(t, single, key)
	assert.Equal(t, 42, value)
	
	nextKey, nextValue, ok := lm.Next(single)
	assert.False(t, ok)
	assert.Equal(t, "", nextKey)
	assert.Equal(t, 0, nextValue)
	
	// Replace
	assert.True(t, lm.Replace(single, replaced, 100))
	assert.False(t, lm.Contains(single))
	assert.True(t, lm.Contains(replaced))
	
	// Remove
	removedValue, ok := lm.Remove(replaced)
	assert.True(t, ok)
	assert.Equal(t, 100, removedValue)
	assert.Equal(t, 0, lm.Size())
}

func TestLinkedMap_BidirectionalTraversal(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	a := "a"
	b := "b"
	c := "c"
	d := "d"
	
	lm.Put(a, 1)
	lm.Put(b, 2)
	lm.Put(c, 3)
	lm.Put(d, 4)
	
	// Forward traversal
	key, value, ok := lm.First()
	assert.True(t, ok)
	assert.Equal(t, a, key)
	assert.Equal(t, 1, value)
	
	key, value, ok = lm.Next(a)
	assert.True(t, ok)
	assert.Equal(t, b, key)
	assert.Equal(t, 2, value)
	
	key, value, ok = lm.Next(b)
	assert.True(t, ok)
	assert.Equal(t, c, key)
	assert.Equal(t, 3, value)
	
	// Backward traversal from current position
	key, value, ok = lm.Previous(c)
	assert.True(t, ok)
	assert.Equal(t, b, key)
	assert.Equal(t, 2, value)
	
	key, value, ok = lm.Previous(b)
	assert.True(t, ok)
	assert.Equal(t, a, key)
	assert.Equal(t, 1, value)
}

func TestLinkedMap_PreviousAfterOperations(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	a := "a"
	b := "b"
	c := "c"
	d := "d"
	
	lm.Put(a, 1)
	lm.Put(b, 2)
	lm.Put(c, 3)
	lm.Put(d, 4)
	
	// Remove middle element
	_, ok := lm.Remove(b)
	assert.True(t, ok)
	
	// Check that previous relationships are updated correctly
	key, value, ok := lm.Previous(c)
	assert.True(t, ok)
	assert.Equal(t, a, key)
	assert.Equal(t, 1, value)
}

func TestLinkedMap_PreviousAfterReplace(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	first := "first"
	second := "second"
	third := "third"
	SECOND := "SECOND"
	
	lm.Put(first, 1)
	lm.Put(second, 2)
	lm.Put(third, 3)
	
	// Replace middle element
	success := lm.Replace(second, SECOND, 200)
	assert.True(t, success)
	
	// Check previous relationships are maintained
	key, value, ok := lm.Previous(third)
	assert.True(t, ok)
	assert.Equal(t, SECOND, key)
	assert.Equal(t, 200, value)
	
	key, value, ok = lm.Previous(SECOND)
	assert.True(t, ok)
	assert.Equal(t, first, key)
	assert.Equal(t, 1, value)
}

func TestLinkedMap_ConcurrentReadOperations(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	// Populate map
	keys := make([]string, 100)
	for i := 0; i < 100; i++ {
		key := string(rune('a'+i%26)) + strconv.Itoa(i)
		keys[i] = key
		lm.Put(key, i)
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
				
				_ = lm.Get(key)
				_ = lm.Contains(key)
				_ = lm.Size()
				
				if lm.Contains(key) {
					_, _, _ = lm.Next(key)
					_, _, _ = lm.Previous(key)
				}
				
				_, _, _ = lm.First()
			}
		}(i)
	}
	
	wg.Wait()
	
	// Verify map integrity
	assert.Equal(t, 100, lm.Size())
}

func TestLinkedMap_ConcurrentWriteOperations(t *testing.T) {
	lm := NewLinkedMap[string, int]()
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
				lm.Put(key, id*1000+j)
			}
		}(i)
	}
	
	wg.Wait()
	
	// Verify all elements were added
	assert.Equal(t, 100, lm.Size())
}

func TestLinkedMap_ConcurrentMixedOperations(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	// Pre-populate with some data
	keys := make([]string, 50)
	for i := 0; i < 50; i++ {
		key := string(rune('a'+i%26)) + strconv.Itoa(i)
		keys[i] = key
		lm.Put(key, i)
	}
	
	var wg sync.WaitGroup
	
	// Reader goroutines
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				key := keys[j%50]
				_ = lm.Get(key)
				_ = lm.Contains(key)
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
				lm.Put(key, baseOffset+j)
				if j%5 == 0 {
					time.Sleep(time.Microsecond)
				}
			}
		}(i)
	}
	
	wg.Wait()
	
	// Verify final state
	assert.True(t, lm.Size() >= 50) // At least original elements
	assert.True(t, lm.Size() <= 110) // Original + new elements
}

func TestLinkedMap_WithIntegerKeys(t *testing.T) {
	intMap := NewLinkedMap[int, string]()
	
	one := 1
	two := 2
	three := 3
	
	intMap.Put(one, "one")
	intMap.Put(two, "two")
	intMap.Put(three, "three")
	
	assert.Equal(t, "one", intMap.Get(one))
	assert.Equal(t, "two", intMap.Get(two))
	assert.Equal(t, "three", intMap.Get(three))
	assert.Equal(t, 3, intMap.Size())
	
	// Test traversal
	key, value, ok := intMap.First()
	assert.True(t, ok)
	assert.Equal(t, one, key)
	assert.Equal(t, "one", value)
	
	key, value, ok = intMap.Next(one)
	assert.True(t, ok)
	assert.Equal(t, two, key)
	assert.Equal(t, "two", value)
	
	key, value, ok = intMap.Previous(two)
	assert.True(t, ok)
	assert.Equal(t, one, key)
	assert.Equal(t, "one", value)
}

func TestLinkedMap_WithStructValues(t *testing.T) {
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
	assert.Equal(t, "Alice", retrievedP1.Name)
	assert.Equal(t, 30, retrievedP1.Age)
	
	// Test zero value
	nonExistent := personMap.Get("charlie")
	assert.Equal(t, "", nonExistent.Name)
	assert.Equal(t, 0, nonExistent.Age)
}

func TestLinkedMap_Replace_WithDifferentTypes(t *testing.T) {
	boolMap := NewLinkedMap[string, bool]()
	
	trueKey := "true"
	falseKey := "false"
	TRUE := "TRUE"
	
	boolMap.Put(trueKey, true)
	boolMap.Put(falseKey, false)
	
	success := boolMap.Replace(trueKey, TRUE, false)
	assert.True(t, success)
	assert.False(t, boolMap.Get(TRUE))
	assert.False(t, boolMap.Contains(trueKey))
}

func TestLinkedMap_Remove_NodeIsolation(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	a := "a"
	b := "b"
	c := "c"
	
	lm.Put(a, 1)
	lm.Put(b, 2)
	lm.Put(c, 3)
	
	// Get references before removal
	firstKey, _, ok := lm.First()
	assert.True(t, ok)
	assert.Equal(t, a, firstKey)
	
	// Remove middle element
	removedValue, ok := lm.Remove(b)
	assert.True(t, ok)
	assert.Equal(t, 2, removedValue)
	
	// Verify links are properly updated
	key, value, ok := lm.Next(a)
	assert.True(t, ok)
	assert.Equal(t, c, key)
	assert.Equal(t, 3, value)
	
	key, value, ok = lm.Previous(c)
	assert.True(t, ok)
	assert.Equal(t, a, key)
	assert.Equal(t, 1, value)
}

func TestLinkedMap_SizeConsistency(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	// Start empty
	assert.Equal(t, 0, lm.Size())
	
	a := "a"
	b := "b"
	A := "A"
	
	// Add elements
	lm.Put(a, 1)
	assert.Equal(t, 1, lm.Size())
	
	lm.Put(b, 2)
	assert.Equal(t, 2, lm.Size())
	
	// Update existing (size should not change)
	lm.Put(a, 10)
	assert.Equal(t, 2, lm.Size())
	
	// Replace (size should not change)
	lm.Replace(a, A, 100)
	assert.Equal(t, 2, lm.Size())
	
	// Remove
	_, ok := lm.Remove(A)
	assert.True(t, ok)
	assert.Equal(t, 1, lm.Size())
	
	_, ok = lm.Remove(b)
	assert.True(t, ok)
	assert.Equal(t, 0, lm.Size())
	
	// Remove non-existent (size should not change)
	_, ok = lm.Remove("nonexistent")
	assert.False(t, ok)
	assert.Equal(t, 0, lm.Size())
}

func TestLinkedMap_ZeroValueHandling(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	// Test with zero values for different types
	
	// Empty string key
	empty := ""
	zero := "zero"
	
	lm.Put(empty, 42) // Empty string key
	assert.True(t, lm.Contains(empty))
	assert.Equal(t, 42, lm.Get(empty))
	
	// Int zero value
	lm.Put(zero, 0) // Zero value
	assert.True(t, lm.Contains(zero))
	assert.Equal(t, 0, lm.Get(zero))
	
	// Test operations with zero values
	key, value, ok := lm.First()
	assert.True(t, ok)
	if key == "" {
		assert.Equal(t, 42, value)
	} else {
		assert.Equal(t, zero, key)
		assert.Equal(t, 0, value)
	}
}

func TestLinkedMap_TraversalIntegrity(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	// Build a map with known order
	keyStrs := []string{"alpha", "beta", "gamma", "delta", "epsilon"}
	keys := make([]string, len(keyStrs))
	for i, keyStr := range keyStrs {
		keys[i] = keyStr
		lm.Put(keys[i], i*10)
	}
	
	// Forward traversal
	currentKey, currentValue, ok := lm.First()
	assert.True(t, ok)
	for i, expectedKey := range keys {
		assert.Equal(t, expectedKey, currentKey, "Forward traversal at position %d", i)
		assert.Equal(t, i*10, currentValue, "Forward traversal value at position %d", i)
		
		if i < len(keys)-1 {
			currentKey, currentValue, ok = lm.Next(currentKey)
			assert.True(t, ok)
		}
	}
	
	// Backward traversal from last element
	currentKey = keys[len(keys)-1]
	for i := len(keys) - 1; i >= 0; i-- {
		expectedKey := keys[i]
		assert.Equal(t, expectedKey, currentKey, "Backward traversal at position %d", i)
		
		if i > 0 {
			currentKey, _, ok = lm.Previous(currentKey)
			assert.True(t, ok)
		}
	}
}