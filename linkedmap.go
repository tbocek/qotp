// Package tomtp provides a linked hash map with O(1) operations and insertion order traversal.
// All exported methods are thread-safe.
package tomtp

import (
	"sync"
)

// LinkedHashMap implements a thread-safe hash map with insertion order preservation.
type LinkedMap[K comparable, V any] struct {
	items map[K]*lmNode[K, V]
	head  *lmNode[K, V] // Sentinel head node
	tail  *lmNode[K, V] // Sentinel tail node
	size  int
	mu    sync.RWMutex
}

// node represents an internal node in the linked list.
type lmNode[K comparable, V any] struct {
	key  K
	value V
	next *lmNode[K, V] // Next element in insertion order
	prev *lmNode[K, V] // Previous element in insertion order
}

// NewLinkedHashMap creates a new linked hash map.
func NewLinkedMap[K comparable, V any]() *LinkedMap[K, V] {
	m := &LinkedMap[K, V]{
		items: make(map[K]*lmNode[K, V]),
	}
	
	// Create sentinel head and tail nodes
	m.head = &lmNode[K, V]{}
	m.tail = &lmNode[K, V]{}
	
	// Link head to tail initially
	m.head.next = m.tail
	m.tail.prev = m.head
	
	return m
}

// Size returns the number of elements in the map.
func (m *LinkedMap[K, V]) Size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.size
}

// IsEmpty returns true if the map is empty.
func (m *LinkedMap[K, V]) IsEmpty() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.size == 0
}

// Put adds or updates a key-value pair in the map.
// If key already exists, updates the value but keeps the insertion order position.
func (m *LinkedMap[K, V]) Put(key K, value V) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Update existing value if key exists (keep same position in insertion order)
	if existing, ok := m.items[key]; ok {
		existing.value = value
		return
	}

	// Create new node
	newNode := &lmNode[K, V]{
		key:   key,
		value: value,
	}

	// Insert at the end of the linked list (before tail)
	predecessor := m.tail.prev
	newNode.next = m.tail
	newNode.prev = predecessor
	predecessor.next = newNode
	m.tail.prev = newNode

	m.items[key] = newNode
	m.size++
}

// Get retrieves a value from the map. Returns zero value if not found.
func (m *LinkedMap[K, V]) Get(key K) V {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if node, exists := m.items[key]; exists {
		return node.value
	}
	
	var zero V
	return zero
}

// Contains checks if a key exists in the map.
func (m *LinkedMap[K, V]) Contains(key K) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.items[key]
	return exists
}

// Remove removes a key-value pair from the map. Returns the removed value.
func (m *LinkedMap[K, V]) Remove(key K) V {
	m.mu.Lock()
	defer m.mu.Unlock()

	node, ok := m.items[key]
	if !ok {
		var zero V
		return zero
	}

	// Remove from doubly-linked list - O(1) thanks to prev/next pointers!
	node.prev.next = node.next
	node.next.prev = node.prev

	delete(m.items, key)
	m.size--

	return node.value
}

// First returns the first inserted key and value in the map.
func (m *LinkedMap[K, V]) First() (K, V) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.head.next != m.tail {
		node := m.head.next
		return node.key, node.value
	}
	
	var zeroK K
	var zeroV V
	return zeroK, zeroV
}

// Last returns the last inserted key and value in the map.
func (m *LinkedMap[K, V]) Last() (K, V) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.tail.prev != m.head {
		node := m.tail.prev
		return node.key, node.value
	}
	
	var zeroK K
	var zeroV V
	return zeroK, zeroV
}

// Next finds the next key in insertion order after the given key.
// This is O(1) if the key exists in the map!
// Returns the next key and its value in insertion order. If no next element exists, returns zero values.
func (m *LinkedMap[K, V]) Next(key K) (K, V) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Fast path: if key exists in map, just follow the 'next' pointer - O(1)!
	if node, exists := m.items[key]; exists {
		if node.next != m.tail {
			return node.next.key, node.next.value
		}
		var zeroK K
		var zeroV V
		return zeroK, zeroV
	}

	// If key doesn't exist, we can't determine insertion order position
	var zeroK K
	var zeroV V
	return zeroK, zeroV
}

// Prev finds the previous key in insertion order before the given key.
// This is O(1) if the key exists in the map!
// Returns the previous key and its value in insertion order. If no previous element exists, returns zero values.
func (m *LinkedMap[K, V]) Prev(key K) (K, V) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Fast path: if key exists in map, just follow the 'prev' pointer - O(1)!
	if node, exists := m.items[key]; exists {
		if node.prev != m.head {
			return node.prev.key, node.prev.value
		}
		var zeroK K
		var zeroV V
		return zeroK, zeroV
	}

	// If key doesn't exist, we can't determine insertion order position
	var zeroK K
	var zeroV V
	return zeroK, zeroV
}

// HasNext checks if there's a next element after the given key in insertion order.
func (m *LinkedMap[K, V]) HasNext(key K) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if node, exists := m.items[key]; exists {
		return node.next != m.tail
	}

	return false
}

// HasPrev checks if there's a previous element before the given key in insertion order.
func (m *LinkedMap[K, V]) HasPrev(key K) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if node, exists := m.items[key]; exists {
		return node.prev != m.head
	}

	return false
}

// Keys returns all keys in insertion order.
func (m *LinkedMap[K, V]) Keys() []K {
	m.mu.RLock()
	defer m.mu.RUnlock()

	keys := make([]K, 0, m.size)
	current := m.head.next

	for current != m.tail {
		keys = append(keys, current.key)
		current = current.next
	}

	return keys
}

// Values returns all values in insertion order.
func (m *LinkedMap[K, V]) Values() []V {
	m.mu.RLock()
	defer m.mu.RUnlock()

	values := make([]V, 0, m.size)
	current := m.head.next

	for current != m.tail {
		values = append(values, current.value)
		current = current.next
	}

	return values
}

// Clear removes all elements from the map.
func (m *LinkedMap[K, V]) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Clear the hash map
	m.items = make(map[K]*lmNode[K, V])
	
	// Reset the linked list
	m.head.next = m.tail
	m.tail.prev = m.head
	
	m.size = 0
}

// RemoveFirst removes and returns the first inserted key-value pair.
func (m *LinkedMap[K, V]) RemoveFirst() (K, V) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.head.next == m.tail {
		var zeroK K
		var zeroV V
		return zeroK, zeroV
	}

	firstNode := m.head.next
	key, value := firstNode.key, firstNode.value

	// Remove from linked list
	m.head.next = firstNode.next
	firstNode.next.prev = m.head

	// Remove from hash map
	delete(m.items, key)
	m.size--

	return key, value
}

// RemoveLast removes and returns the last inserted key-value pair.
func (m *LinkedMap[K, V]) RemoveLast() (K, V) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.tail.prev == m.head {
		var zeroK K
		var zeroV V
		return zeroK, zeroV
	}

	lastNode := m.tail.prev
	key, value := lastNode.key, lastNode.value

	// Remove from linked list
	m.tail.prev = lastNode.prev
	lastNode.prev.next = m.tail

	// Remove from hash map
	delete(m.items, key)
	m.size--

	return key, value
}

// Replace replaces the value for an existing key without affecting insertion order.
// Returns true if the key existed and was replaced, false otherwise.
func (m *LinkedMap[K, V]) Replace(key K, value V) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if existing, ok := m.items[key]; ok {
		existing.value = value
		return true
	}
	
	return false
}