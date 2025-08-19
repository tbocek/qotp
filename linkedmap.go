// Package tomtp provides a linked hash map with O(1) operations and insertion order traversal.
// All exported methods are thread-safe.
package tomtp

import (
	"sync"
)

// LinkedMap implements a thread-safe hash map with insertion order preservation.
type LinkedMap[K comparable, V any] struct {
	items map[K]*lmNode[K, V]
	head  *lmNode[K, V] // Sentinel head node
	tail  *lmNode[K, V] // Sentinel tail node
	size  int
	mu    sync.RWMutex
}

// node represents an internal node in the linked list.
type lmNode[K comparable, V any] struct {
	key   K
	value V
	next  *lmNode[K, V] // Next element in insertion order
	prev  *lmNode[K, V] // Previous element in insertion order
}

type LinkedMapIterator[K comparable, V any] struct {
	m    *LinkedMap[K, V]
	curr *lmNode[K, V]
}

// NewLinkedMap creates a new linked hash map.
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

// Remove removes a key-value pair from the map. Returns the removed value and true if found.
func (m *LinkedMap[K, V]) Remove(key K) (V, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	node, ok := m.items[key]
	if !ok {
		var zero V
		return zero, false
	}

	// Remove from doubly-linked list - O(1) thanks to prev/next pointers!
	node.prev.next = node.next
	node.next.prev = node.prev

	delete(m.items, key)
	m.size--

	return node.value, true
}

// First returns the first inserted key and value in the map.
// Returns false if the map is empty.
func (m *LinkedMap[K, V]) First() (K, V, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.head.next != m.tail {
		node := m.head.next
		return node.key, node.value, true
	}

	var zeroK K
	var zeroV V
	return zeroK, zeroV, false
}

// Next finds the next key in insertion order after the given key.
// This is O(1) if the key exists in the map!
// Returns the next key, its value, and true if a next element exists.
func (m *LinkedMap[K, V]) Next(key K) (K, V, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Fast path: if key exists in map, just follow the 'next' pointer - O(1)!
	if node, exists := m.items[key]; exists {
		if node.next != m.tail {
			return node.next.key, node.next.value, true
		}
	}

	// If key doesn't exist or no next element
	var zeroK K
	var zeroV V
	return zeroK, zeroV, false
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

// Previous finds the previous key in insertion order before the given key.
// Returns the previous key, its value, and true if a previous element exists.
func (m *LinkedMap[K, V]) Previous(key K) (K, V, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Fast path: if key exists in map, just follow the 'prev' pointer - O(1)!
	if node, exists := m.items[key]; exists {
		if node.prev != m.head {
			return node.prev.key, node.prev.value, true
		}
	}

	// If key doesn't exist or no previous element
	var zeroK K
	var zeroV V
	return zeroK, zeroV, false
}

// HasPrevious checks if there's a previous element before the given key in insertion order.
func (m *LinkedMap[K, V]) HasPrevious(key K) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if node, exists := m.items[key]; exists {
		return node.prev != m.head
	}

	return false
}

// Replace replaces an existing key with a new key and value, maintaining the same position in insertion order.
// Returns true if oldKey existed and was replaced, false otherwise.
// If newKey already exists elsewhere in the map, the operation fails and returns false.
func (m *LinkedMap[K, V]) Replace(oldKey K, newKey K, value V) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if old key exists
	oldNode, oldExists := m.items[oldKey]
	if !oldExists {
		return false
	}

	// If the keys are the same, just update the value
	if oldKey == newKey {
		oldNode.value = value
		return true
	}

	// Check if new key already exists (and it's different from old key)
	if _, newExists := m.items[newKey]; newExists {
		return false // Can't replace with a key that already exists
	}

	// Update the node with new key and value
	oldNode.key = newKey
	oldNode.value = value

	// Update the map entries
	delete(m.items, oldKey)
	m.items[newKey] = oldNode

	return true
}

// Iterator returns a new iterator for traversing the map in insertion order.
func (m *LinkedMap[K, V]) Iterator() *LinkedMapIterator[K, V] {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var curr *lmNode[K, V]
	if m.head.next != m.tail {
		curr = m.head.next // Start at first real element
	} else {
		curr = nil // Empty map
	}

	return &LinkedMapIterator[K, V]{
		curr: curr,
		m:    m,
	}
}

// Next advances the iterator and returns the current key, value, and true if valid.
// Returns false when iteration has reached the end.
func (it *LinkedMapIterator[K, V]) Next() (K, V, bool) {
	it.m.mu.RLock()
	defer it.m.mu.RUnlock()

	var zeroK K
	var zeroV V

	// Check if curr is nil (empty map or end of iteration)
	if it.curr == nil || it.curr == it.m.tail {
		return zeroK, zeroV, false
	}

	// Get current values
	key := it.curr.key
	value := it.curr.value

	// Advance to next
	if it.curr.next == it.m.tail {
		it.curr = nil // Mark end of iteration
	} else {
		it.curr = it.curr.next
	}

	return key, value, true
}