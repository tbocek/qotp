// Package tomtp provides a sorted map with O(1) Next() traversal.
// All exported methods are thread-safe.
package qotp

import (
	"cmp"
	"sync"
)

const maxLevel = 32     // Enough for 2^32 elements
const nodesPerLevel = 4 // Every 4 nodes we add a level up

// SortedMap implements a thread-safe skip list with O(1) lookups and O(1) Next() operations.
type SortedMap[K cmp.Ordered, V any] struct {
	items map[K]*smNode[K, V]
	head  *smNode[K, V]
	tail  *smNode[K, V] // Sentinel tail node
	level int
	size  int
	mu    sync.RWMutex
}

// node represents an internal node in the skip list.
type smNode[K cmp.Ordered, V any] struct {
	key   K
	value V
	next  []*smNode[K, V] // Skip list levels for fast search
	after *smNode[K, V]   // Direct pointer to next element in sorted order - O(1) traversal!
	prev  *smNode[K, V]   // Direct pointer to previous element for O(1) removal
}

// NewSortedMap creates a new sorted map with the given key comparison function.
func NewSortedMap[K cmp.Ordered, V any]() *SortedMap[K, V] {
	m := &SortedMap[K, V]{
		items: make(map[K]*smNode[K, V]),
		level: 1,
	}
	
	// Create sentinel head and tail nodes
	m.head = &smNode[K, V]{next: make([]*smNode[K, V], maxLevel)}
	m.tail = &smNode[K, V]{}
	
	// Link head to tail initially
	m.head.after = m.tail
	m.tail.prev = m.head
	
	return m
}

// getNodeLevel returns the level a node should have based on its position.
func (m *SortedMap[K, V]) getNodeLevel() int {
	pos := m.size + 1
	level := 1
	for pos%nodesPerLevel == 0 {
		level++
		pos /= nodesPerLevel
	}
	if level > maxLevel {
		level = maxLevel
	}
	return level
}

// Size returns the number of elements in the map.
func (m *SortedMap[K, V]) Size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.size
}

// Put adds or updates a key-value pair in the map.
func (m *SortedMap[K, V]) Put(key K, value V) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Update existing value if key exists
	if existing, ok := m.items[key]; ok {
		existing.value = value
		return
	}

	// Find insert position at each level using skip list search
	update := make([]*smNode[K, V], maxLevel)
	current := m.head

	for i := m.level - 1; i >= 0; i-- {
		for current.next[i] != nil && current.next[i] != m.tail && current.next[i].key < key {
			current = current.next[i]
		}
		update[i] = current
	}

	// Determine level for new node
	level := m.getNodeLevel()
	if level > m.level {
		for i := m.level; i < level; i++ {
			update[i] = m.head
		}
		m.level = level
	}

	// Create new node
	newNode := &smNode[K, V]{
		key:   key,
		value: value,
		next:  make([]*smNode[K, V], level),
	}

	// Insert into skip list levels
	for i := 0; i < level; i++ {
		newNode.next[i] = update[i].next[i]
		update[i].next[i] = newNode
	}

	// Insert into doubly-linked list for O(1) traversal
	// The node goes after update[0] (which is the largest node smaller than key)
	predecessor := update[0]
	successor := predecessor.after

	newNode.after = successor
	newNode.prev = predecessor
	predecessor.after = newNode
	successor.prev = newNode

	m.items[key] = newNode
	m.size++
}

// Get retrieves a value from the map.
// Returns the value and a boolean indicating if the key was found.
func (m *SortedMap[K, V]) Get(key K) (V, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if node, exists := m.items[key]; exists {
		return node.value, true
	}
	
	var zero V
	return zero, false
}

// Contains checks if a key exists in the map.
func (m *SortedMap[K, V]) Contains(key K) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.items[key]
	return exists
}

// Next finds the next key that is strictly greater than the given key.
// This is now O(1) if the key exists in the map!
// Returns the next key, its value, and a boolean indicating if a next element exists.
func (m *SortedMap[K, V]) Next(key K) (K, V, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Fast path: if key exists in map, just follow the 'after' pointer - O(1)!
	if node, exists := m.items[key]; exists {
		if node.after != m.tail {
			return node.after.key, node.after.value, true
		}
		var zeroK K
		var zeroV V
		return zeroK, zeroV, false
	}

	// Slow path: key doesn't exist, need to search - O(log n)
	current := m.head
	for i := m.level - 1; i >= 0; i-- {
		for current.next[i] != nil && current.next[i] != m.tail && key >= current.next[i].key {
			current = current.next[i]
		}
	}

	if current.after != m.tail {
		return current.after.key, current.after.value, true
	}

	var zeroK K
	var zeroV V
	return zeroK, zeroV, false
}

// Prev finds the previous key that is strictly smaller than the given key.
// This is O(1) if the key exists in the map!
// Returns the previous key, its value, and a boolean indicating if a previous element exists.
func (m *SortedMap[K, V]) Prev(key K) (K, V, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Fast path: if key exists in map, just follow the 'prev' pointer - O(1)!
	if node, exists := m.items[key]; exists {
		if node.prev != m.head {
			return node.prev.key, node.prev.value, true
		}
		var zeroK K
		var zeroV V
		return zeroK, zeroV, false
	}

	// Slow path: key doesn't exist, need to search - O(log n)
	current := m.head
	for i := m.level - 1; i >= 0; i-- {
		for current.next[i] != nil && current.next[i] != m.tail && current.next[i].key < key {
			current = current.next[i]
		}
	}

	// current is now the largest node with key < target key
	if current != m.head {
		return current.key, current.value, true
	}

	var zeroK K
	var zeroV V
	return zeroK, zeroV, false
}

// Min returns the smallest key and value in the map.
// Returns the key, value, and a boolean indicating if the map is not empty.
func (m *SortedMap[K, V]) Min() (K, V, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.head.after != m.tail {
		node := m.head.after
		return node.key, node.value, true
	}
	
	var zeroK K
	var zeroV V
	return zeroK, zeroV, false
}

// Remove removes a key-value pair from the map. 
// Returns the removed value and a boolean indicating if the key existed.
func (m *SortedMap[K, V]) Remove(key K) (V, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	targetNode, ok := m.items[key]
	if !ok {
		var zero V
		return zero, false
	}

	// Remove from skip list levels
	update := make([]*smNode[K, V], maxLevel)
	current := m.head

	for i := m.level - 1; i >= 0; i-- {
		for current.next[i] != nil && current.next[i] != m.tail && current.next[i].key < key {
			current = current.next[i]
		}
		update[i] = current
	}

	// Update skip list pointers
	if current.next[0] == targetNode {
		for i := 0; i < m.level; i++ {
			if update[i].next[i] != targetNode {
				continue
			}
			update[i].next[i] = targetNode.next[i]
		}
	}

	// Remove from doubly-linked list - O(1) thanks to prev/after pointers!
	targetNode.prev.after = targetNode.after
	targetNode.after.prev = targetNode.prev

	// Update level if needed
	for m.level > 1 && m.head.next[m.level-1] == nil {
		m.level--
	}

	delete(m.items, key)
	m.size--

	return targetNode.value, true
}
