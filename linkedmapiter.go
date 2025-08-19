package tomtp

// NestedIterator iterates through nested maps
type NestedIterator[K1, K2 comparable, V1, V2 any] struct {
	outer    *LinkedMap[K1, V1]
	getInner func(V1) *LinkedMap[K2, V2]
	startK1  K1
	startK2  K2
	hasStart bool

	// Current position
	currentOuterK1 K1
	currentInnerK2 K2
	initialized    bool
}

// NewNestedIterator creates a simple nested iterator
func NewNestedIterator[K1, K2 comparable, V1, V2 any](
	outerMap *LinkedMap[K1, V1],
	getInnerMap func(V1) *LinkedMap[K2, V2],
	startOuter K1,
	startInner K2,
) *NestedIterator[K1, K2, V1, V2] {

	it := &NestedIterator[K1, K2, V1, V2]{
		outer:    outerMap,
		getInner: getInnerMap,
		startK1:  startOuter,
		startK2:  startInner,
	}

	// Check if start position exists
	if outerMap.Contains(startOuter) {
		outerVal := outerMap.Get(startOuter)
		if innerMap := getInnerMap(outerVal); innerMap.Contains(startInner) {
			it.hasStart = true
		}
	}

	return it
}

// Next returns (outerValue, innerValue, cycleComplete)
// cycleComplete is true when we've returned to the starting position
func (it *NestedIterator[K1, K2, V1, V2]) Next() (V1, V2, bool) {
	if !it.initialized {
		return it.initialize()
	}

	// Try to advance to next item
	return it.advance()
}

// initialize sets up the iterator for the first call
func (it *NestedIterator[K1, K2, V1, V2]) initialize() (V1, V2, bool) {
	var zeroV1 V1
	var zeroV2 V2

	it.initialized = true

	if !it.hasStart {
		// No valid start, begin from very first item
		outerK1, outerV1, ok := it.outer.First()
		if !ok {
			return zeroV1, zeroV2, false
		}

		innerMap := it.getInner(outerV1)
		innerK2, innerV2, ok := innerMap.First()
		if !ok {
			// This outer has no inner items, advance to next
			it.currentOuterK1 = outerK1
			return it.advance()
		}

		it.currentOuterK1 = outerK1
		it.currentInnerK2 = innerK2
		return outerV1, innerV2, false
	}

	// Start from next position after startK1/startK2
	
	if it.outer.Contains(it.startK1) {
		startOuterV1 := it.outer.Get(it.startK1)
		innerMap := it.getInner(startOuterV1)
		nextInnerK2, nextInnerV2, ok := innerMap.Next(it.startK2)
		if ok {
			it.currentOuterK1 = it.startK1
			it.currentInnerK2 = nextInnerK2
			return startOuterV1, nextInnerV2, false
		}
	}

	// No next inner in same outer, move to next outer
	it.currentOuterK1 = it.startK1
	return it.advance()
}

// advance moves to the next position
func (it *NestedIterator[K1, K2, V1, V2]) advance() (V1, V2, bool) {
	var zeroV1 V1
	var zeroV2 V2

	// Try next inner in current outer first
	
	if it.outer.Contains(it.currentOuterK1) {
		currentOuterV1 := it.outer.Get(it.currentOuterK1)
		innerMap := it.getInner(currentOuterV1)
		nextInnerK2, nextInnerV2, ok := innerMap.Next(it.currentInnerK2)
		if ok {
			// Check if we've come full circle
			if it.hasStart && it.currentOuterK1 == it.startK1 && nextInnerK2 == it.startK2 {
				return currentOuterV1, nextInnerV2, true
			}

			it.currentInnerK2 = nextInnerK2
			return currentOuterV1, nextInnerV2, false
		}
	}

	// No next inner, try next outer
	nextOuterK1, nextOuterV1, ok := it.outer.Next(it.currentOuterK1)
	if !ok {
		// Reached end of outers, wrap around if we have a start
		if it.hasStart {
			nextOuterK1, nextOuterV1, ok = it.outer.First()
			if !ok {
				return zeroV1, zeroV2, false
			}
		} else {
			return zeroV1, zeroV2, false
		}
	}

	// Try first inner of next outer
	innerMap := it.getInner(nextOuterV1)
	firstInnerK2, firstInnerV2, ok := innerMap.First()
	if !ok {
		// This outer has no inner items, advance again
		it.currentOuterK1 = nextOuterK1
		return it.advance()
	}

	// Check if we've come full circle
	if it.hasStart && nextOuterK1 == it.startK1 && firstInnerK2== it.startK2 {
		it.currentOuterK1 = nextOuterK1
		it.currentInnerK2 = firstInnerK2
		return nextOuterV1, firstInnerV2, true
	}

	it.currentOuterK1 = nextOuterK1
	it.currentInnerK2 = firstInnerK2
	return nextOuterV1, firstInnerV2, false
}
