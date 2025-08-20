package qotp

// NestedIterator iterates through nested maps
type NestedIterator[K1, K2 comparable, V1, V2 any] struct {
	outer                         *LinkedMap[K1, V1]
	getInner                      func(V1) *LinkedMap[K2, V2]
	currentOuterKey, nextOuterKey *K1
	currentInnerKey, nextInnerKey *K2
}

// NewNestedIterator creates a simple nested iterator
func NewNestedIterator[K1, K2 comparable, V1, V2 any](
	outerMap *LinkedMap[K1, V1],
	getInnerMap func(V1) *LinkedMap[K2, V2],
) *NestedIterator[K1, K2, V1, V2] {
	return &NestedIterator[K1, K2, V1, V2]{
		outer:    outerMap,
		getInner: getInnerMap,
	}
}

// Next returns (outerValue, innerValue)
func (it *NestedIterator[K1, K2, V1, V2]) Next() (currentOuter V1, currentInner V2) {
	var ok bool
	var zeroOuter V1
	var zeroInner V2
	var tmpOuterKey K1
	var tmpInnerKey K2

	it.currentOuterKey = nil
	if it.nextOuterKey != nil {
		it.currentOuterKey = it.nextOuterKey
	}

	it.currentInnerKey = nil
	if it.nextInnerKey != nil {
		it.currentInnerKey = it.nextInnerKey
	}

	if it.currentOuterKey == nil || !it.outer.Contains(*it.currentOuterKey) {
		tmpOuterKey, currentOuter, ok = it.outer.First()
		if !ok {
			return zeroOuter, zeroInner
		}
		it.currentOuterKey = &tmpOuterKey
	} else {
		currentOuter = it.outer.Get(*it.currentOuterKey)
	}

	innerMap := it.getInner(currentOuter)
	if it.currentInnerKey == nil || !innerMap.Contains(*it.currentInnerKey) {
		tmpInnerKey, currentInner, ok = innerMap.First()
		if !ok {
			currentInner = zeroInner
		}
		it.currentInnerKey = &tmpInnerKey
	} else {
		currentInner = innerMap.Get(*it.currentInnerKey)
	}

	//now we have valid current k1/k2, v1/v2, search next
	tmpOuterKey = *it.currentOuterKey
	tmpInnerKey, _, ok = innerMap.Next(*it.currentInnerKey)
	if !ok { //reached end of streams / inner, go to next connection / outer
		var nextOuter V1
		tmpOuterKey, nextOuter, ok = it.outer.Next(*it.currentOuterKey)
		if !ok { // handle wrap
			tmpOuterKey, nextOuter, ok = it.outer.First()
			if !ok { // no elements
				return zeroOuter, zeroInner
			}
		}

		//in any case on next conn /outer, get first stearm /inner
		innerMap = it.getInner(nextOuter)
		tmpInnerKey, _, ok = innerMap.First()
		if !ok { //if an inner is empty, return empty, we handle outside
			currentInner = zeroInner
		}
	}
	it.nextOuterKey = &tmpOuterKey
	it.nextInnerKey = &tmpInnerKey
	return currentOuter, currentInner
}
