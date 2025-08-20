package qotp

// NestedIterator iterates through nested maps
type NestedIterator[K1, K2 comparable, V1, V2 any] struct {
	outer    *LinkedMap[K1, V1]
	getInner func(V1) *LinkedMap[K2, V2]
	currentK1   *K1
	currentK2   *K2
	nextK1   *K1
	nextK2   *K2
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
func (it *NestedIterator[K1, K2, V1, V2]) Next() (currentV1 V1, currentV2 V2) {
	var ok bool
	var zeroV1 V1
	var zeroV2 V2
	var tmpK1 K1
	var tmpK2 K2
	
	if it.nextK1 != nil {
		it.currentK1 = it.nextK1
	}
	
	if it.nextK2 != nil {
		it.currentK2 = it.nextK2
	}
	
	if it.currentK1 == nil || !it.outer.Contains(*it.currentK1) {
		tmpK1, currentV1, ok = it.outer.First()
		if !ok {
			return zeroV1, zeroV2
		}
		it.currentK1 = &tmpK1
	} else {
		currentV1 = it.outer.Get(*it.currentK1)
	}

	innerMap := it.getInner(currentV1)
	if it.currentK2 == nil || !innerMap.Contains(*it.currentK2) {
		tmpK2, currentV2, ok = innerMap.First()
		if !ok {
			currentV2 = zeroV2
		}
		it.currentK2 = &tmpK2
	} else {
		currentV2 = innerMap.Get(*it.currentK2)
	}

	//now we have valid current k1/k2, v1/v2, search next
	tmpK1 = *it.currentK1
	tmpK2, _, ok = innerMap.Next(*it.currentK2)
	if !ok { //reached end of streams / inner, go to next connection / outer
		var nextV1 V1
		tmpK1, nextV1, ok = it.outer.Next(*it.currentK1)
		if !ok { // handle wrap
			tmpK1, nextV1, ok = it.outer.First()
			if !ok { // no elements
				return zeroV1, zeroV2
			}
		}

		//in any case on next conn /outer, get first stearm /inner
		innerMap = it.getInner(nextV1)
		tmpK2, _, ok = innerMap.First()
		if !ok { //if an inner is empty, return empty, we handle outside
			currentV2 = zeroV2
		}
	}
	it.nextK1 = &tmpK1
	it.nextK2 = &tmpK2
	return currentV1, currentV2
}
