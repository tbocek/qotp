package qotp

import "iter"

// NestedIterator returns an iterator through nested maps using Go 1.23+ iter.Seq2
func NestedIterator[K1, K2 comparable, V1, V2 any](
	outerMap *LinkedMap[K1, V1],
	getInnerMap func(V1) *LinkedMap[K2, V2],
) iter.Seq2[V1, V2] {
	return func(yield func(V1, V2) bool) {
		for _, outerVal := range outerMap.Iterator() {
			innerMap := getInnerMap(outerVal)
			if innerMap == nil {
				continue
			}
			for _, innerVal := range innerMap.Iterator() {
				if !yield(outerVal, innerVal) {
					return
				}
			}
		}
	}
}