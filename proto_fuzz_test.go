package qotp

import (
	"math"
	"reflect"
	"testing"
)

func FuzzPayload(f *testing.F) {
    // Add seed corpus with valid and edge case payloads
    payloads := []*PayloadHeader{
        {
            StreamID:     1,
            StreamOffset: 100,
            RcvWndSize:   1000,
            Ack:          &Ack{streamID: 10, offset: 200, len: 10},
        },
        {
            StreamID:     math.MaxUint32,
            StreamOffset: math.MaxUint64,
        },
    }

    for _, p := range payloads {
        originalData := []byte("test data")
        encoded := encodePayload(p, originalData)
        f.Add(encoded)
    }

    f.Fuzz(func(t *testing.T, data []byte) {
        decoded, payloadData, err := DecodePayload(data)
        if err != nil {
            t.Skip()
        }

        reEncoded := encodePayload(decoded, payloadData)
        reDecoded, reDecodedData, err := DecodePayload(reEncoded)
        if err != nil {
        	t.Fatal("Failed to decode our own encoded data:", err)
        }

        if !reflect.DeepEqual(decoded, reDecoded) || !reflect.DeepEqual(payloadData, reDecodedData) {
            t.Fatal("re-encoded/decoded payload differs from original")
        }
    })
}