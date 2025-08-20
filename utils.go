package qotp

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"golang.org/x/sys/unix"
	"log/slog"
	"math"
	"net"
	"reflect"
	"runtime"
	"strings"
	"time"
)

// based on: https://github.com/quic-go/quic-go/blob/d540f545b0b70217220eb0fbd5278ece436a7a20/sys_conn_df_linux.go#L15
func setDF(conn *net.UDPConn) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}

	var errDFIPv4, errDFIPv6 error
	if err := rawConn.Control(func(fd uintptr) {
		errDFIPv4 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
		errDFIPv6 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DO)
	}); err != nil {
		return err
	}

	switch {
	case errDFIPv4 == nil && errDFIPv6 == nil:
		slog.Info("setting DF for IPv4 and IPv6")
		//TODO: expose this and don't probe for higher MTU when not DF not supported
	case errDFIPv4 == nil && errDFIPv6 != nil:
		slog.Info("setting DF for IPv4 only")
	case errDFIPv4 != nil && errDFIPv6 == nil:
		slog.Info("setting DF for IPv6 only")
	case errDFIPv4 != nil && errDFIPv6 != nil:
		slog.Error("setting DF failed for both IPv4 and IPv6")
	}

	return nil
}

func debugGId() slog.Attr {
	buf := make([]byte, 64)
	n := runtime.Stack(buf, false)
	buf = buf[:n]
	idField := bytes.Fields(buf)[1]
	var id int64
	fmt.Sscanf(string(idField), "%d", &id)
	return slog.String("gid", fmt.Sprintf("0x%02x", id))
}

func PutUint16(b []byte, v uint16) int {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	return 2
}

func PutUint24(b []byte, v uint64) int {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	return 3
}

func PutUint32(b []byte, v uint32) int {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	return 4
}

func PutUint48(b []byte, v uint64) int {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	b[4] = byte(v >> 32)
	b[5] = byte(v >> 40)
	return 6
}

func PutUint64(b []byte, v uint64) int {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	b[4] = byte(v >> 32)
	b[5] = byte(v >> 40)
	b[6] = byte(v >> 48)
	b[7] = byte(v >> 56)
	return 8
}

func Uint16(b []byte) uint16 {
	return uint16(b[0]) | uint16(b[1])<<8
}

func Uint24(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16
}

func Uint32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func Uint48(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 |
		uint64(b[3])<<24 | uint64(b[4])<<32 | uint64(b[5])<<40
}

func Uint64(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

func isNil(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	return rv.Kind() == reflect.Ptr && rv.IsNil()
}

func decodeHex(pubKeyHex string) ([]byte, error) {
	if strings.HasPrefix(pubKeyHex, "0x") {
		pubKeyHex = strings.Replace(pubKeyHex, "0x", "", 1)
	}

	return hex.DecodeString(pubKeyHex)
}

func decodeHexPubKey(pubKeyHex string) (pubKey *ecdh.PublicKey, err error) {
	b, err := decodeHex(pubKeyHex)
	if err != nil {
		return nil, err
	}

	pubKey, err = ecdh.X25519().NewPublicKey(b)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

func generateTwoKeys() (*ecdh.PrivateKey, *ecdh.PrivateKey, error) {
	prvKey1, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	prvKey2, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return prvKey1, prvKey2, nil
}

var specificNano uint64 = math.MaxUint64

func setTime(nowNano uint64) {
	if nowNano <= specificNano {
		slog.Warn("Time/Warp/Fail", 
			slog.Uint64("before:ms", specificNano/msNano), 
			slog.Uint64("after:ms", nowNano/msNano))	
		return
	}
	slog.Debug("Time/Warp/Manual", 
		slog.Uint64("+:ms", (nowNano - specificNano)/msNano), 
		slog.Uint64("before:ms", specificNano/msNano), 
		slog.Uint64("after:ms", nowNano/msNano))
	specificNano = nowNano
	}

func timeNowNano() uint64 {
	if specificNano == math.MaxUint64 {
		return uint64(time.Now().UnixNano())
	}
	return specificNano
}

func debug(msg string, keysAndValues ...any) {
	if len(keysAndValues)%2 != 0 {
		panic("debug requires even number of arguments (key-value pairs)")
	}
	
	attrs := make([]any, 0, len(keysAndValues)/2)
	for i := 0; i < len(keysAndValues); i += 2 {
		key := keysAndValues[i].(string)
		value := keysAndValues[i+1]
		attrs = append(attrs, slog.Any(key, value))
	}
	slog.Debug(msg, attrs...)
}
