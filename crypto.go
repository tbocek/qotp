package qotp

import (
	"crypto/ecdh"
	"errors"
	"log/slog"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

type MsgType int8

const (
	InitSnd MsgType = iota
	InitRcv
	InitCryptoSnd
	InitCryptoRcv
	Data
)

const (
	Version = 0
	MacSize = 16
	SnSize  = 6 // Sequence number Size is 48bit / 6 bytes
	//MinPayloadSize is the minimum payload Size in bytes. We need at least 8 bytes as
	// 8 + the MAC Size (16 bytes) is 24 bytes, which is used as the input for
	// sealing with chacha20poly1305.NewX().
	MinPayloadSize = 8
	PubKeySize     = 32

	HeaderSize         = 1
	ConnIdSize         = 8
	MsgInitFillLenSize = 2

	HeaderConnIdSize        = HeaderSize + ConnIdSize
	MinInitSndSize          = startMtu
	MinInitRcvSizeHdr       = HeaderConnIdSize + (2 * PubKeySize)
	MinInitCryptoSndSizeHdr = HeaderConnIdSize + (2 * PubKeySize)
	MinInitCryptoRcvSizeHdr = HeaderConnIdSize + PubKeySize
	MinDataSizeHdr          = HeaderConnIdSize
	FooterDataSize          = SnSize + MacSize
)

type Message struct {
	MsgType           MsgType
	SnConn            uint64
	currentEpochCrypt uint64
	PayloadRaw        []byte
	SharedSecret      []byte
}

// ************************************* Encoder *************************************

func fillHeaderKey(header []byte, msgType MsgType, pubKeyEpSnd *ecdh.PublicKey, pubKeyEpRcv *ecdh.PublicKey) {
	// Write version
	header[0] = (Version << 3) | uint8(msgType)

	connId := Uint64(pubKeyEpSnd.Bytes())
	if msgType == Data {
		connId = connId ^ Uint64(pubKeyEpRcv.Bytes())
	}

	PutUint64(header[HeaderSize:], connId)
}

func EncodeInitSnd(
	pubKeyIdSnd *ecdh.PublicKey,
	prvKeyEpSnd *ecdh.PrivateKey) (encData []byte) {

	if pubKeyIdSnd == nil || prvKeyEpSnd == nil {
		panic("handshake keys cannot be nil")
	}

	// Create the buffer with the correct size
	headerCryptoDataBuffer := make([]byte, startMtu)

	fillHeaderKey(headerCryptoDataBuffer, InitSnd, prvKeyEpSnd.PublicKey(), nil)

	// Directly copy the isSender's public key to the buffer following the connection ID
	copy(headerCryptoDataBuffer[HeaderConnIdSize:], pubKeyIdSnd.Bytes())

	// Directly copy the ephemeral public key to the buffer following the isSender's public key
	copy(headerCryptoDataBuffer[HeaderConnIdSize+PubKeySize:], prvKeyEpSnd.PublicKey().Bytes())

	return headerCryptoDataBuffer
}

func EncodeInitRcv(
	pubKeyIdRcv *ecdh.PublicKey,
	pubKeyIdSnd *ecdh.PublicKey,
	pubKeyEpRcv *ecdh.PublicKey,
	prvKeyEpSnd *ecdh.PrivateKey,
	snCrypto uint64,
	epochCrypto uint64,
	packetData []byte) (encData []byte, err error) {

	if pubKeyIdRcv == nil || pubKeyIdSnd == nil || pubKeyEpRcv == nil || prvKeyEpSnd == nil {
		panic("handshake keys cannot be nil")
	}

	// Create the buffer with the correct size, INIT_HANDSHAKE_R0 has 3 public keys
	headerWithKeys := make([]byte, MinInitRcvSizeHdr)

	fillHeaderKey(headerWithKeys, InitRcv, pubKeyEpRcv, nil)

	// Directly copy the isSender's public key to the buffer following the connection ID
	copy(headerWithKeys[HeaderConnIdSize:], pubKeyIdSnd.Bytes())

	// Directly copy the ephemeral public key to the buffer following the isSender's public key
	copy(headerWithKeys[HeaderConnIdSize+PubKeySize:], prvKeyEpSnd.PublicKey().Bytes())

	// Perform ECDH for initial encryption
	sharedSecret, err := prvKeyEpSnd.ECDH(pubKeyEpRcv)

	slog.Debug("EncodeInitHandshakeR0 shared secret:", slog.Any("sharedSecret1", sharedSecret))

	if err != nil {
		return nil, err
	}

	// Encrypt and write dataToSend
	return chainedEncrypt(snCrypto, epochCrypto, false, sharedSecret, headerWithKeys, packetData)

}

func EncodeInitCryptoSnd(
	pubKeyIdRcv *ecdh.PublicKey,
	pubKeyIdSnd *ecdh.PublicKey,
	prvKeyEpSnd *ecdh.PrivateKey,
	snCrypto uint64,
	epochCrypto uint64,
	packetData []byte) (encData []byte, err error) {

	if pubKeyIdRcv == nil || pubKeyIdSnd == nil || prvKeyEpSnd == nil {
		panic("handshake keys cannot be nil")
	}

	if len(packetData) < MinPayloadSize {
		return nil, errors.New("packet dataToSend too short")
	}

	// Create the buffer with the correct size, INIT_WITH_CRYPTO_S0 has 3 public keys
	headerWithKeys := make([]byte, MinInitCryptoSndSizeHdr)

	fillHeaderKey(headerWithKeys, InitCryptoSnd, prvKeyEpSnd.PublicKey(), nil)

	// Directly copy the isSender's public key to the buffer following the connection ID
	copy(headerWithKeys[HeaderConnIdSize:], pubKeyIdSnd.Bytes())

	// Directly copy the ephemeral public key to the buffer following the isSender's public key
	copy(headerWithKeys[HeaderConnIdSize+PubKeySize:], prvKeyEpSnd.PublicKey().Bytes())

	// Encrypt and write dataToSend
	fillLen := startMtu - (MinInitCryptoSndSizeHdr + FooterDataSize + MsgInitFillLenSize + len(packetData))

	if fillLen < 0 {
		return nil, errors.New("packet dataToSend cannot be larger than MTU")
	}

	// Create payload with filler length and filler if needed
	paddedPacketData := make([]byte, len(packetData)+MsgInitFillLenSize+fillLen)

	// Add filler length, this is also encrypted
	PutUint16(paddedPacketData, uint16(fillLen))

	// After the filler, copy the dataToSend
	copy(paddedPacketData[2+fillLen:], packetData)

	// Perform ECDH for initial encryption
	nonForwardSecretKey, err := prvKeyEpSnd.ECDH(pubKeyIdRcv)

	if err != nil {
		return nil, err
	}

	return chainedEncrypt(snCrypto, epochCrypto, true, nonForwardSecretKey, headerWithKeys, paddedPacketData)
}

func EncodeInitCryptoRcv(
	pubKeyIdRcv *ecdh.PublicKey,
	pubKeyIdSnd *ecdh.PublicKey,
	pubKeyEpRcv *ecdh.PublicKey,
	prvKeyEpSnd *ecdh.PrivateKey,
	snCrypto uint64,
	epochCrypto uint64,
	packetData []byte) (encData []byte, err error) {

	if pubKeyIdRcv == nil || pubKeyIdSnd == nil || pubKeyEpRcv == nil || prvKeyEpSnd == nil {
		panic("handshake keys cannot be nil")
	}

	if len(packetData) < MinPayloadSize {
		return nil, errors.New("packet dataToSend too short")
	}

	// Create the buffer with the correct size, INIT_WITH_CRYPTO_R0 has 2 public keys
	headerWithKeys := make([]byte, MinInitCryptoRcvSizeHdr)

	fillHeaderKey(headerWithKeys, InitCryptoRcv, pubKeyEpRcv, nil)

	// Directly copy the ephemeral public key to the buffer following the isSender's public key
	copy(headerWithKeys[HeaderConnIdSize:], prvKeyEpSnd.PublicKey().Bytes())

	// Perform ECDH for initial encryption
	sharedSecret, err := prvKeyEpSnd.ECDH(pubKeyEpRcv)

	if err != nil {
		return nil, err
	}

	// Encrypt and write dataToSend
	return chainedEncrypt(snCrypto, epochCrypto, false, sharedSecret, headerWithKeys, packetData)
}

func EncodeData(
	pubKeyEpSnd *ecdh.PublicKey,
	pubKeyEpRcv *ecdh.PublicKey,
	isSender bool,
	sharedSecret []byte,
	snCrypto uint64,
	epochCrypto uint64,
	packetData []byte) (encData []byte, err error) {

	if pubKeyEpSnd == nil || pubKeyEpRcv == nil || sharedSecret == nil {
		panic("pubKeyEpSnd/pubKeyEpRcv keys cannot be nil")
	}

	if len(packetData) < MinPayloadSize {
		return nil, errors.New("packet dataToSend too short")
	}

	// Create the buffer with the correct size, DATA_0 has no public key
	headerBuffer := make([]byte, HeaderConnIdSize)

	fillHeaderKey(headerBuffer, Data, pubKeyEpSnd, pubKeyEpRcv)

	// Encrypt and write dataToSend
	return chainedEncrypt(snCrypto, epochCrypto, isSender, sharedSecret, headerBuffer, packetData)
}

func chainedEncrypt(snCrypt uint64, epochConn uint64, isSender bool, sharedSecret []byte, headerAndCrypto []byte, packetData []byte) (encData []byte, err error) {
	if len(packetData) < 8 {
		return nil, errors.New("dataToSend too short")
	}

	nonceDet := make([]byte, chacha20poly1305.NonceSize)

	PutUint48(nonceDet, epochConn)
	PutUint48(nonceDet[6:], snCrypt)

	if !isSender {
		// set first (highest) bit to 0
		nonceDet[0] = nonceDet[0] &^ 0x80 // bit clear
	} else {
		// set first (highest) bit to 1
		nonceDet[0] = nonceDet[0] | 0x80 // bit set
	}

	slog.Debug(" ENCRY", getGoroutineID(), slog.Any("nonce", nonceDet), slog.Bool("isSender", isSender))
	aead, err := chacha20poly1305.New(sharedSecret)
	if err != nil {
		return nil, err
	}
	sealed := aead.Seal(nil, nonceDet, packetData, headerAndCrypto)

	encData = make([]byte, len(headerAndCrypto)+SnSize+len(sealed))
	copy(encData, headerAndCrypto)

	aeadSn, err := chacha20poly1305.NewX(sharedSecret)
	if err != nil {
		return nil, err
	}

	nonceRand := sealed[0:24]
	encSn := aeadSn.Seal(nil, nonceRand, nonceDet[6:12], nil)
	copy(encData[len(headerAndCrypto):], encSn[:SnSize])
	copy(encData[len(headerAndCrypto)+SnSize:], sealed)

	// Write the full message in one operation
	return encData, nil
}

// ************************************* Decoder *************************************

func decodeHeader(encData []byte) (connId uint64, msgType MsgType, err error) {
	// Read the header byte and connId
	if len(encData) < HeaderConnIdSize {
		return 0, 0, errors.New("header needs to be at least 8 bytes")
	}

	header := encData[0]
	version := header >> 3

	if version != Version {
		return 0, 0, errors.New("unsupported version version")
	}

	msgType = MsgType(header & 0x07)
	connId = Uint64(encData[HeaderSize:HeaderConnIdSize])

	return connId, msgType, nil
}

func DecodeInitSnd(encData []byte, prvKeyEpRcv *ecdh.PrivateKey) (
	pubKeyIdSnd *ecdh.PublicKey,
	pubKeyEpSnd *ecdh.PublicKey,
	m *Message,
	err error) {

	if len(encData) < MinInitSndSize {
		return nil, nil, nil, errors.New("size is below minimum init")
	}

	pubKeyIdSnd, err = ecdh.X25519().NewPublicKey(encData[HeaderConnIdSize : HeaderConnIdSize+PubKeySize])
	if err != nil {
		return nil, nil, nil, err
	}

	pubKeyEpSnd, err = ecdh.X25519().NewPublicKey(encData[HeaderConnIdSize+PubKeySize : HeaderConnIdSize+(2*PubKeySize)])
	if err != nil {
		return nil, nil, nil, err
	}

	sharedSecret, err := prvKeyEpRcv.ECDH(pubKeyEpSnd)

	if err != nil {
		return nil, nil, nil, err
	}

	return pubKeyIdSnd, pubKeyEpSnd, &Message{
		MsgType:      InitSnd,
		SharedSecret: sharedSecret,
		SnConn:       0,
	}, nil
}

func DecodeInitRcv(encData []byte, prvKeyEpSnd *ecdh.PrivateKey) (
	pubKeyIdRcv *ecdh.PublicKey,
	pubKeyEpRcv *ecdh.PublicKey,
	m *Message,
	err error) {

	if len(encData) < MinInitRcvSizeHdr+FooterDataSize {
		return nil, nil, nil, errors.New("size is below minimum init reply")
	}

	pubKeyIdRcv, err = ecdh.X25519().NewPublicKey(encData[HeaderConnIdSize : HeaderConnIdSize+PubKeySize])
	if err != nil {
		return nil, nil, nil, err
	}

	pubKeyEpRcv, err = ecdh.X25519().NewPublicKey(encData[HeaderConnIdSize+PubKeySize : HeaderConnIdSize+2*PubKeySize])
	if err != nil {
		return nil, nil, nil, err
	}

	sharedSecret, err := prvKeyEpSnd.ECDH(pubKeyEpRcv)

	slog.Debug("EncodeInitHandshakeR0 shared secret:", slog.Any("sharedSecret2", sharedSecret))

	if err != nil {
		return nil, nil, nil, err
	}

	snConn, currentEpochCrypt, packetData, err := chainedDecrypt(
		true,
		0,
		sharedSecret,
		encData[0:HeaderConnIdSize+(2*PubKeySize)],
		encData[HeaderConnIdSize+(2*PubKeySize):],
	)
	if err != nil {
		return nil, nil, nil, err
	}

	return pubKeyIdRcv, pubKeyEpRcv, &Message{
		MsgType:           InitRcv,
		PayloadRaw:        packetData,
		SharedSecret:      sharedSecret,
		SnConn:            snConn,
		currentEpochCrypt: currentEpochCrypt,
	}, nil

}

func DecodeInitCryptoSnd(
	encData []byte,
	prvKeyIdRcv *ecdh.PrivateKey,
	prvKeyEpRcv *ecdh.PrivateKey) (
	pubKeyIdSnd *ecdh.PublicKey,
	pubKeyEpSnd *ecdh.PublicKey,
	m *Message,
	err error) {

	if len(encData) < MinInitSndSize {
		return nil, nil, nil, errors.New("size is below minimum init")
	}

	pubKeyIdSnd, err = ecdh.X25519().NewPublicKey(encData[HeaderConnIdSize : HeaderConnIdSize+PubKeySize])
	if err != nil {
		return nil, nil, nil, err
	}

	pubKeyEpSnd, err = ecdh.X25519().NewPublicKey(encData[HeaderConnIdSize+PubKeySize : HeaderConnIdSize+(2*PubKeySize)])
	if err != nil {
		return nil, nil, nil, err
	}

	nonForwardSecretKey, err := prvKeyIdRcv.ECDH(pubKeyEpSnd)

	if err != nil {
		return nil, nil, nil, err
	}

	snConn, currentEpochCrypt, packetData, err := chainedDecrypt(
		false,
		0,
		nonForwardSecretKey,
		encData[0:HeaderConnIdSize+(2*PubKeySize)],
		encData[HeaderConnIdSize+(2*PubKeySize):],
	)
	if err != nil {
		return nil, nil, nil, err
	}

	sharedSecret, err := prvKeyEpRcv.ECDH(pubKeyEpSnd)

	if err != nil {
		return nil, nil, nil, err
	}

	// Extract actual dataToSend - Remove filler_length and filler
	fillerLen := Uint16(packetData)
	actualData := packetData[2+int(fillerLen):]

	return pubKeyIdSnd, pubKeyEpSnd, &Message{
		MsgType:           InitCryptoSnd,
		PayloadRaw:        actualData,
		SharedSecret:      sharedSecret,
		SnConn:            snConn,
		currentEpochCrypt: currentEpochCrypt,
	}, nil
}

// DecodeInitCryptoRcv is decoded by the isSender
func DecodeInitCryptoRcv(
	encData []byte,
	prvKeyEpSnd *ecdh.PrivateKey) (
	pubKeyEpRcv *ecdh.PublicKey,
	m *Message,
	err error) {

	if len(encData) < MinInitCryptoRcvSizeHdr+FooterDataSize {
		return nil, nil, errors.New("size is below minimum init reply")
	}

	pubKeyEpRcv, err = ecdh.X25519().NewPublicKey(encData[HeaderConnIdSize : HeaderConnIdSize+PubKeySize])
	if err != nil {
		return nil, nil, err
	}

	sharedSecret, err := prvKeyEpSnd.ECDH(pubKeyEpRcv)
	if err != nil {
		return nil, nil, err
	}

	snConn, currentEpochCrypt, packetData, err := chainedDecrypt(
		true,
		0,
		sharedSecret,
		encData[0:HeaderConnIdSize+PubKeySize],
		encData[HeaderConnIdSize+PubKeySize:],
	)
	if err != nil {
		return nil, nil, err
	}
	if snConn != 0 {
		return nil, nil, errors.New("sn must be 0")
	}

	return pubKeyEpRcv, &Message{
		MsgType:           InitCryptoRcv,
		PayloadRaw:        packetData,
		SharedSecret:      sharedSecret,
		SnConn:            snConn,
		currentEpochCrypt: currentEpochCrypt,
	}, nil
}

func DecodeData(
	encData []byte,
	isSender bool,
	epochCrypt uint64,
	sharedSecret []byte) (*Message, error) {

	if len(encData) < MinDataSizeHdr+FooterDataSize {
		return nil, errors.New("size is below minimum")
	}

	snConn, currentEpochCrypt, packetData, err := chainedDecrypt(
		isSender,
		epochCrypt,
		sharedSecret,
		encData[0:HeaderConnIdSize],
		encData[HeaderConnIdSize:],
	)
	if err != nil {
		return nil, err
	}

	return &Message{
		MsgType:           Data,
		PayloadRaw:        packetData,
		SnConn:            snConn,
		currentEpochCrypt: currentEpochCrypt,
	}, nil
}

func chainedDecrypt(isSender bool, epochCrypt uint64, sharedSecret []byte, header []byte, encData []byte) (snConn uint64, currentEpochCrypt uint64, packetData []byte, err error) {
	if len(encData) < 24 { // 8 bytes for encSn + 24 bytes for nonceRand
		return 0, 0, nil, errors.New("encrypted dataToSend too short")
	}

	snConnBytes := make([]byte, SnSize)

	encSn := encData[0:SnSize]
	encData = encData[SnSize:]
	nonceRand := encData[:24]
	snConnBytes, err = openNoVerify(sharedSecret, nonceRand, encSn, snConnBytes)
	if err != nil {
		return 0, 0, nil, err
	}
	snConn = Uint48(snConnBytes)

	nonceDet := make([]byte, chacha20poly1305.NonceSize)

	epochs := []uint64{epochCrypt}
	// Only try previous epoch if > 0
	if epochCrypt > 0 {
		epochs = append(epochs, epochCrypt-1)
	}
	epochs = append(epochs, epochCrypt+1)

	aead, err := chacha20poly1305.New(sharedSecret)
	if err != nil {
		return 0, 0, nil, err
	}
	PutUint48(nonceDet[6:], snConn)

	for _, epochTry := range epochs {
		PutUint48(nonceDet, epochTry)
		if isSender {
			// set first (highest) bit to 0
			nonceDet[0] = nonceDet[0] &^ 0x80 // bit clear
		} else {
			// set first (highest) bit to 1
			nonceDet[0] = nonceDet[0] | 0x80 // bit set
		}

		slog.Debug(" DECRC", getGoroutineID(), slog.Any("nonce", nonceDet), slog.Bool("isSender", isSender))
		packetData, err = aead.Open(nil, nonceDet, encData, header)
		if err == nil {
			//TODO if we are at epochCrypt + 1 -> make this the new epochCrypt
			return snConn, epochTry, packetData, nil
		}
	}
	return 0, 0, nil, err
}

// inspired by: https://github.com/golang/crypto/blob/master/chacha20poly1305/chacha20poly1305_generic.go
func openNoVerify(sharedSecret []byte, nonce []byte, encoded []byte, snSer []byte) ([]byte, error) {
	s, err := chacha20.NewUnauthenticatedCipher(sharedSecret, nonce)
	if err != nil {
		return nil, err
	}
	s.SetCounter(1) // Set the counter to 1, skipping 32 bytes

	// Decrypt the ciphertext
	s.XORKeyStream(snSer, encoded)

	return snSer, nil
}
