package qotp

import (
	"crypto/ecdh"
	"crypto/rand"
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

	MinInitSndSize          = startMtu
	MinInitRcvSizeHdr       = HeaderSize + ConnIdSize + (2 * PubKeySize)
	MinInitCryptoSndSizeHdr = HeaderSize + (2 * PubKeySize)
	MinInitCryptoRcvSizeHdr = HeaderSize + ConnIdSize + PubKeySize
	MinDataSizeHdr          = HeaderSize + ConnIdSize
	FooterDataSize          = SnSize + MacSize

	MinPacketSize = MinDataSizeHdr + FooterDataSize + MinPayloadSize
)

type Message struct {
	MsgType           MsgType
	SnConn            uint64
	currentEpochCrypt uint64
	PayloadRaw        []byte
}

// ************************************* Encoder *************************************

func EncodeInitSnd(
	pubKeyIdSnd *ecdh.PublicKey,
	prvKeyEpSnd *ecdh.PrivateKey) (encData []byte) {

	if pubKeyIdSnd == nil || prvKeyEpSnd == nil {
		panic("handshake keys cannot be nil")
	}

	// Create the buffer with the correct size
	headerCryptoDataBuffer := make([]byte, startMtu)

	headerCryptoDataBuffer[0] = (Version << 3) | uint8(InitSnd)

	// Directly copy the isSender's public key to the buffer following the connection ID
	copy(headerCryptoDataBuffer[HeaderSize:], pubKeyIdSnd.Bytes())

	// Directly copy the ephemeral public key to the buffer following the isSender's public key
	copy(headerCryptoDataBuffer[HeaderSize+PubKeySize:], prvKeyEpSnd.PublicKey().Bytes())

	return headerCryptoDataBuffer
}

func EncodeInitRcv(
	pubKeyIdRcv *ecdh.PublicKey,
	pubKeyIdSnd *ecdh.PublicKey,
	pubKeyEpRcv *ecdh.PublicKey,
	prvKeyEpSnd *ecdh.PrivateKey,
	snCrypto uint64,
	packetData []byte) (encData []byte, err error) {

	if pubKeyIdRcv == nil || pubKeyIdSnd == nil || pubKeyEpRcv == nil || prvKeyEpSnd == nil {
		panic("handshake keys cannot be nil")
	}

	// Create the buffer with the correct size, INIT_HANDSHAKE_R0 has 3 public keys
	headerWithKeys := make([]byte, MinInitRcvSizeHdr)

	headerWithKeys[0] = (Version << 3) | uint8(InitRcv)
	copy(headerWithKeys[HeaderSize:], pubKeyEpRcv.Bytes()[0:ConnIdSize])

	// Directly copy the isSender's public key to the buffer following the connection ID
	copy(headerWithKeys[HeaderSize+ConnIdSize:], pubKeyIdSnd.Bytes())

	// Directly copy the ephemeral public key to the buffer following the isSender's public key
	copy(headerWithKeys[HeaderSize+ConnIdSize+PubKeySize:], prvKeyEpSnd.PublicKey().Bytes())

	// Perform ECDH for initial encryption
	sharedSecret, err := prvKeyEpSnd.ECDH(pubKeyEpRcv)

	slog.Debug("EncodeInitHandshakeR0 shared secret:", slog.Any("sharedSecret1", sharedSecret))

	if err != nil {
		return nil, err
	}

	// Encrypt and write dataToSend
	return chainedEncrypt(snCrypto, 0, false, sharedSecret, headerWithKeys, packetData)

}

func EncodeInitCryptoSnd(
	pubKeyIdRcv *ecdh.PublicKey,
	pubKeyIdSnd *ecdh.PublicKey,
	prvKeyEpSnd *ecdh.PrivateKey,
	snCrypto uint64,
	packetData []byte) (encData []byte, err error) {

	if pubKeyIdRcv == nil || pubKeyIdSnd == nil || prvKeyEpSnd == nil {
		panic("handshake keys cannot be nil")
	}

	if len(packetData) < MinPayloadSize {
		return nil, errors.New("packet dataToSend too short")
	}

	// Create the buffer with the correct size, INIT_WITH_CRYPTO_S0 has 3 public keys
	headerWithKeys := make([]byte, MinInitCryptoSndSizeHdr)

	headerWithKeys[0] = (Version << 3) | uint8(InitCryptoSnd)

	// Directly copy the isSender's public key to the buffer following the connection ID
	copy(headerWithKeys[HeaderSize:], pubKeyIdSnd.Bytes())

	// Directly copy the ephemeral public key to the buffer following the isSender's public key
	copy(headerWithKeys[HeaderSize+PubKeySize:], prvKeyEpSnd.PublicKey().Bytes())

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

	return chainedEncrypt(snCrypto, 0, true, nonForwardSecretKey, headerWithKeys, paddedPacketData)
}

func EncodeInitCryptoRcv(
	pubKeyIdRcv *ecdh.PublicKey,
	pubKeyIdSnd *ecdh.PublicKey,
	pubKeyEpRcv *ecdh.PublicKey,
	prvKeyEpSnd *ecdh.PrivateKey,
	snCrypto uint64,
	packetData []byte) (encData []byte, err error) {

	if pubKeyIdRcv == nil || pubKeyIdSnd == nil || pubKeyEpRcv == nil || prvKeyEpSnd == nil {
		panic("handshake keys cannot be nil")
	}

	if len(packetData) < MinPayloadSize {
		return nil, errors.New("packet dataToSend too short")
	}

	// Create the buffer with the correct size, INIT_WITH_CRYPTO_R0 has 2 public keys
	headerWithKeys := make([]byte, MinInitCryptoRcvSizeHdr)

	headerWithKeys[0] = (Version << 3) | uint8(InitCryptoRcv)
	copy(headerWithKeys[HeaderSize:], pubKeyEpRcv.Bytes()[0:ConnIdSize])

	// Directly copy the ephemeral public key to the buffer following the isSender's public key
	copy(headerWithKeys[HeaderSize+ConnIdSize:], prvKeyEpSnd.PublicKey().Bytes())

	// Perform ECDH for initial encryption
	sharedSecret, err := prvKeyEpSnd.ECDH(pubKeyEpRcv)

	if err != nil {
		return nil, err
	}

	// Encrypt and write dataToSend
	return chainedEncrypt(snCrypto, 0, false, sharedSecret, headerWithKeys, packetData)
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
	headerBuffer := make([]byte, HeaderSize+ConnIdSize)

	headerBuffer[0] = (Version << 3) | uint8(Data)
	if isSender {
		copy(headerBuffer[HeaderSize:], pubKeyEpSnd.Bytes()[0:ConnIdSize])
	} else {
		copy(headerBuffer[HeaderSize:], pubKeyEpRcv.Bytes()[0:ConnIdSize])
	}

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

func decodeHeader(encData []byte) (msgType MsgType, err error) {
	// Read the header byte and connId
	if len(encData) < MinPacketSize {
		return 0, errors.New("header needs to be at least 8 bytes")
	}

	header := encData[0]
	version := header >> 3

	if version != Version {
		return 0, errors.New("unsupported version version")
	}

	msgType = MsgType(header & 0x07)

	return msgType, nil
}

func DecodeInitSnd(encData []byte) (
	connId uint64,
	pubKeyIdSnd *ecdh.PublicKey,
	pubKeyEpSnd *ecdh.PublicKey,
	m *Message,
	err error) {

	if len(encData) < MinInitSndSize {
		return 0, nil, nil, nil, errors.New("size is below minimum init")
	}

	pubKeyIdSnd, err = ecdh.X25519().NewPublicKey(encData[HeaderSize : HeaderSize+PubKeySize])
	if err != nil {
		return 0, nil, nil, nil, err
	}

	pubKeyEpSnd, err = ecdh.X25519().NewPublicKey(encData[HeaderSize+PubKeySize : HeaderSize+(2*PubKeySize)])
	if err != nil {
		return 0, nil, nil, nil, err
	}

	if err != nil {
		return 0, nil, nil, nil, err
	}

	return Uint64(pubKeyEpSnd.Bytes()[0:ConnIdSize]), pubKeyIdSnd, pubKeyEpSnd, &Message{
		MsgType: InitSnd,
		SnConn: 0,
	}, nil
}

func DecodeInitRcv(encData []byte, prvKeyEpSnd *ecdh.PrivateKey) (
	sharedSecret []byte,
	pubKeyIdRcv *ecdh.PublicKey,
	pubKeyEpRcv *ecdh.PublicKey,
	m *Message,
	err error) {

	if len(encData) < MinInitRcvSizeHdr+FooterDataSize {
		return nil, nil, nil, nil, errors.New("size is below minimum init reply")
	}

	pubKeyIdRcv, err = ecdh.X25519().NewPublicKey(encData[HeaderSize+ConnIdSize : HeaderSize+ConnIdSize+PubKeySize])
	if err != nil {
		return nil, nil, nil, nil, err
	}

	pubKeyEpRcv, err = ecdh.X25519().NewPublicKey(encData[HeaderSize+ConnIdSize+PubKeySize : HeaderSize+ConnIdSize+2*PubKeySize])
	if err != nil {
		return nil, nil, nil, nil, err
	}

	sharedSecret, err = prvKeyEpSnd.ECDH(pubKeyEpRcv)

	slog.Debug("EncodeInitHandshakeR0 shared secret:", slog.Any("sharedSecret2", sharedSecret))

	if err != nil {
		return nil, nil, nil, nil, err
	}

	snConn, currentEpochCrypt, packetData, err := chainedDecrypt(
		true,
		0,
		sharedSecret,
		encData[0:HeaderSize+ConnIdSize+(2*PubKeySize)],
		encData[HeaderSize+ConnIdSize+(2*PubKeySize):],
	)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return sharedSecret, pubKeyIdRcv, pubKeyEpRcv, &Message{
		MsgType:           InitRcv,
		PayloadRaw:        packetData,
		SnConn:            snConn,
		currentEpochCrypt: currentEpochCrypt,
	}, nil

}

func DecodeInitCryptoSnd(
	encData []byte,
	prvKeyIdRcv *ecdh.PrivateKey) (
	connId uint64,
	pubKeyIdSnd *ecdh.PublicKey,
	pubKeyEpSnd *ecdh.PublicKey,
	m *Message,
	err error) {

	if len(encData) < MinInitSndSize {
		return 0, nil, nil, nil, errors.New("size is below minimum init")
	}

	pubKeyIdSnd, err = ecdh.X25519().NewPublicKey(encData[HeaderSize : HeaderSize+PubKeySize])
	if err != nil {
		return 0, nil, nil, nil, err
	}

	pubKeyEpSnd, err = ecdh.X25519().NewPublicKey(encData[HeaderSize+PubKeySize : HeaderSize+(2*PubKeySize)])
	if err != nil {
		return 0, nil, nil, nil, err
	}

	nonForwardSecretKey, err := prvKeyIdRcv.ECDH(pubKeyEpSnd)

	if err != nil {
		return 0, nil, nil, nil, err
	}

	snConn, currentEpochCrypt, packetData, err := chainedDecrypt(
		false,
		0,
		nonForwardSecretKey,
		encData[0:HeaderSize+(2*PubKeySize)],
		encData[HeaderSize+(2*PubKeySize):],
	)
	if err != nil {
		return 0, nil, nil, nil, err
	}

	if err != nil {
		return 0, nil, nil, nil, err
	}

	// Extract actual dataToSend - Remove filler_length and filler
	fillerLen := Uint16(packetData)
	actualData := packetData[2+int(fillerLen):]

	return Uint64(pubKeyEpSnd.Bytes()[0:ConnIdSize]), pubKeyIdSnd, pubKeyEpSnd, &Message{
		MsgType:           InitCryptoSnd,
		PayloadRaw:        actualData,
		SnConn:            snConn,
		currentEpochCrypt: currentEpochCrypt,
	}, nil
}

// DecodeInitCryptoRcv is decoded by the isSender
func DecodeInitCryptoRcv(
	encData []byte,
	prvKeyEpSnd *ecdh.PrivateKey) (
	sharedSecret []byte,
	pubKeyEpRcv *ecdh.PublicKey,
	m *Message,
	err error) {

	if len(encData) < MinInitCryptoRcvSizeHdr+FooterDataSize {
		return nil, nil, nil, errors.New("size is below minimum init reply")
	}

	pubKeyEpRcv, err = ecdh.X25519().NewPublicKey(encData[HeaderSize+ConnIdSize : HeaderSize+ConnIdSize+PubKeySize])
	if err != nil {
		return nil, nil, nil, err
	}

	sharedSecret, err = prvKeyEpSnd.ECDH(pubKeyEpRcv)
	if err != nil {
		return nil, nil, nil, err
	}

	snConn, currentEpochCrypt, packetData, err := chainedDecrypt(
		true,
		0,
		sharedSecret,
		encData[0:HeaderSize+ConnIdSize+PubKeySize],
		encData[HeaderSize+ConnIdSize+PubKeySize:],
	)
	if err != nil {
		return nil, nil, nil, err
	}
	if snConn != 0 {
		return nil, nil, nil, errors.New("sn must be 0")
	}

	return sharedSecret, pubKeyEpRcv, &Message{
		MsgType:           InitCryptoRcv,
		PayloadRaw:        packetData,
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
		encData[0:HeaderSize + ConnIdSize],
		encData[HeaderSize + ConnIdSize:],
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

func generateKey() (*ecdh.PrivateKey, error) {
	prvKey1, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return prvKey1, nil
}