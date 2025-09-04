package qotp

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

// Helper functions
func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

func generateKeys(t *testing.T) *ecdh.PrivateKey {
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	return privKey
}

// EncryptionTestSuite - Tests for encryption/decryption functionality
type EncryptionTestSuite struct {
	suite.Suite
}

func (suite *EncryptionTestSuite) TestDoubleEncryptDecryptShortData() {
	suite.testDoubleEncryptDecrypt(1234567890, randomBytes(10), []byte("AAD"))
}

func (suite *EncryptionTestSuite) TestDoubleEncryptDecryptLongData() {
	suite.testDoubleEncryptDecrypt(987654321, randomBytes(100), randomBytes(100))
}

func (suite *EncryptionTestSuite) TestDoubleEncryptDecryptLongDataShortAAD() {
	suite.testDoubleEncryptDecrypt(1, randomBytes(100), []byte(""))
}

func (suite *EncryptionTestSuite) TestDoubleEncryptDecryptMinData() {
	suite.testDoubleEncryptDecrypt(2, randomBytes(9), []byte("Only AAD"))
}

func (suite *EncryptionTestSuite) TestDoubleEncryptDecryptMinData2() {
	suite.testDoubleEncryptDecrypt(2, randomBytes(9), []byte(""))
}

func (suite *EncryptionTestSuite) TestDoubleEncryptDecryptEmptyData() {
	suite.testDoubleEncryptDecrypt(1111111111, []byte{}, []byte("Only AAD"))
}

func (suite *EncryptionTestSuite) testDoubleEncryptDecrypt(sn uint64, data []byte, additionalData []byte) {
	sharedSecret := make([]byte, 32)
	if _, err := rand.Read(sharedSecret); err != nil {
		suite.T().Fatalf("Failed to generate shared secret: %v", err)
	}

	buf, err := chainedEncrypt(sn, 0, true, sharedSecret, additionalData, data)
	// too short
	if len(data) < MinPayloadSize {
		assert.NotNil(suite.T(), err)
		return
	}
	assert.Nil(suite.T(), err)

	if len(buf) == 0 {
		suite.T().Fatalf("No encrypted dataToSend written")
	}
	suite.T().Logf("Encrypted dataToSend: %s", hex.EncodeToString(buf))

	decryptedSn, decryptedEpoch, decryptedData, err := chainedDecrypt(false, 0, sharedSecret, buf[0:len(additionalData)], buf[len(additionalData):])
	assert.Nil(suite.T(), err)

	assert.Equal(suite.T(), uint64(0), decryptedEpoch)
	assert.Equal(suite.T(), sn, decryptedSn)
	assert.Equal(suite.T(), data, decryptedData)
}

func (suite *EncryptionTestSuite) TestSecretKey() {
	bobPrvKeyId, err := ecdh.X25519().GenerateKey(rand.Reader)
	assert.Nil(suite.T(), err)
	bobPubKeyId := bobPrvKeyId.PublicKey()
	alicePrvKeyEp, err := ecdh.X25519().GenerateKey(rand.Reader)
	assert.Nil(suite.T(), err)
	alicePubKeyEp := alicePrvKeyEp.PublicKey()

	secret1, err := bobPrvKeyId.ECDH(alicePubKeyEp)
	assert.Nil(suite.T(), err)
	secret2, err := alicePrvKeyEp.ECDH(bobPubKeyId)
	assert.Nil(suite.T(), err)

	assert.Equal(suite.T(), secret1, secret2)
}

func TestCryptoEncryptionSuite(t *testing.T) {
	suite.Run(t, new(EncryptionTestSuite))
}

// InitCryptoTestSuite - Tests for InitCrypto message encoding/decoding
type InitCryptoTestSuite struct {
	suite.Suite
}

func (suite *InitCryptoTestSuite) TestEncodeDecodeInitCryptoSndShortPayload() {
	suite.testEncodeDecodeInitCryptoSnd([]byte("short1234"))
}

func (suite *InitCryptoTestSuite) TestEncodeDecodeInitCryptoSndLongPayload() {
	suite.testEncodeDecodeInitCryptoSnd(randomBytes(100))
}

func (suite *InitCryptoTestSuite) TestEncodeDecodeInitCryptoSndMaxPayload() {
	suite.testEncodeDecodeInitCryptoSnd(randomBytes(1303))
}

func (suite *InitCryptoTestSuite) testEncodeDecodeInitCryptoSnd(payload []byte) {
	alicePrvKeyId, alicePrvKeyEp, err := generateTwoKeys()
	assert.NoError(suite.T(), err)
	bobPrvKeyId, _, err := generateTwoKeys()
	assert.NoError(suite.T(), err)

	buffer, err := EncodeInitCryptoSnd(bobPrvKeyId.PublicKey(), alicePrvKeyId.PublicKey(), alicePrvKeyEp, 0, 0, payload)
	assert.Nil(suite.T(), err)

	_, _, m, err := DecodeInitCryptoSnd(buffer, bobPrvKeyId, alicePrvKeyEp)
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), payload, m.PayloadRaw)
}

func (suite *InitCryptoTestSuite) TestEncodeDecodeInitCryptoRcvShortPayload() {
	suite.testEncodeDecodeInitCryptoRcv([]byte("short1234"))
}

func (suite *InitCryptoTestSuite) TestEncodeDecodeInitCryptoRcvLongPayload() {
	suite.testEncodeDecodeInitCryptoRcv(randomBytes(100))
}

func (suite *InitCryptoTestSuite) testEncodeDecodeInitCryptoRcv(payload []byte) {
	alicePrvKeyId, alicePrvKeyEp, err := generateTwoKeys()
	assert.NoError(suite.T(), err)
	bobPrvKeyId, bobPrvKeyEp, err := generateTwoKeys()
	assert.NoError(suite.T(), err)

	// Alice -> Bob, Alice encodes
	bufferInit, err := EncodeInitCryptoSnd(bobPrvKeyId.PublicKey(), alicePrvKeyId.PublicKey(), alicePrvKeyEp, 0, 0, payload)
	assert.Nil(suite.T(), err)

	// Bob decodes message from Alice
	_, _, m, err := DecodeInitCryptoSnd(bufferInit,  bobPrvKeyId, bobPrvKeyEp)
	assert.Nil(suite.T(), err)

	// Bob -> Alice
	bufferInitReply, err := EncodeInitCryptoRcv(alicePrvKeyId.PublicKey(), bobPrvKeyId.PublicKey(), alicePrvKeyEp.PublicKey(), bobPrvKeyEp, 0, 0, payload)
	assert.Nil(suite.T(), err)

	// Alice decodes message from Bob
	_, m2, err := DecodeInitCryptoRcv(bufferInitReply,  alicePrvKeyEp)
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), payload, m2.PayloadRaw)

	assert.Equal(suite.T(), m.SharedSecret, m2.SharedSecret)
}

func TestCryptoInitCryptoSuite(t *testing.T) {
	suite.Run(t, new(InitCryptoTestSuite))
}

// DataMessagesTestSuite - Tests for DataRot and Data message encoding/decoding
type DataMessagesTestSuite struct {
	suite.Suite
}

func TestCryptoDataMessagesSuite(t *testing.T) {
	suite.Run(t, new(DataMessagesTestSuite))
}

// InitHandshakeTestSuite - Tests for basic handshake flow
type InitHandshakeTestSuite struct {
	suite.Suite
}

func (suite *InitHandshakeTestSuite) TestInitSndBasicFlow() {
	// Generate keys
	alicePrvKeyId, alicePrvKeyEp, err := generateTwoKeys()
	assert.NoError(suite.T(), err)
	bobPrvKeyEp := generateKeys(suite.T())

	// Alice -> Bob: Encode InitHandshakeS0
	buffer := EncodeInitSnd(
		alicePrvKeyId.PublicKey(),
		alicePrvKeyEp)

	// Bob receives and decodes InitHandshakeS0
	pubKeyIdSnd, pubKeyEpSnd, msg, err := DecodeInitSnd(buffer, bobPrvKeyEp)

	// Verify the results
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), InitSnd, msg.MsgType)
	assert.Equal(suite.T(), uint64(0), msg.SnConn)
	assert.NotNil(suite.T(), msg.SharedSecret)

	// Verify the public keys match what was sent
	assert.True(suite.T(), bytes.Equal(alicePrvKeyId.PublicKey().Bytes(), pubKeyIdSnd.Bytes()))
	assert.True(suite.T(), bytes.Equal(alicePrvKeyEp.PublicKey().Bytes(), pubKeyEpSnd.Bytes()))
}

func (suite *InitHandshakeTestSuite) TestInitSndInvalidSize() {
	// Test with buffer that's too small
	buffer := make([]byte, MinInitSndSize-1)
	_, _, _, err := DecodeInitSnd(buffer, generateKeys(suite.T()))
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "size is below minimum init")
}

func (suite *InitHandshakeTestSuite) TestInitRcvBasicFlow() {
	// Generate keys
	alicePrvKeyId, alicePrvKeyEp, err := generateTwoKeys()
	assert.NoError(suite.T(), err)
	bobPrvKeyId, bobPrvKeyEp, err := generateTwoKeys()
	assert.NoError(suite.T(), err)

	// Bob -> Alice: Encode InitHandshakeR0
	rawData := []byte("test data")
	buffer, err := EncodeInitRcv(
		alicePrvKeyId.PublicKey(),
		bobPrvKeyId.PublicKey(),
		alicePrvKeyEp.PublicKey(),
		bobPrvKeyEp,
		0, 0,
		rawData)

	assert.NoError(suite.T(), err)

	// Alice receives and decodes InitHandshakeR0
	pubKeyIdRcv, pubKeyEpRcv, msg, err := DecodeInitRcv(
		buffer, 
		alicePrvKeyEp)

	// Verify the results
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), InitRcv, msg.MsgType)
	assert.Equal(suite.T(), uint64(0), msg.SnConn)
	assert.Equal(suite.T(), rawData, msg.PayloadRaw)
	assert.NotNil(suite.T(), msg.SharedSecret)

	// Verify the public keys match what was sent
	assert.True(suite.T(), bytes.Equal(bobPrvKeyId.PublicKey().Bytes(), pubKeyIdRcv.Bytes()))
	assert.True(suite.T(), bytes.Equal(bobPrvKeyEp.PublicKey().Bytes(), pubKeyEpRcv.Bytes()))
}

func (suite *InitHandshakeTestSuite) TestInitRcvInvalidSize() {
	// Test with buffer that's too small
	buffer := make([]byte, MinInitRcvSizeHdr+FooterDataSize-1)
	_, _, _, err := DecodeInitRcv(buffer, generateKeys(suite.T()))
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "size is below minimum init reply")
}

func (suite *InitHandshakeTestSuite) TestFullHandshakeFlow() {
	// Generate keys for both parties
	alicePrvKeyId, alicePrvKeyEp, err := generateTwoKeys()
	assert.NoError(suite.T(), err)
	bobPrvKeyId, bobPrvKeyEp, err := generateTwoKeys()
	assert.NoError(suite.T(), err)

	// Step 1: Alice sends InitHandshakeS0
	bufferS0 := EncodeInitSnd(
		alicePrvKeyId.PublicKey(),
		alicePrvKeyEp)

	// Step 2: Bob receives and decodes InitHandshakeS0
	_, _, msgS0, err := DecodeInitSnd(bufferS0, bobPrvKeyEp)
	assert.NoError(suite.T(), err)

	// Step 3: Bob sends InitHandshakeR0
	rawData := []byte("handshake response")
	bufferR0, err := EncodeInitRcv(
		alicePrvKeyId.PublicKey(),
		bobPrvKeyId.PublicKey(),
		alicePrvKeyEp.PublicKey(),
		bobPrvKeyEp, 0, 0,
		rawData)
	assert.NoError(suite.T(), err)

	// Step 4: Alice receives and decodes InitHandshakeR0
	_, _, msgR0, err := DecodeInitRcv(bufferR0,  alicePrvKeyEp)
	assert.NoError(suite.T(), err)

	// Verify shared secrets match
	assert.True(suite.T(), bytes.Equal(msgS0.SharedSecret, msgR0.SharedSecret))
}

func (suite *InitHandshakeTestSuite) TestNilKeyHandling() {
	// Test encoding with nil keys
	assert.Panics(suite.T(), func() {
		EncodeInitSnd(nil, nil)
	})

	assert.Panics(suite.T(), func() {
		EncodeInitRcv(nil, nil, nil, nil, 0, 0, []byte("test"))
	})

	validBuffer := make([]byte, startMtu)
	assert.Panics(suite.T(), func() {
		DecodeInitSnd(validBuffer, nil)
	})

	validBuffer = make([]byte, startMtu)
	assert.Panics(suite.T(), func() {
		DecodeInitRcv(validBuffer,  nil)
	})
}

func TestCryptoInitHandshakeSuite(t *testing.T) {
	suite.Run(t, new(InitHandshakeTestSuite))
}
