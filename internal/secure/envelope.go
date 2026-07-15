package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

const (
	envelopeVersion = byte(1)
	keySize         = 32
)

var ErrInvalidEnvelope = errors.New("invalid encrypted envelope")

type Envelope struct {
	master []byte
}

func NewEnvelope(master []byte) (*Envelope, error) {
	if len(master) != keySize {
		return nil, fmt.Errorf("master key must be %d bytes", keySize)
	}
	copyOfKey := make([]byte, keySize)
	copy(copyOfKey, master)
	return &Envelope{master: copyOfKey}, nil
}

func DecodeMasterKey(value string) ([]byte, error) {
	key, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		key, err = base64.StdEncoding.DecodeString(value)
	}
	if err != nil || len(key) != keySize {
		return nil, fmt.Errorf("IVPN_MASTER_KEY must be base64 encoding of %d random bytes", keySize)
	}
	return key, nil
}

func GenerateMasterKey() (string, error) {
	key := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(key), nil
}

func (e *Envelope) Seal(plaintext, associatedData []byte) ([]byte, error) {
	dataKey := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, dataKey); err != nil {
		return nil, err
	}
	defer zero(dataKey)

	wrappedKey, keyNonce, err := seal(e.master, dataKey, associatedData)
	if err != nil {
		return nil, err
	}
	ciphertext, dataNonce, err := seal(dataKey, plaintext, associatedData)
	if err != nil {
		return nil, err
	}

	result := make([]byte, 0, 1+len(keyNonce)+len(wrappedKey)+len(dataNonce)+len(ciphertext))
	result = append(result, envelopeVersion)
	result = append(result, keyNonce...)
	result = append(result, wrappedKey...)
	result = append(result, dataNonce...)
	result = append(result, ciphertext...)
	return result, nil
}

func (e *Envelope) Open(envelope, associatedData []byte) ([]byte, error) {
	masterAEAD, err := newAEAD(e.master)
	if err != nil {
		return nil, err
	}
	keyNonceSize := masterAEAD.NonceSize()
	wrappedKeySize := keySize + masterAEAD.Overhead()
	minimum := 1 + keyNonceSize + wrappedKeySize + keyNonceSize + masterAEAD.Overhead()
	if len(envelope) < minimum || envelope[0] != envelopeVersion {
		return nil, ErrInvalidEnvelope
	}
	offset := 1
	keyNonce := envelope[offset : offset+keyNonceSize]
	offset += keyNonceSize
	wrappedKey := envelope[offset : offset+wrappedKeySize]
	offset += wrappedKeySize
	dataNonce := envelope[offset : offset+keyNonceSize]
	offset += keyNonceSize
	ciphertext := envelope[offset:]

	dataKey, err := masterAEAD.Open(nil, keyNonce, wrappedKey, associatedData)
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	defer zero(dataKey)
	dataAEAD, err := newAEAD(dataKey)
	if err != nil {
		return nil, err
	}
	plaintext, err := dataAEAD.Open(nil, dataNonce, ciphertext, associatedData)
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	return plaintext, nil
}

func seal(key, plaintext, associatedData []byte) ([]byte, []byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	return aead.Seal(nil, nonce, plaintext, associatedData), nonce, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
