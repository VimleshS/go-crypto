package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
)

type SizeKeyBlock interface {
	Size() int
	KeyBytes() []byte
	GetBlock(fn func() []byte) (cipher.Block, error)
}

type Vectorizer interface {
	InitializationVector(ciphertext []byte) ([]byte, error)
}

type EsInterfacer interface {
	SizeKeyBlock
	Vectorizer
}

type KeyBlock struct {
	BlockSize int
	NewCipher func(key []byte) (cipher.Block, error)
}

func (kb *KeyBlock) Size() int {
	return kb.BlockSize
}

func (kb *KeyBlock) KeyBytes() []byte {
	key, _ := hex.DecodeString("909f5f575649391ca627ea2dfcbbbc15da3369d8fc102b360c8204c244e09c15")
	return key
}

func (kb *KeyBlock) GetBlock(fn func() []byte) (cipher.Block, error) {
	block, err := kb.NewCipher(fn())
	if err != nil {
		return nil, err
	}
	return block, err
}

func (kb *KeyBlock) InitializationVector(ciphertext []byte) ([]byte, error) {
	iv := ciphertext[:kb.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	return iv, nil
}

// streamHelper ...
type streamHelper struct {
	EsInterfacer
	Text string
}

// NewstreamHelper ...
func NewstreamHelper(text string) *streamHelper {
	return &streamHelper{EsInterfacer: &KeyBlock{
		NewCipher: aes.NewCipher, BlockSize: aes.BlockSize},
		Text: text}
}

// Encrypt ...
func (a *streamHelper) Encrypt() ([]byte, error) {
	paddedSrcBytes := []byte(a.Text)

	block, err := a.GetBlock(a.KeyBytes)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, a.Size()+len(paddedSrcBytes))
	iv, err := a.InitializationVector(ciphertext)
	if err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[a.Size():], paddedSrcBytes)
	return ciphertext, nil
}

// Decrypt ...
func (a *streamHelper) Decrypt(ciphertext []byte) (string, error) {
	block, err := a.GetBlock(a.KeyBytes)
	if err != nil {
		return "", err
	}

	iv := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	decryptor := cipher.NewCFBDecrypter(block, iv)
	_dst := make([]byte, len(ciphertext))
	decryptor.XORKeyStream(_dst, ciphertext)
	return string(_dst[a.Size():]), nil
}

type helper struct {
	EsInterfacer
	Text string
}

func Newhelper(text string) *helper {
	return &helper{EsInterfacer: &KeyBlock{
		NewCipher: aes.NewCipher, BlockSize: aes.BlockSize}, Text: text}
}

// Encrypt ...
func (a *helper) Encrypt() ([]byte, error) {
	paddedSrcBytes := []byte(a.Text)

	block, err := a.GetBlock(a.KeyBytes)
	if err != nil {
		return nil, err
	}

	paddedSrcBytes = a.pkcS5Padding(paddedSrcBytes, a.Size())

	ciphertext := make([]byte, a.Size()+len(paddedSrcBytes))
	iv, err := a.InitializationVector(ciphertext)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[a.Size():], paddedSrcBytes)
	return ciphertext, nil
}

// Decrypt ...
func (a *helper) Decrypt(ciphertext []byte) (string, error) {
	block, err := a.GetBlock(a.KeyBytes)
	if err != nil {
		return "", err
	}

	iv := ciphertext[:a.Size()]
	dec := cipher.NewCBCDecrypter(block, iv)
	_dst := make([]byte, len(ciphertext))
	dec.CryptBlocks(_dst, ciphertext)

	return string(a.removePKCSPadding(_dst[a.Size():])), nil
}

func (a *helper) pkcS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func (a *helper) removePKCSPadding(_dst []byte) []byte {
	result := []byte{}
	for _, char := range _dst {
		if char < 16 {
			continue
		}
		result = append(result, char)
	}
	return result
}
