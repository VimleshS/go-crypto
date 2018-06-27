package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log"
)

type KeyBlock struct {
	BlockSize int
	NewCipher func(key []byte) (cipher.Block, error)
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
		log.Println(err.Error())
		return nil, err
	}
	return iv, nil
}

// Aesstream ...
type aesStream struct {
	KeyBlock
	Text string
}

// NewAesStream ...
func NewAesStream(text string) *aesStream {
	return &aesStream{KeyBlock: KeyBlock{
		NewCipher: aes.NewCipher, BlockSize: aes.BlockSize}, Text: text}
}

// Encrypt ...
func (a *aesStream) Encrypt() ([]byte, error) {
	paddedSrcBytes := []byte(a.Text)

	block, err := a.GetBlock(a.KeyBytes)
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}

	ciphertext := make([]byte, a.BlockSize+len(paddedSrcBytes))
	iv, err := a.InitializationVector(ciphertext)
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[a.BlockSize:], paddedSrcBytes)
	return ciphertext, nil
}

// Decrypt ...
func (a *aesStream) Decrypt(ciphertext []byte) (string, error) {
	block, err := a.GetBlock(a.KeyBytes)
	if err != nil {
		log.Println(err.Error())
		return "", err
	}

	iv := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Println(err.Error())
		return "", err
	}

	decryptor := cipher.NewCFBDecrypter(block, iv)
	_dst := make([]byte, len(ciphertext))
	decryptor.XORKeyStream(_dst, ciphertext)
	return string(_dst[a.BlockSize:]), nil
}

type aesCBC struct {
	KeyBlock
	Text string
}

func NewAesCBC(text string) *aesCBC {
	return &aesCBC{KeyBlock: KeyBlock{
		NewCipher: aes.NewCipher, BlockSize: aes.BlockSize}, Text: text}
}

// Encrypt ...
func (a *aesCBC) Encrypt() ([]byte, error) {
	paddedSrcBytes := []byte(a.Text)

	block, err := a.GetBlock(a.KeyBytes)
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}

	paddedSrcBytes = a.pkcS5Padding(paddedSrcBytes, a.BlockSize)

	ciphertext := make([]byte, a.BlockSize+len(paddedSrcBytes))
	iv, err := a.InitializationVector(ciphertext)
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[a.BlockSize:], paddedSrcBytes)
	return ciphertext, nil
}

// Decrypt ...
func (a *aesCBC) Decrypt(ciphertext []byte) (string, error) {
	block, err := a.GetBlock(a.KeyBytes)
	if err != nil {
		log.Println(err.Error())
		return "", err
	}

	iv := ciphertext[:a.BlockSize]
	dec := cipher.NewCBCDecrypter(block, iv)
	_dst := make([]byte, len(ciphertext))
	dec.CryptBlocks(_dst, ciphertext)

	return string(a.removePKCSPadding(_dst[a.BlockSize:])), nil
}

func (a *aesCBC) pkcS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func (a *aesCBC) removePKCSPadding(_dst []byte) []byte {
	result := []byte{}
	for _, char := range _dst {
		if char < 16 {
			continue
		}
		result = append(result, char)
	}
	return result
}
