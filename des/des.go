package des

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"log"

	vaes "github.com/VimleshS/crypto/aes"
)

type desCBC struct {
	vaes.KeyBlock
	Text string
}

func (a *desCBC) KeyBytes() []byte {
	return []byte("12345678")
}

func NewDesCBC(text string) *desCBC {
	return &desCBC{KeyBlock: vaes.KeyBlock{NewCipher: des.NewCipher, BlockSize: des.BlockSize}, Text: text}
}

// Encrypt ...
func (a *desCBC) Encrypt() ([]byte, error) {
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
func (a *desCBC) Decrypt(ciphertext []byte) (string, error) {
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

func (a *desCBC) pkcS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func (a *desCBC) removePKCSPadding(_dst []byte) []byte {
	result := []byte{}
	for _, char := range _dst {
		if char < 16 {
			continue
		}
		result = append(result, char)
	}
	return result
}
