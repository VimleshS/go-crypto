package des

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"log"

	vaes "github.com/VimleshS/crypto/aes"
)

type helper struct {
	vaes.EsInterfacer
	Text string
}

func (a *helper) KeyBytes() []byte {
	return []byte("12345678")
}

func Newhelper(text string) *helper {
	return &helper{EsInterfacer: &vaes.KeyBlock{
		NewCipher: des.NewCipher, BlockSize: des.BlockSize},
		Text: text}
}

// Encrypt ...
func (a *helper) Encrypt() ([]byte, error) {
	paddedSrcBytes := []byte(a.Text)

	block, err := a.GetBlock(a.KeyBytes)
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}

	paddedSrcBytes = a.pkcS5Padding(paddedSrcBytes, a.Size())

	ciphertext := make([]byte, a.Size()+len(paddedSrcBytes))
	iv, err := a.InitializationVector(ciphertext)
	if err != nil {
		log.Println(err.Error())
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
		log.Println(err.Error())
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
