// http://etutorials.org/Linux+systems/unix+internet+security/Part+II+Security+Building+Blocks/Chapter+7.+Cryptography+Basics/7.2+Symmetric+Key+Algorithms/
// has good defination of what is HMAC.
// http://etutorials.org/Linux+systems/unix+internet+security/Part+II+Security+Building+Blocks/Chapter+7.+Cryptography+Basics/7.4+Message+Digest+Functions/
// https://www.password-depot.com/know-how/blowfish_and_rijndael.htm
// https://golang.org/pkg/crypto/cipher/#BlockMode
// https://golang.org/src/crypto/cipher/example_test.go
// https://asecuritysite.com/encryption/padding
// https://crypto.stackexchange.com/questions/5333/difference-between-stream-cipher-and-block-cipher
// https://www.socketloop.com/tutorials/golang-example-for-dsa-functions

//RELATED TO RSA FILE LOAD
//https://stackoverflow.com/questions/13555085/save-and-load-crypto-rsa-privatekey-to-and-from-the-disk
//https://stackoverflow.com/questions/44230634/how-to-read-an-rsa-key-from-file/44231740

//jemygraw/golang_rsa_oaep_decrypt.go
//https://gist.github.com/jemygraw/f31c74b0e0e8ec7c7d15

//https://www.socketloop.com/tutorials/golang-tutorial-on-loading-gob-and-pem-files

//https://gist.github.com/Soarez/9688998
//https://support.ssl.com/Knowledgebase/Article/View/19/0/der-vs-crt-vs-cer-vs-pem-certificates-and-how-to-convert-them

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
)

func main() {
	// testAes()
	// testAesStream()
	// testDes()
	// testdsa()
	// testonlyRSA()
	testRSA()
	// gen_from_file()
}

func testDes() {
	plaintext := []byte("This is my very secret code")
	key := []byte("12345678")
	block, err := des.NewCipher(key)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	plaintext = PKCS5Padding(plaintext, block.BlockSize())
	ciphertext := make([]byte, des.BlockSize+len(plaintext))
	iv := ciphertext[:des.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		fmt.Println(err.Error())
		return
	}
	// fmt.Println(iv)
	// fmt.Println(ciphertext)

	//ENCODING
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[des.BlockSize:], plaintext)
	fmt.Printf("%x\n", ciphertext)

	// DECODING
	iv1 := ciphertext[:des.BlockSize]
	dec := cipher.NewCBCDecrypter(block, iv1)
	_dst := make([]byte, len(ciphertext))
	dec.CryptBlocks(_dst, ciphertext)
	fmt.Println(string(_dst[dec.BlockSize():]))
}

func testAes() {
	plaintext := []byte("very very secret Aes")
	// echo "Vimlesh" | sha256sum
	key, err := hex.DecodeString("909f5f575649391ca627ea2dfcbbbc15da3369d8fc102b360c8204c244e09c15")
	// key, err := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println(block.BlockSize())
	fmt.Printf("Size --> %d ==> %v \n", len(plaintext), plaintext)
	plaintext = PKCS5Padding(plaintext, block.BlockSize())
	fmt.Printf("After Size --> %d ==> %v \n", len(plaintext), plaintext)

	// nonce := make([]byte, 12)
	// if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
	// 	panic(err.Error())
	// }
	// fmt.Println(nonce)
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	fmt.Println(iv)
	fmt.Println(ciphertext)

	//ENCODING
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)
	fmt.Printf("%x\n", ciphertext)

	// DECODING
	iv1 := ciphertext[:aes.BlockSize]
	dec := cipher.NewCBCDecrypter(block, iv1)
	_dst := make([]byte, len(ciphertext))
	dec.CryptBlocks(_dst, ciphertext)
	fmt.Println(string(_dst[dec.BlockSize():]))
}

func testAesStream() {
	plaintext := []byte("very very secret AES stream")
	// echo "Vimlesh" | sha256sum
	key, err := hex.DecodeString("909f5f575649391ca627ea2dfcbbbc15da3369d8fc102b360c8204c244e09c15")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	ciphertext := make([]byte, block.BlockSize()+len(plaintext))

	//IMP: below is the statement very important for the ciphertext to get initialized with IV
	// Generate and append to the cipher text
	iv := ciphertext[:block.BlockSize()]
	// iv := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		fmt.Println(err.Error())
		return
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[block.BlockSize():], plaintext)
	fmt.Printf("=-> \n%x\n", ciphertext)

	//Acceptable..
	iv1 := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, iv1); err != nil {
		panic(err)
	}

	decryptor := cipher.NewCFBDecrypter(block, iv1)
	_dst := make([]byte, len(ciphertext))
	decryptor.XORKeyStream(_dst, ciphertext)
	fmt.Printf("Final Ans => %s\n", _dst[block.BlockSize():])
}

// PKCS5Padding ...
func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	// padtext := bytes.Repeat([]byte{byte(padding)}, padding)

	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func testSha1() {
	s := sha1.New()
	s.Write([]byte("Vimlesh\n"))
	fmt.Printf("%x\n", s.Sum(nil))
}

func testSha512() {
	s := sha512.New()
	s.Write([]byte("Vimlesh\n"))
	fmt.Printf("%x\n", s.Sum(nil))
}

func testSha256() {
	s := sha256.New()
	s.Write([]byte("Vimlesh\n"))
	// Prepends hex of `x` computed hash
	// fmt.Printf("%x\n", s.Sum([]byte("x")))
	fmt.Printf("%x\n", s.Sum(nil))

	s1 := sha256.Sum256([]byte("Vimlesh\n"))
	fmt.Printf("%x\n", s1)
}
