package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

//https://stackoverflow.com/questions/11410770/load-rsa-public-key-from-file?rq=1
/*
	1. openssl genrsa -out private_key.pem 2048
	2. openssl pkcs8 -topk8 -inform PEM -outform DER -in private_key.pem -out private_key.der -nocrypt
	3. openssl rsa -in private_key.pem -pubout -outform DER -out public_key.der
*/

func testRSA() {
	encrypteddata := readpublickey()
	decryptData(encrypteddata)
}

func readpublickey() []byte {
	b, e := ioutil.ReadFile("./public_key.der")
	if e != nil {
		fmt.Println(e.Error())
	}
	k, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		fmt.Println(err.Error())
	}

	//to check what is key type
	/*
		switch k := k.(type) {
		case *rsa.PublicKey:
			fmt.Println("pub is of type RSA:", k)
		case *dsa.PublicKey:
			fmt.Println("pub is of type DSA:", k)
		case *ecdsa.PublicKey:
			fmt.Println("pub is of type ECDSA:", k)
		default:
			panic("unknown type of public key")
		}
	*/

	hash := sha1.New()
	random := rand.Reader
	encrypted, err := rsa.EncryptOAEP(hash, random, k.(*rsa.PublicKey), []byte("My very secret to be preserved"), nil)
	if err != nil {
		fmt.Println(err.Error())
	}
	return encrypted
}

func decryptData(cipherbytes []byte) {
	b, e := ioutil.ReadFile("./private_key.pem")
	if e != nil {
		fmt.Println(e.Error())
	}
	pem, _ := pem.Decode(b)

	var pri *rsa.PrivateKey
	pri, parseErr := x509.ParsePKCS1PrivateKey(pem.Bytes)
	if parseErr != nil {
		fmt.Println("Load private key error")
		panic(parseErr)
	}

	hash := sha1.New()
	random := rand.Reader
	decrypted, err := rsa.DecryptOAEP(hash, random, pri, cipherbytes, nil)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println(string(decrypted))
}
