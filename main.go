package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/pem"
	"fmt"

	vrsa "github.com/VimleshS/crypto/rsa"
	/*
		vaes "github.com/VimleshS/crypto/aes"
		vdes "github.com/VimleshS/crypto/des"
	*/)

func main() {
	h := vrsa.Helper{PrivateKey: "./keys/private_key.pem",
		PublicKey: "./keys/public_key.der",
	}
	b, e := h.Encrypt([]byte("Very private text"))
	if e != nil {
		panic(e)
	}

	s, e := h.Decrypt(b)
	if e != nil {
		panic(e.Error())
	}

	fmt.Println(s)

	RsaPem := vrsa.Helper{PrivateKey: "./keys/private_key.pem",
		PublicKey: "./keys/public_key.pem",
		DecodeFn:  pem.Decode,
	}
	b, e = RsaPem.Encrypt([]byte("decode via a pem decoding..."))
	if e != nil {
		panic(e)
	}

	s, e = RsaPem.Decrypt(b)
	if e != nil {
		panic(e.Error())
	}

	fmt.Println(s)
}

func checkSha1() {
	s := sha1.New()
	s.Write([]byte("Test Sha Sum\n"))
	fmt.Printf("%x\n", s.Sum(nil))
}

func checkSha512() {
	s := sha512.New()
	s.Write([]byte("Test Sha Sum\n"))
	fmt.Printf("%x\n", s.Sum(nil))
}

func checkSha256() {
	s := sha256.New()
	s.Write([]byte("Test Sha Sum\n"))
	// Prepends hex of `x` computed hash
	// fmt.Printf("%x\n", s.Sum([]byte("x")))
	fmt.Printf("%x\n", s.Sum(nil))

	s1 := sha256.Sum256([]byte("Test Sha Sum\n"))
	fmt.Printf("%x\n", s1)
}
