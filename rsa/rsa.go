package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
)

//https://stackoverflow.com/questions/11410770/load-rsa-public-key-from-file?rq=1
/*
	1. openssl genrsa -out private_key.pem 2048

	NOT REQUIRED
	2. openssl pkcs8 -topk8 -inform PEM -outform DER -in private_key.pem -out private_key.der -nocrypt

	3. openssl rsa -in private_key.pem -pubout -outform DER -out public_key.der
	OR
	4. openssl rsa -in private_key.pem -pubout -outform PEM -out public_key.pem
*/

//Helper have a simple encode and decode method
type Helper struct {
	PublicKey  string
	PrivateKey string
	DecodeFn   func(data []byte) (p *pem.Block, rest []byte)
}

func (h *Helper) Encrypt(dataBytes []byte) ([]byte, error) {
	b, e := h.readPublicKey()
	if e != nil {
		return []byte{}, e
	}
	key, e := h.parseKey(b)
	if e != nil {
		return []byte{}, e
	}
	b, e = h.encryptData(key, dataBytes)
	return b, e
}

func (h *Helper) encryptData(k interface{}, dataBytes []byte) ([]byte, error) {
	hash := sha1.New()
	random := rand.Reader
	encrypted, err := rsa.EncryptOAEP(hash, random, k.(*rsa.PublicKey), dataBytes, nil)
	if err != nil {
		return []byte{}, err
	}
	return encrypted, nil
}

func (h *Helper) readPublicKey() ([]byte, error) {
	return ioutil.ReadFile(h.PublicKey)
}

func (h *Helper) parseKey(b []byte) (interface{}, error) {
	if h.DecodeFn != nil {
		block, _ := h.DecodeFn(b)
		b = block.Bytes
	}
	k, err := x509.ParsePKIXPublicKey(b)
	return k, err
}

func (h *Helper) Decrypt(encryptedData []byte) (string, error) {
	b, e := ioutil.ReadFile(h.PrivateKey)
	if e != nil {
		return "", e
	}
	pem, _ := pem.Decode(b)

	var pri *rsa.PrivateKey
	pri, parseErr := x509.ParsePKCS1PrivateKey(pem.Bytes)
	if parseErr != nil {
		return "", parseErr
	}

	hash := sha1.New()
	random := rand.Reader
	decrypted, err := rsa.DecryptOAEP(hash, random, pri, encryptedData, nil)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}
