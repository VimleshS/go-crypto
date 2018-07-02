package rsa

import (
	"encoding/pem"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_RSAHelper_DecodeFn_Nil(t *testing.T) {
	h := Helper{PrivateKey: "/home/Vimlesh/private.pem",
		PublicKey: "/home/Vimlesh/public.pem",
	}

	assert.Nil(t, h.DecodeFn, "Decode function should be nil, unless specified")
}

func Test_Helper_DecodeFn_NotNil(t *testing.T) {
	h := Helper{PrivateKey: "/home/Vimlesh/private.pem",
		PublicKey: "/home/Vimlesh/public.pem",
		DecodeFn:  pem.Decode,
	}

	assert.NotNil(t, h.DecodeFn, "Decode function should not be nil")
}

func Test_Helper_KeyFiles(t *testing.T) {
	dir, _ := os.Getwd()

	_t := Helper{PrivateKey: dir + "/../keys/private_key.pem",
		PublicKey: dir + "/../keys/public_key.pem",
	}
	_, err := _t.readPublicKey()
	assert.Nilf(t, err, "There should not be an errror")
}

func Test_Helper_encrpyt_decrypt(t *testing.T) {
	dir, _ := os.Getwd()

	_t := Helper{PrivateKey: dir + "/../keys/private_key.pem",
		PublicKey: dir + "/../keys/public_key.pem",
		DecodeFn:  pem.Decode,
	}
	data := "decode via a pem decoding..."
	b, e := _t.Encrypt([]byte(data))
	assert.Nil(t, e, "There should be no error while encoding")

	s, e := _t.Decrypt(b)
	assert.Nil(t, e, "There should be no error while decoding")
	assert.Equal(t, s, data, "decoded data should be same as encoded")
}
