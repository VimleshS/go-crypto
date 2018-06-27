package aes

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Key_Block(t *testing.T) {
	inputs := []struct {
		block int
	}{{8}, {16}}

	for _, input := range inputs {
		kb := KeyBlock{BlockSize: input.block}
		assert.Equal(t, kb.BlockSize, input.block)
	}
}

func Test_Key_IV(t *testing.T) {

}

func Test_Aes(t *testing.T) {
	tests := []struct {
		test string
	}{
		{"世界, Hello World"},
		{"vimlesh secretc"},
	}
	for _, test := range tests {
		_tempa := NewAesCBC(test.test)
		_t, err := _tempa.Encrypt()
		assert.Equal(t, err, nil)
		res, _ := _tempa.Decrypt(_t)
		assert.Equal(t, test.test, res)

	}
}

func Test_Aesstream(t *testing.T) {
	tests := []struct {
		test string
	}{
		{"世界, Hello World"},
		{"vimlesh secretc"},
	}
	for _, test := range tests {
		_tempa := NewAesStream(test.test)
		_t, err := _tempa.Encrypt()
		assert.Equal(t, err, nil)
		res, _ := _tempa.Decrypt(_t)
		assert.Equal(t, test.test, res)

	}
}
