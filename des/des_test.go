package des

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Des(t *testing.T) {
	tests := []struct {
		test string
	}{
		{"世界, Hello World"},
		{"my secrect"},
	}
	for _, test := range tests {
		_tempa := Newhelper(test.test)
		_t, err := _tempa.Encrypt()
		assert.Equal(t, err, nil)
		res, _ := _tempa.Decrypt(_t)
		assert.Equal(t, test.test, res)

	}
}

func Test_Decrypt(t *testing.T) {
	enc := []byte{220, 161, 163, 65, 6, 140, 216, 36, 144, 32, 159, 25, 147,
		145, 141, 23, 174, 182, 209, 209, 100, 60, 19, 88, 135, 71, 78, 15,
		144, 191, 151, 181}

	_tempa := Newhelper("")
	res, _ := _tempa.Decrypt(enc)
	assert.Equal(t, res, "世界, Hello World")
}
