package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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

type kbmock struct {
	mock.Mock
	EsInterfacer
	Text string
}

func (m *kbmock) Size() int {
	args := m.Called()
	return args.Int(0)
}

func (m *kbmock) KeyBytes() []byte {
	args := m.Called()
	return args.Get(0).([]byte)
}

func (m *kbmock) GetBlock(fn func() []byte) (cipher.Block, error) {
	args := m.Called(fn)
	k, _ := hex.DecodeString("909f5f575649391ca627ea2dfcbbbc15da3369d8fc102b360c8204c244e09c15")
	block, _ := aes.NewCipher(k)
	return block, args.Error(0)
}

func (m *kbmock) InitializationVector(ciphertext []byte) ([]byte, error) {
	args := m.Called(ciphertext)
	return args.Get(0).([]byte), args.Error(1)
}

func Test_Key_blockSize(t *testing.T) {
	mock := kbmock{}
	mock.On("Size").Return(8)
	aesObj := &streamHelper{EsInterfacer: &mock, Text: "text"}
	res := aesObj.Size()
	assert.Equal(t, res, 8)
	//Not required, as sure that size will be called..
	// mock.AssertExpectations(t)
}

func Test_Key_block_failure(t *testing.T) {
	_mock := kbmock{}
	_mock.On("Size").Return(16)
	_mock.On("KeyBytes").
		Return(hex.DecodeString("909f5f575649391ca627ea2dfcbbbc15da3369d8fc102b360c8204c244e09c15"))
	_mock.On("GetBlock", mock.AnythingOfType("func() []uint8")).
		Return(errors.New("block failed"))
	_mock.On("InitializationVector", []byte("hello")).
		Return([]byte(""), errors.New("IV failed"))

	aesObj := &streamHelper{EsInterfacer: &_mock, Text: "This is very secrect text.."}
	_, err := aesObj.Encrypt()
	assert.Error(t, err, "expecting an error.")
	// _mock.AssertExpectations(t)
}

func Test_Aes(t *testing.T) {
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

func Test_Aesstream(t *testing.T) {
	tests := []struct {
		test string
	}{
		{"世界, Hello World"},
		{"vimlesh secretc"},
	}
	for _, test := range tests {
		_tempa := NewstreamHelper(test.test)
		_t, err := _tempa.Encrypt()
		assert.Equal(t, err, nil)
		res, _ := _tempa.Decrypt(_t)
		assert.Equal(t, test.test, res)

	}
}
