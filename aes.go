package anenc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"errors"
	"io"
	"sync"
)

type AES struct {
	passwd     []byte
	mu         sync.Mutex
	saltHeader []byte
	salt       [8]byte
	blockSize  int
}

func NewAES(passwd []byte) *AES {
	return &AES{
		passwd:     passwd,
		saltHeader: []byte("Salted__"),
		blockSize:  aes.BlockSize,
	}
}

func (a *AES) SetKeyStr(passwd string) {
	a.SetPasswd([]byte(passwd))
}

func (a *AES) SetPasswd(passwd []byte) {
	a.mu.Lock()
	a.passwd = passwd
	a.mu.Unlock()
}

func (a *AES) Decrypt(data []byte) ([]byte, error) {
	lenData := len(data)
	if lenData < a.blockSize || lenData == 0 {
		return nil, errors.New("invalid data size")
	}
	saltHeader := data[:a.blockSize]
	if !bytes.Equal(saltHeader[:8], a.saltHeader) {
		return nil, errors.New("invalid or missing saltHeader")
	}

	key, iv := a.getKeyAndIV(saltHeader[8:])
	if lenData == 0 || lenData % a.blockSize != 0 {
		return nil, errors.New("bad blocksize")
	}
	if ci, err := aes.NewCipher(key); err != nil {
		return nil, err
	} else {
		cbc := cipher.NewCBCDecrypter(ci, iv)
		cbc.CryptBlocks(data[a.blockSize:], data[a.blockSize:])
		return pkcs7Remove(data[a.blockSize:], a.blockSize)
	}
}

func (a *AES) newSalt() error {
	a.mu.Lock()
	if _, err := io.ReadFull(rand.Reader, a.salt[:]); err != nil {
		a.mu.Unlock()
		return err
	}
	a.mu.Unlock()
	return nil
}

func (a *AES) Encrypt(inp []byte) ([]byte, error) {
	if err := a.newSalt(); err != nil {
		return nil, err
	}

	data := make([]byte, len(inp)+a.blockSize, len(inp)+a.blockSize+1) // for newline
	copy(data[0:], a.saltHeader)
	copy(data[8:], a.salt[:])
	copy(data[a.blockSize:], inp)

	key, iv := a.getKeyAndIV(a.salt[:])
	if enc, err := encrypt(key, iv, data); err != nil {
		return nil, err
	} else {
		return enc, nil
	}
}

// TODO: check mutex
// NOTE TESTED
func (a *AES) encrypt(key, iv, data []byte) ([]byte, error) {
	paddedData := pkcs7Add(data, a.blockSize)
	if ci, err := aes.NewCipher(key); err != nil {
		return nil, err
	} else {
		cbc := cipher.NewCBCEncrypter(ci, iv)
		cbc.CryptBlocks(paddedData[a.blockSize:], paddedData[a.blockSize:])
		return paddedData, nil
	}
}

func (a *AES) getKeyAndIV(salt []byte) (key, iv []byte) {
	var keyIv [48]byte
	var md5sum [16]byte

	lenPwd := len(a.passwd)
	buf := make([]byte, 0, 16+len(salt)+lenPwd) // between 0 - (16 + salt + password)

	n := 0
	for i := 0; i < 3; i++ {
		if i != 0 {
			n = 16
		}
		buf = buf[:n+lenPwd+len(salt)]
		copy(buf, md5sum[:])
		copy(buf[n:], a.passwd)
		copy(buf[n+lenPwd:], salt[:])
		md5sum = md5.Sum(buf)
		copy(keyIv[i*16:], md5sum[:])
	}
	return keyIv[:32], keyIv[32:] // key 32, iv 16 bytes;
}

// pkcs7Add will add PKCS#7 padding
func pkcs7Add(data []byte, blockSize int) []byte {
	// Fits the block -- No padding required.
	lenData := len(data)
	if lenData%blockSize == 0 {
		return data
	}

	// If data is smaller than the blocksize, then add padding for diffs.
	// If data is bigger, then reminder of (lenData % blockSize) will be
	// the padding size.
	var padSize int
	if lenData < blockSize {
		padSize = blockSize - lenData
	} else {
		padSize = blockSize - lenData%blockSize
	}

	// Append the padding to the data
	// byte(padSize) --> DEC to HEX
	data = append(data, bytes.Repeat([]byte{byte(padSize)}, padSize)...)
	return data
}

// pkcs7Remove will remove PKCS#7 padding
func pkcs7Remove(data []byte, blockSize int) ([]byte, error) {
	lenData := len(data)
	if lenData == 0 || lenData%blockSize != 0 {
		return nil, errors.New("invalid data")
	}

	padSize := int(data[lenData-1]) // HEX to DEC
	if padSize == 0 || padSize > blockSize {
		return nil, errors.New("invalid padding size")
	}

	// Check the last char (HEX) I got represents actual DEC
	// by checking repeats.
	if !bytes.Equal(
		bytes.Repeat([]byte{byte(padSize)}, padSize),
		data[lenData-padSize:]) {
		return nil, errors.New("invalid padding byte")
	}
	return data[:lenData-padSize], nil
}
