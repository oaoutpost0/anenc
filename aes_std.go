package anenc

import (
	"errors"
)

// This is a standard one; so the user don't have to create object if they don't want to.
var std_aes = NewAES(nil)

func Encrypt(passwd, data []byte) ([]byte, error) {
	if len(passwd) == 0 || len(data) == 0 {
		return nil, errors.New("either passwd or data missing")
	}
	std_aes.SetPasswd(passwd)
	return std_aes.Encrypt(data)
}

func Decrypt(passwd, encryptedData []byte) ([]byte, error) {
	if len(passwd) == 0 || len(encryptedData) == 0 {
		return nil, errors.New("either passwd or data missing")
	}
	std_aes.SetPasswd(passwd)
	return std_aes.Decrypt(encryptedData)
}

func MustEncrypt(passwd, data, fallback []byte) []byte {
	if out, err := Encrypt(passwd, data); err != nil {
		return fallback
	} else {
		return out
	}
}

func MustDecrypt(passwd, data, fallback []byte) []byte {
	if out, err := Decrypt(passwd, data); err != nil {
		return fallback
	} else {
		return out
	}
}