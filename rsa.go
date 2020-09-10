package anenc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
)

// =====================================================================================================================

type RSA struct {
	PEMPrivate    []byte
	PEMPublic     []byte
	DataEncrypted []byte
	DataPlain     []byte

	random           io.Reader
	bits             int
	blockTypePrivate string
	blockTypePublic  string
	label            []byte
	hash             hash.Hash
}

func NewRSA(fns ...func(*RSA)) *RSA {
	r := RSA{
		random:           rand.Reader,
		bits:             2048,
		blockTypePrivate: "RSA PRIVATE KEY",
		blockTypePublic:  "RSA PUBLIC KEY",
		label:            []byte("orangenumber.com"),
		hash:             crypto.SHA256.New(),
	}

	for _, f := range fns {
		f(&r)
	}

	return &r
}

// =====================================================================================================================
// Setting variables
// =====================================================================================================================
func (m *RSA) GetPEMPrivate() string     { return string(m.PEMPrivate) }
func (m *RSA) GetPEMPublic() string      { return string(m.PEMPublic) }
func (m *RSA) GetDataEncrypted() string  { return string(m.DataEncrypted) }
func (m *RSA) GetDataPlain() string      { return string(m.DataPlain) }
func (m *RSA) SetPEMPrivate(s string)    { m.PEMPrivate = []byte(s) }
func (m *RSA) SetPEMPublic(s string)     { m.PEMPublic = []byte(s) }
func (m *RSA) SetDataEncrypted(s string) { m.DataEncrypted = []byte(s) }
func (m *RSA) SetDataPlain(s string)     { m.DataPlain = []byte(s) }

// =====================================================================================================================
// Creating Keys
// =====================================================================================================================
func (m *RSA) GenerateKeys() error {
	privKey, err := rsa.GenerateKey(m.random, m.bits)
	if err != nil {
		return err
	}

	m.PEMPrivate = pem.EncodeToMemory(m.getPriPemBlock(privKey))
	m.PEMPublic = pem.EncodeToMemory(m.getPubPemBlock(privKey))
	return nil
}

func (m *RSA) getPriPemBlock(privKey *rsa.PrivateKey) *pem.Block {
	return &pem.Block{
		Type:  m.blockTypePrivate,
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	}
}

func (m *RSA) getPubPemBlock(privKey *rsa.PrivateKey) *pem.Block {
	return &pem.Block{
		Type:  m.blockTypePublic,
		Bytes: x509.MarshalPKCS1PublicKey(&privKey.PublicKey),
	}
}

func (m *RSA) decryptPemIfEncrypted(block *pem.Block) ([]byte, error) {
	if x509.IsEncryptedPEMBlock(block) {
		b, err := x509.DecryptPEMBlock(block, nil)
		return b, err
	}
	return block.Bytes, nil
}

func (m *RSA) Encrypt() (err error) {
	// Encrypt needs public key
	if len(m.PEMPublic) == 0 {
		if len(m.PEMPrivate) == 0 {
			return errors.New("PEMPublic is required for Encrypt()")
		}
		if err := m.GetPubKeyFromPriKey(); err != nil {
			return err
		}
	}

	if len(m.DataPlain) == 0 {
		return fmt.Errorf("DataPlain is required for Encrypt()")
	}

	block, _ := pem.Decode([]byte(m.PEMPublic))
	b, err := m.decryptPemIfEncrypted(block)
	if err != nil {
		return err
	}

	key, err := x509.ParsePKCS1PublicKey(b)
	if err != nil {
		return err
	}

	encrypted, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, key, []byte(m.DataPlain), m.label)

	// m.DataEncrypted = base64.StdEncoding.EncodeToString(encrypted)
	tmp := make([]byte, base64.StdEncoding.EncodedLen(len(encrypted)))
	base64.StdEncoding.Encode(tmp, encrypted)

	m.DataEncrypted = tmp[:]

	if err != nil {
		return err
	}
	m.DataPlain = nil
	return nil
}

func (m *RSA) GetPubKeyFromPriKey() (err error) {
	// ==================================================================== PARSE PRIVATE KEY
	if len(m.PEMPrivate) == 0 {
		return fmt.Errorf("PEMPrivate is required to generate PEMPublic")
	}

	block, _ := pem.Decode([]byte(m.PEMPrivate))
	if block == nil {
		return fmt.Errorf("cannot decode PEMPrivate key")
	}

	b, err := m.decryptPemIfEncrypted(block)
	if err != nil {
		return err
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		return err
	}

	m.PEMPublic = pem.EncodeToMemory(m.getPubPemBlock(privateKey))
	return nil
}

func (m *RSA) Decrypt() (err error) {
	// Encrypt needs public key
	if len(m.PEMPrivate) == 0 {
		return fmt.Errorf("PEMPrivate is required for Decrypt()")
	}
	if len(m.DataEncrypted) == 0 {
		return fmt.Errorf("DataEncrypted is required for Decrypt()")
	}

	block, _ := pem.Decode(m.PEMPrivate)
	if block == nil {
		return fmt.Errorf("cannot decode PEMPrivate key")
	}

	b, err := m.decryptPemIfEncrypted(block)
	if err != nil {
		return fmt.Errorf("decryptPemIfEncrypted(block): %w", err)
	}

	key, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		return fmt.Errorf("ParsePKCS1PrivateKey(b): %w", err)
	}

	// b, err = base64.StdEncoding.DecodeString(string(m.DataEncrypted))
	b = make([]byte, base64.StdEncoding.DecodedLen(len(m.DataEncrypted)))
	if l, err := base64.StdEncoding.Decode(b, m.DataEncrypted); err != nil {
		return errors.New("cannot decode base64 pem")
	} else {
		b = b[:l]
	}

	plain, err := rsa.DecryptOAEP(sha512.New(), rand.Reader, key, b, m.label)
	if err != nil {
		return fmt.Errorf("DecryptOAEP(): %w", err)
	}

	m.DataPlain = plain
	m.DataEncrypted = nil
	return nil
}

func (m *RSA) Debug() {
	shorter := func(inp string) string {
		// return as is if shorter than wanted length
		if len(inp) <= 40 {
			return inp
		}
		return inp[0:20] + "..." + inp[len(inp)-5:]
	}
	println("PEM_PRI: ", "["+shorter(string(m.PEMPrivate))+"]", len(m.PEMPrivate), "b")
	println("PEM_PUB: ", "["+shorter(string(m.PEMPublic))+"]", len(m.PEMPublic), "b")
	println("TXT_ENC: ", "["+shorter(string(m.DataEncrypted))+"]", len(m.DataEncrypted), "b")
	println("TXT_PLN: ", "["+shorter(string(m.DataPlain))+"]", len(m.DataPlain), "b")
}

func (m *RSA) Reset() {
	m.PEMPublic = nil
	m.PEMPrivate = nil
	m.DataEncrypted = nil
	m.DataPlain = nil
}
