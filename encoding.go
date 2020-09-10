package anenc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
)

// =====================================================================================================================
// ENCODING -- BASE64
// =====================================================================================================================
func Base64Enc(b []byte) []byte {
	base64Text := make([]byte, base64.StdEncoding.EncodedLen(len(b)))
	base64.StdEncoding.Encode(base64Text, []byte(b))
	return base64Text
}
func Base64Dec(b []byte) ([]byte, error) {
	// Note: if decoding failes this will return empty string.
	base64Text := make([]byte, base64.StdEncoding.DecodedLen(len(b)))
	if l, err := base64.StdEncoding.Decode(base64Text, b); err != nil {
		return nil, err
	} else {
		return base64Text[:l], nil
	}
}
func MustBase64Dec(b []byte, fallback []byte) []byte {
	if out, err := Base64Dec(b); err != nil {
		return fallback
	} else {
		return out
	}
}

func HexEnc(b []byte) []byte {
	dst := make([]byte, hex.EncodedLen(len(b)))
	hex.Encode(dst, b)
	return dst
}

func HexDec(b []byte) ([]byte, error) {
	dst := make([]byte, hex.DecodedLen(len(b)))
	if n, err := hex.Decode(dst, b); err != nil {
		return nil, err
	} else {
		return dst[:n], nil
	}
}

func MustHexDec(b, fallback []byte) []byte {
	if out, err := HexDec(b); err != nil {
		return fallback
	} else {
		return out
	}
}

// =====================================================================================================================
// SHA 256 HASHING
// =====================================================================================================================
func SHA256(data []byte) [32]byte {
	return sha256.Sum256(data)
}
func SHA256i(ior io.Reader) ([]byte, error) {
	hash := sha256.New()
	if _, err := io.Copy(hash, ior); err != nil {
		return nil, err
	}
	sum := hash.Sum(nil)
	return sum, nil
}
func MustSHA256i(ior io.Reader, fallback []byte) []byte {
	if out, err := SHA256i(ior); err != nil {
		return fallback
	} else {
		return out
	}
}
