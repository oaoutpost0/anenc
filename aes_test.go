package anenc_test

import (
	"bytes"
	"encoding/base64"
	"github.com/orangenumber/anenc"
	"testing"
)

func TestStds(t *testing.T) {
	rawPasswd := []byte("123")
	rawData := []byte("awesome worked!")

	// Encode
	b, err := anenc.Encrypt(rawPasswd, rawData)
	if err != nil {
		t.Error(err.Error())
	}
	encodedStr := base64.StdEncoding.EncodeToString(b)
	// println(encodedStr)

	// Decode
	b, err = base64.StdEncoding.DecodeString(encodedStr)
	if err != nil {
		t.Error(err.Error())
	}
	b, err = anenc.Decrypt(rawPasswd, b)

	if !bytes.Equal(rawData, b) {
		t.Fail()
	}
}

func TestStds_withBase64Func(t *testing.T) {
	rawPasswd := []byte("123")
	rawData := []byte("awesome worked!")

	// Encode
	b, err := anenc.Encrypt(rawPasswd, rawData)
	if err != nil {
		t.Error(err.Error())
	}
	encodedStr := anenc.Base64Enc(b)
	// println(encodedStr)

	// Decode
	b, err = anenc.Base64Dec(encodedStr)
	if err != nil {
		t.Error(err.Error())
	}
	b, err = anenc.Decrypt(rawPasswd, b)

	if !bytes.Equal(rawData, b) {
		t.Fail()
	}
}

func TestAES(t *testing.T) {
	testData := [][]string{
		[]string{"123", "gonyi"},
		[]string{"1231231231231234354", "gonyi12312312312312343541231231231231234354"},
		[]string{"base64.StdEncoding.Encode", "gonyi1234567890123456789012345678901234567890gonyi1234567890123456789012345678901234567890"},
	}

	a := anenc.NewAES(nil)
	for _, v := range testData {
		// v[0] = pwd, v[1] = data

		// =============
		// ENCODING
		// =============
		a.SetKeyStr(v[0])
		b, err := a.Encrypt([]byte(v[1]))
		if err != nil {
			println(err.Error())
			t.Fatalf("1: %s", err)
		}
		b64_encoded := anenc.Base64Enc(b)
		// b64_encoded := base64.StdEncoding.EncodeToString(b)

		// =============
		// DECODE
		// =============
		b64_enc_decoded, err := anenc.Base64Dec(b64_encoded)
		// b64_enc_decoded, err := base64.StdEncoding.DecodeString(b64_encoded)
		if err != nil {
			println(err.Error())
			t.Fatalf("2: %s", err)
		}
		b, err = a.Decrypt(b64_enc_decoded)
		if err != nil {
			println(err.Error())
			t.Fatalf("3: %s", err)
		}
		// fmt.Printf("%s / %s\n\t--> %s\n\t%s\n", v[0], v[1], b64_encoded, string(b))
		if v[1] != string(b) {
			t.Failed()
		}
	}
}
