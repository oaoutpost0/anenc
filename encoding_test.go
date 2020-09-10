package anenc_test

import (
	"errors"
	"github.com/orangenumber/anenc"
	"strings"
	"testing"
)

func TestSHA256i(t *testing.T) {
	inp := "Hello, Gon!"
	expOut := "81f7ce53c28054d46fcbf6b74232f69fcfa192c26b70cd4ef146a4f18dc1cd1f"
	r := strings.NewReader(inp)

	s, err := anenc.SHA256i(r)
	if err != nil {
		t.Error(err.Error())
		t.Fail()
	}

	if string(anenc.HexEnc(s)) != expOut {
		t.Error(errors.New("unexpected output"))
		t.Fail()
	}
}

func TestSHA256(t *testing.T) {
	verbose := false
	out := anenc.SHA256([]byte("test"))
	// hex: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
	if verbose {
		println("out.string()", string(out[:]))
	}
	out_hex := anenc.HexEnc(out[:])
	if verbose {
		println("out.string().hex()", string(out_hex))
	}
	if string(out_hex) != "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Error("invalid sha256 returned")
		t.Fail()
	}

	out2, err := anenc.HexDec(out_hex)
	if err != nil {
		if verbose {
			println("err --> ", err.Error())
		}
		t.Error(err)
		t.Fail()
	}
	if verbose {
		println("ok --> ", string(out2))
	}
}

func TestHex(t *testing.T) {
	verbose := false
	rawTxt := "gon is awesome" // hex: 676f6e20697320617765736f6d65
	expHex := "676f6e20697320617765736f6d65"

	// Encode
	{
		rawTxt_hex := anenc.HexEnc([]byte(rawTxt))
		rawTxt_hex_str := string(rawTxt_hex)
		if rawTxt_hex_str != expHex {
			t.Error("invalid encoded hex")
			t.Fail()
		}
	}

	// Decode
	if out, err := anenc.HexDec([]byte(expHex)); err != nil {
		t.Error(err.Error())
		t.Fail()
	} else {
		if rawTxt != string(out) {
			t.Error("invalid decoded hex")
			t.Fail()
		}
		if verbose {
			println(10,"decoded hex: ", string(out))
		}
	}

	// Must Decode
	if out := anenc.MustHexDec([]byte(expHex), nil); string(out) != rawTxt {
		t.Error("invalid must decoded hex", string(out))
		t.Fail()
	} else {
		if verbose { println(20, "decoded hex: ", string(out))}
	}

}
