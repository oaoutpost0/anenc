// +build go1.10

package anenc

import (
	"hash"
	"io"
)

type rsaOption struct{}
var RSAOpt = new(rsaOption)

// random:           rand.Reader,
// bits:             2048,
// blockTypePrivate: "RSA PRIVATE KEY",
// blockTypePublic:  "RSA PUBLIC KEY",
// label:            []byte("orangenumber.com"),
// hash:             crypto.SHA256.New(),

func (r *rsaOption) SetRandom(rdr io.Reader) func(*RSA) {
	return func(rr *RSA) {
		rr.random = rdr
	}
}

func (r *rsaOption) SetBits(i int) func(*RSA) {
	return func(rr *RSA) {
		rr.bits = i
	}
}

func (r *rsaOption) SetBlockTypePrivate(s string) func(*RSA) {
	return func(rr *RSA) {
		rr.blockTypePrivate = s
	}
}

func (r *rsaOption) SetBlockTypePublic(s string) func(*RSA) {
	return func(rr *RSA) {
		rr.blockTypePublic = s
	}
}

func (r *rsaOption) SetLabel(b []byte) func(*RSA) {
	return func(rr *RSA) {
		rr.label = b
	}
}

func (r *rsaOption) SetHash(h hash.Hash) func(*RSA) {
	return func(rr *RSA) {
		rr.hash = h
	}
}

// =====================================================================================================================
// ERROR
// =====================================================================================================================

type ErrorRSA struct {
	Err error
}

func (e *ErrorRSA) Error() string {
	return e.Err.Error()
}
