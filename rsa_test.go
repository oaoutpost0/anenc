package anenc_test

import (
	"bytes"
	"github.com/orangenumber/anenc"
	"testing"
)

func TestNewRSA(t *testing.T) {
	testPrivateKey := `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAsEWW0PcM2+GSLnwzzgaYebyfqZ2aJdVeXhGWcrASOPRGvBUv
kg40aEClA3ENWhA09/gW+xrgPYMWZ72jRJFJ0vaHcaJcbB5XgTZ7Qz/2Dqw+OPIq
a88U2mVUW8dRbC4gxB/AWERKkyl6w8v1IgB/JyUw2frKn9lmcCCXYA1MdnWpVb9s
M7tL6tOUQtWL/VXvdkGYp/QLGuFkkMt0ComtWs6BTbbk8VfT51jcl9QIX4VQmZks
CsQrYqMMiEM4bIW622TBTDdUy76jVmT5mI5/PHc8iw2xHjXi4hhO/gkSXi2pwzWp
exl2bycabK/ZrgD2q6y2T4sSu6nGzLDp/z9dswIDAQABAoIBAHImzrFKm/g1Dx6t
bjsIyGtlvJvyJSZFFBSlHSHuZg6eGsSoj6LtMgElg/dDmhruDe9bqT46PGd5YeQS
yg2YbQ+CeVocg++8gnx6FL8LR8RexPjJ0rD4bQ+1uTiqTk9ZW/zGdyByMT02CnuL
tJatbaqjCgzPvbJg7lbEtGMOmarIGiV2xobkF/e8I4QK2vpjzpfyNlsbzFc3rHyd
hnQpwWut4jA3ijKkVma2+yIlCTBBpkNi3NjINO1krowwg+ENQlWj4/G1xyW7ynql
sYGj3/wAyYnRugTpAAn1XEpbE8QxumEoMka6s00BAJWnBscvkrAJgZdWJpjHbMD8
QARY+qECgYEA4RQ6HDF5EItNALjEdFfWXRZ9iXzb9eQwb7zhNdP8wTLU0fIzpjkd
N61GE2Ew84nRLOnTPXhOA3q1LjxSxF9N6KmgWclBJrk59U/k++nkTHac1e8/0wkX
vLVBRM7MoPySsNU4TmQU4+mubfHYVrpX4Tbf8qXoaq1QIULCwiYOH0MCgYEAyHze
fojvcFo2ACqxsREDI8ZMHO/upy34EXi39e27abIOSm/lZ9srJOpdkghmx0flBNCr
oBllF+ffB7yRC9pl/73t3sI4Sl1qsvgKWxiqzcT2N3i+wjFzEpVy6is8F6GFv6nY
AntRBT/88Z0TQs6onsAxAsBSqvUz+u+duGAPSNECgYA8k1sIV3BDuZnhxdhpj3JL
30+t/wKb7Ov0Rps+B22Q+YM5dbvc0qZAY8vmT1QDV2YKdmu5sXUdjprQdL+5xgSL
x4s2Xum/6D3m/bec7NfalFmlYhyFSX8v9IA6aoW8Ff3MxbW/s0PECxI82Mfmn4Qj
QseG4IvqmfZk3TjZU7CdTQKBgGEfPJmHtJZ03RwPkqz4VNELyutpv+708etk05kr
ZVK6kvm0YymAntHvRwzrTP7U8Tj37WxNYQ/Hn9+blZhsYGUXmRgEdkhwILQ6PKoM
tRGhjLUqpR5l3hzukRCniSDZenVyzdXF72XfraVONnpyqnTdHeD7UhDHYDr7wSgE
QONBAoGAQ1B8qgaODIw7l9f7RUiUmwvKxEt5EeETydg9h3gygnO8Mx5QrJ7cJBHE
eAhiRUFob27CpysY2nkf8HdlKMWCLnVtvjOPs/bpzaljUfW3tzDU4JJ8Cv6JdwnV
pwycQg/DXtj9CzRvTEEByrZARvZNUTcUfMf8dAfklDx2bU+X+LY=
-----END RSA PRIVATE KEY-----`

	rawTxt := "this is my home"
	verbose := false

	rsa := anenc.NewRSA()
	rsa.PEMPrivate = []byte(testPrivateKey)
	rsa.DataPlain = []byte(rawTxt)
	// if err := rsa.GetPubKeyFromPriKey(); err != nil {println(err.Error())}
	if err := rsa.Encrypt(); err != nil {
		t.Errorf(err.Error())
		t.Fail()
	}

	if verbose {
		println("encrypted: [", rsa.DataEncrypted, "]\n")
	}
	// G85iGLFvqGdVWb00+pdVIo8cRPNzBABFBntHE1VXV1P96CipIHglnUL1v3rwy74/KLMBD4L7TmIoDgFYS1Fd0n49SlPrBoOoCybiPLc6I+lQ8OnsNcFAAir3hVUSFWNF6IyfmKal2kU+aYpWZEc8GQ6HO7A/fz7cwuEyKKCL9K2ZqKfWShk3VmifnSUyFJqSRrFz9ODxHaklvhurNJx0KRRvlbgv5RDZOUD5KXZ1UeZOak0+Uh/+CIa5QnVlcKTVWoJujQMIlS5KNSMglIQ6/f3JN1PO5t3RBxclblxh9TGp7sF4J4mSbDHo+tF4ZlStH8UNtrdJT7UsJnNnxkI5XQ==

	rsa.Reset()
	if verbose {
		println("PriKey: [", rsa.PEMPrivate,
			"]\nPubKey: [", rsa.PEMPrivate,
			"]\nTxtPlain: [", rsa.DataPlain,
			"]\nTxtEncrypted: [", rsa.DataEncrypted, "]\n")
	}
	rsa.DataEncrypted = []byte("G85iGLFvqGdVWb00+pdVIo8cRPNzBABFBntHE1VXV1P96CipIHglnUL1v3rwy74/KLMBD4L7TmIoDgFYS1Fd0n49SlPrBoOoCybiPLc6I+lQ8OnsNcFAAir3hVUSFWNF6IyfmKal2kU+aYpWZEc8GQ6HO7A/fz7cwuEyKKCL9K2ZqKfWShk3VmifnSUyFJqSRrFz9ODxHaklvhurNJx0KRRvlbgv5RDZOUD5KXZ1UeZOak0+Uh/+CIa5QnVlcKTVWoJujQMIlS5KNSMglIQ6/f3JN1PO5t3RBxclblxh9TGp7sF4J4mSbDHo+tF4ZlStH8UNtrdJT7UsJnNnxkI5XQ==")
	rsa.PEMPrivate = []byte(testPrivateKey)
	if err := rsa.Decrypt(); err != nil {
		t.Errorf(err.Error())
		t.Fail()
	}
	if verbose {
		println("decrypted", rsa.DataPlain)
	}

	if !bytes.Equal([]byte(rawTxt), rsa.DataPlain) {
		t.Errorf("Decrypted string does not match with the raw string: [%s] vs [%s]", rawTxt, rsa.DataPlain)
		t.Fail()
	}
}


func TestNewRSA2(t *testing.T) {
	testPrivateKey := `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAsEWW0PcM2+GSLnwzzgaYebyfqZ2aJdVeXhGWcrASOPRGvBUv
kg40aEClA3ENWhA09/gW+xrgPYMWZ72jRJFJ0vaHcaJcbB5XgTZ7Qz/2Dqw+OPIq
a88U2mVUW8dRbC4gxB/AWERKkyl6w8v1IgB/JyUw2frKn9lmcCCXYA1MdnWpVb9s
M7tL6tOUQtWL/VXvdkGYp/QLGuFkkMt0ComtWs6BTbbk8VfT51jcl9QIX4VQmZks
CsQrYqMMiEM4bIW622TBTDdUy76jVmT5mI5/PHc8iw2xHjXi4hhO/gkSXi2pwzWp
exl2bycabK/ZrgD2q6y2T4sSu6nGzLDp/z9dswIDAQABAoIBAHImzrFKm/g1Dx6t
bjsIyGtlvJvyJSZFFBSlHSHuZg6eGsSoj6LtMgElg/dDmhruDe9bqT46PGd5YeQS
yg2YbQ+CeVocg++8gnx6FL8LR8RexPjJ0rD4bQ+1uTiqTk9ZW/zGdyByMT02CnuL
tJatbaqjCgzPvbJg7lbEtGMOmarIGiV2xobkF/e8I4QK2vpjzpfyNlsbzFc3rHyd
hnQpwWut4jA3ijKkVma2+yIlCTBBpkNi3NjINO1krowwg+ENQlWj4/G1xyW7ynql
sYGj3/wAyYnRugTpAAn1XEpbE8QxumEoMka6s00BAJWnBscvkrAJgZdWJpjHbMD8
QARY+qECgYEA4RQ6HDF5EItNALjEdFfWXRZ9iXzb9eQwb7zhNdP8wTLU0fIzpjkd
N61GE2Ew84nRLOnTPXhOA3q1LjxSxF9N6KmgWclBJrk59U/k++nkTHac1e8/0wkX
vLVBRM7MoPySsNU4TmQU4+mubfHYVrpX4Tbf8qXoaq1QIULCwiYOH0MCgYEAyHze
fojvcFo2ACqxsREDI8ZMHO/upy34EXi39e27abIOSm/lZ9srJOpdkghmx0flBNCr
oBllF+ffB7yRC9pl/73t3sI4Sl1qsvgKWxiqzcT2N3i+wjFzEpVy6is8F6GFv6nY
AntRBT/88Z0TQs6onsAxAsBSqvUz+u+duGAPSNECgYA8k1sIV3BDuZnhxdhpj3JL
30+t/wKb7Ov0Rps+B22Q+YM5dbvc0qZAY8vmT1QDV2YKdmu5sXUdjprQdL+5xgSL
x4s2Xum/6D3m/bec7NfalFmlYhyFSX8v9IA6aoW8Ff3MxbW/s0PECxI82Mfmn4Qj
QseG4IvqmfZk3TjZU7CdTQKBgGEfPJmHtJZ03RwPkqz4VNELyutpv+708etk05kr
ZVK6kvm0YymAntHvRwzrTP7U8Tj37WxNYQ/Hn9+blZhsYGUXmRgEdkhwILQ6PKoM
tRGhjLUqpR5l3hzukRCniSDZenVyzdXF72XfraVONnpyqnTdHeD7UhDHYDr7wSgE
QONBAoGAQ1B8qgaODIw7l9f7RUiUmwvKxEt5EeETydg9h3gygnO8Mx5QrJ7cJBHE
eAhiRUFob27CpysY2nkf8HdlKMWCLnVtvjOPs/bpzaljUfW3tzDU4JJ8Cv6JdwnV
pwycQg/DXtj9CzRvTEEByrZARvZNUTcUfMf8dAfklDx2bU+X+LY=
-----END RSA PRIVATE KEY-----`

	rawTxt := "this is my home"
	verbose := false

	rsa := anenc.NewRSA()
	rsa.SetPEMPrivate(testPrivateKey)
	rsa.SetDataPlain(rawTxt)

	if err := rsa.Encrypt(); err != nil {
		t.Errorf(err.Error())
		t.Fail()
	}

	if verbose {
		println("encrypted: [", rsa.GetDataEncrypted(), "]\n")
	}
	// G85iGLFvqGdVWb00+pdVIo8cRPNzBABFBntHE1VXV1P96CipIHglnUL1v3rwy74/KLMBD4L7TmIoDgFYS1Fd0n49SlPrBoOoCybiPLc6I+lQ8OnsNcFAAir3hVUSFWNF6IyfmKal2kU+aYpWZEc8GQ6HO7A/fz7cwuEyKKCL9K2ZqKfWShk3VmifnSUyFJqSRrFz9ODxHaklvhurNJx0KRRvlbgv5RDZOUD5KXZ1UeZOak0+Uh/+CIa5QnVlcKTVWoJujQMIlS5KNSMglIQ6/f3JN1PO5t3RBxclblxh9TGp7sF4J4mSbDHo+tF4ZlStH8UNtrdJT7UsJnNnxkI5XQ==

	rsa.Reset()
	if verbose {
		println("PriKey: [", rsa.GetPEMPrivate(),
			"]\nPubKey: [", rsa.GetPEMPrivate(),
			"]\nTxtPlain: [", rsa.GetDataPlain(),
			"]\nTxtEncrypted: [", rsa.GetDataEncrypted(), "]\n")
	}
	rsa.SetDataEncrypted("G85iGLFvqGdVWb00+pdVIo8cRPNzBABFBntHE1VXV1P96CipIHglnUL1v3rwy74/KLMBD4L7TmIoDgFYS1Fd0n49SlPrBoOoCybiPLc6I+lQ8OnsNcFAAir3hVUSFWNF6IyfmKal2kU+aYpWZEc8GQ6HO7A/fz7cwuEyKKCL9K2ZqKfWShk3VmifnSUyFJqSRrFz9ODxHaklvhurNJx0KRRvlbgv5RDZOUD5KXZ1UeZOak0+Uh/+CIa5QnVlcKTVWoJujQMIlS5KNSMglIQ6/f3JN1PO5t3RBxclblxh9TGp7sF4J4mSbDHo+tF4ZlStH8UNtrdJT7UsJnNnxkI5XQ==")
	rsa.SetPEMPrivate(testPrivateKey)
	if err := rsa.Decrypt(); err != nil {
		t.Errorf(err.Error())
		t.Fail()
	}
	if verbose {
		println("decrypted", rsa.GetDataPlain())
	}

	if !bytes.Equal([]byte(rawTxt), rsa.DataPlain) {
		t.Errorf("Decrypted string does not match with the raw string: [%s] vs [%s]", rawTxt, rsa.GetDataPlain())
		t.Fail()
	}
}
