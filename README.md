# anEnc

(c) 2020 Orange Number.
Written by Gon Yi. <https://gonyyi.com/copyright.txt>


anEnc is an encryption library includes:

- RSA
- AES-256 CBC _(compatible with OpenSSL)_
- SHA-256
- Encoding
    - Base 64
    - HEX

__Note:__ Any function or method with a prefix `Must` will not return an error.
Instead it will take a fallback values as addition to its necessary parameter(s).  
_(eg: `func MustHexDec(b, fallback []byte) []byte` vs `func HexDec(b []byte) ([]byte, error)`)_

__Note:__ Any function or method with a suffix `i` will take either `io.Reader` or `io.Writer` interface.  
_(eg: `func SHA256i(ior io.Reader) ([]byte, error)`)_


---

## RSA

There are 4 key byte slice variables in RSA struct.

- `PEMPrivate`
- `PEMPublic`
- `DataEncrypted`
- `DataPlain`

What needs to be filled?

- Encrypt:
    - `PEMPublic` + `DataPlain` = `DataEncrypted`
    - or `PEMPrivate` + `DataPlain` = `DataEncrypted`  
        _(this is because you can create a public key from the private key)_
- Decrypt:
    - `PEMPrivate` + `DataEncrypted` = `DataPlain`


### Usage: Encrypt

For encryption, public key is needed. However, this can be generated from private key.
When rsa.Encrypt() runs, it will check if public key is available, if not, it will generate
a public key to encrypt.

```go
rsa := anenc.NewRSA()

privKey := "-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEAsEWW0PcM2+...."

rsa.SetPEMPrivate(privKey) // set string of private key
// rsa.PEMPrivate = []byte(privKey) // OR byte slice of private key

rsa.SetDataPlain("this is my secret data")
// rsa.DataPlain = []byte(rawTxt) // OR byte slice can be used

if err := rsa.Encrypt(); err != nil {
    t.Errorf(err.Error())
    t.Fail()
}
```

### Usage: Decrypt

When decrypt, private key is needed along with encrypted data.

```go
rsa := anenc.NewRSA()
privKey := "-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEAsEWW0PcM2+...."

// SetPEMPrivate() and GetPEMPrivate() will deal with string type.
rsa.SetPEMPrivate(privKey)

// If encrypted data is byte slice, it can directly added by
// rsa.DataEncrypted = encryptedDataBytes
rsa.SetDataEncrypted("G85iGLFvqGdVWb00+pdVIo8cRPNzBABFBntHE1VXV1P96CipIHglnUL1v3rwy74...")

if err := rsa.Decrypt(); err != nil {
    println(err.Error())
} else {
    println(rsa.GetDataPlain())
}
```

---

## AES

OpenSSL compatible with AES 256 CBC algorithm and can be tested with OpenSSL as below.


### Usage: Encrypt

```go
aes := anenc.NewAES( []byte("myPwd") )
encrypted, _ := aes.Encrypt( []byte("mySecretDataGoeshere") )
println(base64.StdEncoding.EncodeToString(encrypted)) // ret: U2FsdGVkX1+vBuzVPzcCUSIVkzya0fH/Cbuw4YG8ZxDSu1mDiAC0FHWWZ/ncpB0W
```

```sh
> echo "U2FsdGVkX1+vBuzVPzcCUSIVkzya0fH/Cbuw4YG8ZxDSu1mDiAC0FHWWZ/ncpB0W" | openssl enc -d -aes-256-cbc -a -k myPwd
  mySecretDataGoeshere
```


### Usage: Decrypt

```sh
echo "gon is always gone" | openssl enc -e -aes-256-cbc -a -k myPwd
  U2FsdGVkX19xNwC5ILkb94ffvVNhQTIUbGExFAHcyaQ3LkN4GR2CqT5Xu5LjI8bi
```

```go
b64decoded, _ := base64.StdEncoding.DecodeString("U2FsdGVkX19xNwC5ILkb94ffvVNhQTIUbGExFAHcyaQ3LkN4GR2CqT5Xu5LjI8bi")
decoded, _ := aes.Decrypt( b64decoded )
println(string(decoded)) // ret: gon is always gone
```
