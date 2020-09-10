# anEnc

anEnc is OpenSSL compatible with AES 256 CBC algorithm and can be tested with OpenSSL as below.

Encrypt

```sh
# Encrypt: test
# Output: U2FsdGVkX1/B4uNKrFh06GGpoYPHXiAjRw3PhEEPOjo= (will be differ each run due to the salt key)
echo "test" | openssl enc -e -aes-256-cbc -a -k myPwd  
```
 
Decrypt

```sh
# Decrypt: U2FsdGVkX1/B4uNKrFh06GGpoYPHXiAjRw3PhEEPOjo=
# Output: test
echo "U2FsdGVkX1/B4uNKrFh06GGpoYPHXiAjRw3PhEEPOjo=" | openssl enc -d -aes-256-cbc -a -k myPwd
```

## Usage: Encryption

```go
aes := anenc.NewAES( []byte("myPwd") )
encrypted, _ := aes.Encrypt( []byte("mySecretDataGoeshere") )
println(base64.StdEncoding.EncodeToString(encrypted)) // ret: U2FsdGVkX1+vBuzVPzcCUSIVkzya0fH/Cbuw4YG8ZxDSu1mDiAC0FHWWZ/ncpB0W
```

```sh
> echo "U2FsdGVkX1+vBuzVPzcCUSIVkzya0fH/Cbuw4YG8ZxDSu1mDiAC0FHWWZ/ncpB0W" | openssl enc -d -aes-256-cbc -a -k myPwd
  mySecretDataGoeshere
```

## Usage: Decrypt

```sh
echo "gon is always gone" | openssl enc -e -aes-256-cbc -a -k myPwd
  U2FsdGVkX19xNwC5ILkb94ffvVNhQTIUbGExFAHcyaQ3LkN4GR2CqT5Xu5LjI8bi
```

```go
b64decoded, _ := base64.StdEncoding.DecodeString("U2FsdGVkX19xNwC5ILkb94ffvVNhQTIUbGExFAHcyaQ3LkN4GR2CqT5Xu5LjI8bi")
decoded, _ := aes.Decrypt( b64decoded )
println(string(decoded)) // ret: gon is always gone
```
