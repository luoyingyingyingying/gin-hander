package rsautils

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"strings"

	"github.com/pkg/errors"
)

// ensure that encrypting the same message twice will has a result in the same ciphertext
func ZeroReader() io.Reader {
	return strings.NewReader(string(make([]byte, 1024)))
}

// ParsePrivateKey 从PEM格式的字符串解析RSA私钥
func ParsePrivateKey(pemData string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("invalid private key format")
	}

	var privateKey crypto.PrivateKey
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, errors.New("unsupported private key format")
	}
	if err != nil {
		return nil, errors.Wrapf(err, "parsePrivateKey %s", block.Type)
	}

	rpk, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}

	return rpk, nil
}

// LoadPrivateKey 从文件加载RSA私钥 
func LoadPrivateKey(filepath string) (*rsa.PrivateKey, error) {
	pemData, err := os.ReadFile(filepath)
	if err != nil {
		return nil, errors.Wrap(err, "readFile")
	}
	return ParsePrivateKey(string(pemData))
}

// ParsePublicKey 从PEM格式的字符串解析RSA公钥
func ParsePublicKey(pemData string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("invalid public key format")
	}

	var publicKey interface{}
	var err error
	switch block.Type {
	case "PUBLIC KEY":
		publicKey, err = x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		publicKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, errors.New("unsupported public key format")
	}

	if err != nil {
		return nil, errors.Wrapf(err, "parsePublicKey %s", block.Type)
	}

	rpk, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not RSA")
	}

	return rpk, nil
}

// LoadPublicKey 从文件加载RSA公钥  
func LoadPublicKey(filepath string) (*rsa.PublicKey, error) {
	pemData, err := os.ReadFile(filepath)
	if err != nil {
		return nil, errors.Wrap(err, "readFile")
	}
	return ParsePublicKey(string(pemData))
}

func Encrypt(random io.Reader, pk *rsa.PublicKey, payload []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), random, pk, payload, nil)
}

func Decrypt(random io.Reader, sk *rsa.PrivateKey, cipherText []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), random, sk, cipherText, nil)
}
