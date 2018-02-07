package jwtauth

import (
	"fmt"
	"io/ioutil"
	"os"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

// KeyProvider is interface to provide public keys
type KeyProvider interface {
	PublicKey() (interface{}, error)
}

// NewPublicKeyProvider returns a new public key provider parsed from PEM formatted bytes
func NewPublicKeyProvider(pem []byte) (KeyProvider, error) {
	if len(pem) <= 0 {
		return nil, fmt.Errorf("empty bytes for public key provided")
	}
	pk, err := ParsePublicKey(pem)
	if err != nil {
		return nil, err
	}
	return &publicKeyProvider{
		key: pk,
	}, nil
}

// NewLazyPublicKeyFileProvider returns a new lazy public key proivder from file
func NewLazyPublicKeyFileProvider(value string) (KeyProvider, error) {
	if len(value) <= 0 {
		return nil, fmt.Errorf("empty filename for public key provided")
	}
	return &lazyPublicKeyProvider{
		filename: value,
	}, nil
}

type publicKeyProvider struct {
	key interface{}
}

func (pkp *publicKeyProvider) PublicKey() (interface{}, error) {
	return pkp.key, nil
}

type lazyPublicKeyProvider struct {
	filename  string
	modTime   time.Time
	publicKey interface{}
}

func (pkp *lazyPublicKeyProvider) PublicKey() (interface{}, error) {
	if err := pkp.loadIfRequired(); err != nil {
		return nil, err
	}
	return pkp.publicKey, nil
}

func (pkp *lazyPublicKeyProvider) loadIfRequired() error {
	finfo, err := os.Stat(pkp.filename)
	if os.IsNotExist(err) {
		return fmt.Errorf("public key file '%s' does not exist", pkp.filename)
	}
	if pkp.publicKey == nil || !finfo.ModTime().Equal(pkp.modTime) {
		pkp.publicKey, err = ReadPublicKeyFile(pkp.filename)
		if err != nil {
			return fmt.Errorf("could not load public key file '%s': %v", pkp.filename, err)
		}
		if pkp.publicKey == nil {
			return fmt.Errorf("no public key contained in file '%s'", pkp.filename)
		}
	}
	return nil
}

// ParsePublicKey tries to parse rsa, ecdsa public key in PEM format from bytes
func ParsePublicKey(pem []byte) (interface{}, error) {
	result, err := jwt.ParseRSAPublicKeyFromPEM(pem)
	if err != nil {
		result2, err2 := jwt.ParseECPublicKeyFromPEM(pem)
		if err2 == nil {
			return result2, nil
		}
	}
	return result, err
}

// ReadPublicKeyFile tries to parse rsa, ecdsa public key in PEM format in file
func ReadPublicKeyFile(filepath string) (interface{}, error) {
	content, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	return ParsePublicKey(content)
}
