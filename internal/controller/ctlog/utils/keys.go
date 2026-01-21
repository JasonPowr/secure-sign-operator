package utils

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/youmark/pkcs8"
)

const (
	curveType = "p256"
)

type KeyConfig struct {
	PrivateKey     []byte
	PrivateKeyPass []byte
	PublicKey      []byte
}

func (k KeyConfig) ToMap() map[string][]byte {
	return map[string][]byte{
		"private":  k.PrivateKey,
		"public":   k.PublicKey,
		"password": k.PrivateKeyPass,
	}
}

func CreatePrivateKey(password []byte) (*KeyConfig, error) {

	key, err := ecdsa.GenerateKey(supportedCurves[curveType], rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	var block *pem.Block
	if len(password) > 0 {
		der, err := pkcs8.MarshalPrivateKey(key, password, pkcs8.DefaultOpts)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt private key (PKCS#8): %w", err)
		}

		block = &pem.Block{
			Type:  "ENCRYPTED PRIVATE KEY",
			Bytes: der,
		}
	} else {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}

		block = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		}
	}

	var pemKey bytes.Buffer
	if err := pem.Encode(&pemKey, block); err != nil {
		return nil, err
	}

	mPubKey, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, err
	}

	var pemPubKey bytes.Buffer
	if err := pem.Encode(&pemPubKey, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: mPubKey,
	}); err != nil {
		return nil, err
	}

	return &KeyConfig{
		PrivateKey:     pemKey.Bytes(),
		PublicKey:      pemPubKey.Bytes(),
		PrivateKeyPass: password,
	}, nil
}

func GeneratePublicKey(certConfig *KeyConfig) (*KeyConfig, error) {
	var signer crypto.Signer
	var priv crypto.PrivateKey
	var err error
	var ok bool

	privatePEMBlock, _ := pem.Decode(certConfig.PrivateKey)
	if privatePEMBlock == nil {
		return nil, fmt.Errorf("failed to decode private key")
	}

	switch privatePEMBlock.Type {
	case "ENCRYPTED PRIVATE KEY":
		if len(certConfig.PrivateKeyPass) == 0 {
			return nil, fmt.Errorf("can't find private key password")
		}
		if priv, err = pkcs8.ParsePKCS8PrivateKey(privatePEMBlock.Bytes, certConfig.PrivateKeyPass); err != nil {
			return nil, fmt.Errorf("failed to decrypt private key: %w", err)
		}
	default:
		der := privatePEMBlock.Bytes
		if x509.IsEncryptedPEMBlock(privatePEMBlock) { //nolint:staticcheck
			if len(certConfig.PrivateKeyPass) == 0 {
				return nil, fmt.Errorf("can't find private key password")
			}
			der, err = x509.DecryptPEMBlock(privatePEMBlock, certConfig.PrivateKeyPass) //nolint:staticcheck
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt private key: %w", err)
			}
		}

		if priv, err = x509.ParsePKCS8PrivateKey(der); err != nil {
			// Try it as RSA
			if priv, err = x509.ParsePKCS1PrivateKey(der); err != nil {
				if priv, err = x509.ParseECPrivateKey(der); err != nil {
					return nil, fmt.Errorf("failed to parse private key PEM: %w", err)
				}
			}
		}
	}

	if signer, ok = priv.(crypto.Signer); !ok {
		return nil, fmt.Errorf("failed to convert to crypto.Signer")
	}

	mPubKey, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, err
	}
	var pemPubKey bytes.Buffer
	err = pem.Encode(&pemPubKey, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: mPubKey,
	})
	if err != nil {
		return nil, err
	}
	certConfig.PublicKey = pemPubKey.Bytes()
	return certConfig, nil
}
