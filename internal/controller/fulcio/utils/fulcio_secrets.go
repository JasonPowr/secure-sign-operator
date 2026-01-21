package utils

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/youmark/pkcs8"
)

type FulcioCertConfig struct {
	PrivateKey         []byte
	PublicKey          []byte
	RootCert           []byte
	PrivateKeyPassword []byte
	OrganizationName   string
	CommonName         string
	OrganizationEmail  string
}

func (c FulcioCertConfig) ToData() map[string][]byte {
	result := make(map[string][]byte)

	if len(c.PrivateKey) > 0 {
		result["private"] = c.PrivateKey
	}
	if len(c.PublicKey) > 0 {
		result["public"] = c.PublicKey
	}
	if len(c.PrivateKeyPassword) > 0 {
		result["password"] = c.PrivateKeyPassword
	}
	if len(c.RootCert) > 0 {
		result["cert"] = c.RootCert
	}

	return result
}

func CreateCAKey(key *ecdsa.PrivateKey, password []byte) ([]byte, error) {
	var (
		block *pem.Block
	)
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
			return nil, fmt.Errorf("failed to marshal private key (PKCS#8): %w", err)
		}
		block = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		}
	}

	var pemData bytes.Buffer
	if err := pem.Encode(&pemData, block); err != nil {
		return nil, err
	}

	return pemData.Bytes(), nil
}

func CreateCAPub(key crypto.PublicKey) ([]byte, error) {
	mPubKey, err := x509.MarshalPKIXPublicKey(key)
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

	return pemPubKey.Bytes(), nil
}

func CreateFulcioCA(config *FulcioCertConfig) ([]byte, error) {
	var err error

	if config.OrganizationName == "" {
		return nil, fmt.Errorf("could not create certificate: missing OrganizationName from config")
	}

	block, _ := pem.Decode(config.PrivateKey)
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key")
	}

	var key *ecdsa.PrivateKey
	switch block.Type {
	case "ENCRYPTED PRIVATE KEY":
		if len(config.PrivateKeyPassword) == 0 {
			return nil, fmt.Errorf("input private key is encrypted but no password was provided")
		}
		parsed, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, config.PrivateKeyPassword)
		if err != nil {
			return nil, err
		}
		var ok bool
		key, ok = parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("unsupported private key type %T", parsed)
		}
	default:
		keyBytes := block.Bytes
		if x509.IsEncryptedPEMBlock(block) { //nolint:staticcheck
			keyBytes, err = x509.DecryptPEMBlock(block, config.PrivateKeyPassword) //nolint:staticcheck
			if err != nil {
				return nil, err
			}
		}

		switch block.Type {
		case "EC PRIVATE KEY":
			key, err = x509.ParseECPrivateKey(keyBytes)
			if err != nil {
				return nil, err
			}
		case "PRIVATE KEY":
			parsed, err := x509.ParsePKCS8PrivateKey(keyBytes)
			if err != nil {
				return nil, err
			}
			var ok bool
			key, ok = parsed.(*ecdsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("unsupported private key type %T", parsed)
			}
		default:
			return nil, fmt.Errorf("unsupported private key PEM type: %s", block.Type)
		}
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * 10 * time.Hour)

	issuer := pkix.Name{
		CommonName:   config.CommonName,
		Organization: []string{config.OrganizationName},
	}

	serialNumber, err := GenerateSerialNumber()
	if err != nil {
		return nil, err
	}

	emailAddresses := make([]string, 0)

	if config.OrganizationEmail != "" {
		emailAddresses = append(emailAddresses, config.OrganizationEmail)
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               issuer,
		EmailAddresses:        emailAddresses,
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		Issuer:                issuer,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
	}

	fulcioRoot, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		return nil, err
	}

	var pemFulcioRoot bytes.Buffer
	err = pem.Encode(&pemFulcioRoot, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: fulcioRoot,
	})
	if err != nil {
		return nil, err
	}

	return pemFulcioRoot.Bytes(), nil
}

// GenerateSerialNumber creates a compliant serial number as per RFC 5280 4.1.2.2.
// Serial numbers must be positive, and can be no longer than 20 bytes.
// The serial number is generated with 159 bits, so that the first bit will always
// be 0, resulting in a positive serial number.
func GenerateSerialNumber() (*big.Int, error) {
	// Pick a random number from 0 to 2^159.
	serial, err := rand.Int(rand.Reader, (&big.Int{}).Exp(big.NewInt(2), big.NewInt(159), nil))
	if err != nil {
		return nil, errors.New("error generating serial number")
	}
	return serial, nil
}
