//go:generate bencgen --in ../schemas/RootKey.benc --out . --file root.benc --lang go
//go:generate bencgen --in ../schemas/Certificate.benc --out . --file cert.benc --lang go
package cert

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"os"
	"time"
)

var (
	ErrFailedVerification = errors.New("public key of certificate couldn't be verified")
	ErrCertificateExpired = errors.New("certificate has expired")
	ErrRootKeyExpired     = errors.New("root key has expired")

	ErrVersionMismatch = errors.New("certificate and root key are not in sync")

	oneYear = 365 * 24 * time.Hour // one year in hours
)

func VerifyCertificate(cert Certificate, root RootKey) (*ecdh.PublicKey, error) {
	if cert.Version != root.Version {
		return nil, ErrVersionMismatch
	}

	if time.Now().Unix()-cert.CreatedAt > int64(oneYear.Seconds()) {
		return nil, ErrCertificateExpired
	}
	if time.Now().Unix()-root.CreatedAt > int64(oneYear.Seconds()) {
		return nil, ErrRootKeyExpired
	}

	publicKey, err := ecdh.P521().NewPublicKey(cert.PublicKey)
	if err != nil {
		return nil, err
	}

	rootKey := new(ecdsa.PublicKey)
	rootKey.Curve = elliptic.P521()
	rootKey.X, rootKey.Y = elliptic.UnmarshalCompressed(elliptic.P521(), root.PublicKey)

	if !ecdsa.VerifyASN1(rootKey, publicKey.Bytes(), cert.PublicKeySignature) {
		return nil, ErrFailedVerification
	}

	return publicKey, nil
}

func GenerateCertificateChain(version int, certFilePath string, rootKeyFilePath string) error {
	privateKey, err := ecdh.P521().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	rootKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return err
	}

	publicKey := privateKey.PublicKey().Bytes()
	signature, err := ecdsa.SignASN1(rand.Reader, rootKey, publicKey)
	if err != nil {
		return err
	}

	cert := Certificate{
		PrivateKey:         privateKey.Bytes(),
		PublicKey:          publicKey,
		PublicKeySignature: signature,

		Version:   version,
		CreatedAt: time.Now().Unix(),
	}

	root := RootKey{
		PublicKey: elliptic.MarshalCompressed(elliptic.P521(), rootKey.PublicKey.X, rootKey.PublicKey.Y),

		Version:   version,
		CreatedAt: time.Now().Unix(),
	}

	certData := make([]byte, cert.Size())
	cert.Marshal(certData)

	certFile, err := os.Create(certFilePath)
	if err != nil {
		return err
	}
	defer certFile.Close()

	if _, err = certFile.Write(certData); err != nil {
		return err
	}

	rootKeyData := make([]byte, root.Size())
	root.Marshal(rootKeyData)

	rootKeyFile, err := os.Create(rootKeyFilePath)
	if err != nil {
		return err
	}
	defer rootKeyFile.Close()

	if _, err = rootKeyFile.Write(rootKeyData); err != nil {
		return err
	}

	return nil
}
