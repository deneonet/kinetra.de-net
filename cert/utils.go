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
	ErrClientRootKeyExpired     = errors.New("root key has expired")
	ErrServerCertificateExpired = errors.New("certificate has expired")
	ErrVersionMismatch          = errors.New("certificate and root key are not in sync")
	ErrFailedVerification       = errors.New("public key of certificate couldn't be verified")

	ErrCertificateSigningFailed = errors.New("failed to sign certificate")

	ErrECDSARootKeyGenerationFailed   = errors.New("failed to generate ECDSA root key")
	ErrECDHPrivateKeyGenerationFailed = errors.New("failed to generate ECDH private key")
	ErrServerPublicKeyCreationFailed  = errors.New("failed to create server's public key")

	// TODO: Make expiration time configurable
	DefaultCertificateExpiry = 365 * 24 * time.Hour // Default one year in hours
)

// VerifyCertificate verifies the certificate with the provided root key, returning the public key.
func VerifyCertificate(cert ServerCertificate, root ClientRootKey, expiry time.Duration) (*ecdh.PublicKey, error) {
	if cert.Version != root.Version {
		return nil, ErrVersionMismatch
	}

	if expiry == 0 {
		expiry = DefaultCertificateExpiry
	}

	if time.Now().Unix()-cert.CreatedAt > int64(expiry.Seconds()) {
		return nil, ErrServerCertificateExpired
	}
	if time.Now().Unix()-root.CreatedAt > int64(expiry.Seconds()) {
		return nil, ErrClientRootKeyExpired
	}

	publicKey, err := ecdh.P521().NewPublicKey(cert.PublicKey)
	if err != nil {
		return nil, ErrServerPublicKeyCreationFailed
	}

	rootKey := new(ecdsa.PublicKey)
	rootKey.Curve = elliptic.P521()
	rootKey.X, rootKey.Y = elliptic.UnmarshalCompressed(elliptic.P521(), root.Key)

	if !ecdsa.VerifyASN1(rootKey, publicKey.Bytes(), cert.PublicKeySignature) {
		return nil, ErrFailedVerification
	}

	return publicKey, nil
}

// GenerateCertificateChain generates a certificate chain and stores it in the specified file paths.
func GenerateCertificateChain(version int, certFilePath string, rootKeyFilePath string) error {
	privateKey, err := ecdh.P521().GenerateKey(rand.Reader)
	if err != nil {
		return ErrECDHPrivateKeyGenerationFailed
	}

	rootKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return ErrECDSARootKeyGenerationFailed
	}

	publicKey := privateKey.PublicKey().Bytes()
	signature, err := ecdsa.SignASN1(rand.Reader, rootKey, publicKey)
	if err != nil {
		return ErrCertificateSigningFailed
	}

	cert := ServerCertificate{
		PublicKey:          publicKey,
		PublicKeySignature: signature,
		PrivateKey:         privateKey.Bytes(),
		Version:            version,
		CreatedAt:          time.Now().Unix(),
	}

	root := ClientRootKey{
		Key:       elliptic.MarshalCompressed(elliptic.P521(), rootKey.PublicKey.X, rootKey.PublicKey.Y),
		Version:   version,
		CreatedAt: time.Now().Unix(),
	}

	certData := make([]byte, cert.Size())
	cert.Marshal(certData)

	if err := writeToFile(certFilePath, certData); err != nil {
		return err
	}

	rootKeyData := make([]byte, root.Size())
	root.Marshal(rootKeyData)

	if err := writeToFile(rootKeyFilePath, rootKeyData); err != nil {
		return err
	}

	return nil
}

func writeToFile(filePath string, data []byte) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.Write(data); err != nil {
		return err
	}

	if err := os.Chmod(filePath, 0600); err != nil {
		return err
	}

	return nil
}
