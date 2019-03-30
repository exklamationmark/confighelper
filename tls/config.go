/*
Package tls provides shared functionality for configurations related to TLS.

At the moment, it support runtime checks for a "TLS bundle".

Terminologies:
  - TLS bundle:
    a collection of files for CA certificate(s), certificate, key and optionally, key password.
    It is used to establish mututal TLS connections.
	All files are assumed to be in PEM format.
    The term is derived from "CA bundle".
*/
package tls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"

	"github.com/pkg/errors"
)

// Config contains options for chrono components to communicate over TLS.
// It designed be used in YAML files.
type Config struct {
	InsecureSkipTLS   bool   `yaml:"insecureSkipTLS"`   // convention: false
	CACertificateFile string `yaml:"caCertificateFile"` // convention: ca-certificate.pem
	CertificateFile   string `yaml:"certificateFile"`   // convention: certificate.pem
	KeyFile           string `yaml:"keyFile"`           // convention: key.pem
	KeyPasswordFile   string `yaml:"keyPasswordFile"`   // optional; convention: key.password
}

// Check performs a  validation on values of a TLS config, including:
//   - assert that either InsecureSkipTLS == true and no files are specified;
//     or that InsecureSkipTLS == false and at least CACertificateFile,
//     CertificateFile and KeyFile are specified.
//   - for CACertificateFile, CertificateFile, KeyFile and KeyPasswordFile,
//     assert that they are readable files if the field is specified.
//   - assert that the content of CACertificateFile, CertificateFile, KeyFile
//     and KeyPasswordFile (if specified), can be used to generate valid
//     *tls.Config.
//
// It can be used in conjunction with Ping or PingInsecureSkipVerify to verify
// that we can connect to a server through TLS.
func Check(c *Config) error {
	haveCAFile := len(c.CACertificateFile) > 0
	haveCertFile := len(c.CertificateFile) > 0
	haveKeyFile := len(c.KeyFile) > 0
	haveKeyPasswordFile := len(c.KeyPasswordFile) > 0
	haveTLSFiles := haveCAFile || haveCertFile || haveKeyFile || haveKeyPasswordFile
	if c.InsecureSkipTLS == haveTLSFiles { // xor
		return errors.New("either use 'insecureSkipTLS: false' and specify TLS files or 'insecureSkipTLS: true' with no files")
	}
	if c.InsecureSkipTLS {
		return nil
	}

	if _, err := tlsConfigFromStruct(c); err != nil {
		return err
	}

	return nil
}

// Ping checks if we can connect to a given server over mutual TLS.
//
// It also verify that the hostname on server's certificates is correct.
func Ping(c *Config, serverAddr, serverName string) error {
	if len(serverName) < 1 {
		return errors.New("need serverName")
	}
	return ping(c, serverAddr, serverName)
}

// PingInsecureSkipVerify also checks if we can connect to a given address
// over TLS. However, it skip hostname verification
// (i.e., use tls.Config's InsecureSkipVerify).
func PingInsecureSkipVerify(c *Config, serverAddr string) error {
	return ping(c, serverAddr, "")
}

// ping checks connection to a listener over TLS.
func ping(c *Config, addr, serverName string) error {
	config, err := tlsConfigFromStruct(c)
	if err != nil {
		return errors.Wrapf(err, "bad config")
	}
	if len(serverName) > 0 {
		config.ServerName = serverName
	} else {
		config.InsecureSkipVerify = true
	}

	conn, err := tls.Dial("tcp", addr, config)
	if err != nil {
		return errors.Wrapf(err, "cannot connect over TLS")
	}
	defer conn.Close()

	return nil
}

// tlsConfigFromStruct takes in a *Config that uses TLS, validate it
// and returns a *tls.Config to be used for Go TLS.
func tlsConfigFromStruct(c *Config) (*tls.Config, error) {
	if c.InsecureSkipTLS {
		panic("expecting a *Config where .InsecureSkipTLS is set to true")
	}

	// load CA cert
	caCert, err := ioutil.ReadFile(c.CACertificateFile)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot read file in 'caCertificateFile'")
	}
	caCerts := x509.NewCertPool()
	if ok := caCerts.AppendCertsFromPEM(caCert); !ok {
		return nil, errors.New("cannot create pool of CA certificate(s) from file content")
	}
	// load cert
	cert, err := ioutil.ReadFile(c.CertificateFile)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot read file in 'certificateFile'")
	}
	// load key
	key, err := ioutil.ReadFile(c.KeyFile)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot read file in 'keyFile'")
	}
	// if there is a key password, derypt keyPEM
	if len(c.KeyPasswordFile) > 0 {
		keyPassword, err := ioutil.ReadFile(c.KeyPasswordFile)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot read file in 'keyPasswordFile'")
		}
		if len(keyPassword) < 1 || (len(keyPassword) == 1 && keyPassword[0] == '\n') {
			// assumption: nobody uses '\n' as the actual password
			return nil, errors.New("file in 'keyPasswordFile' have no password")
		}
		key, err = decryptedPEM(key, keyPassword)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot decrypt key in 'keyFile' with given password")
		}
	}
	// load key + cert pair
	actualCert, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot load key pair using files in 'certificateFile' and 'keyFile'")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{actualCert},
		RootCAs:      caCerts,
	}, nil
}

// decryptedPEM takes a PEM-encoded block that is encrypted with a password,
// decrypt it and returns the result encoded in PEM format.
func decryptedPEM(encryptedPEM, password []byte) ([]byte, error) {
	pemBlock, _ := pem.Decode(encryptedPEM)
	if pemBlock == nil {
		return nil, errors.New("format is not PEM")
	}
	if !x509.IsEncryptedPEMBlock(pemBlock) {
		panic("key is not encrypted with a password")
	}
	decryptedKey, err := x509.DecryptPEMBlock(pemBlock, password)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  pemBlock.Type,
		Bytes: decryptedKey,
	}), nil
}
