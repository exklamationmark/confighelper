package tls

import (
	"bytes"
	"context"
	"crypto/tls"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v2"
)

func TestCheckGood(t *testing.T) {
	configFiles := []string{
		"testdata/good.skip-tls.yml",
		"testdata/good.rsa-no-password.yml",
		"testdata/good.rsa-with-password.yml",
		"testdata/good.ec-no-password.yml",
		"testdata/good.ec-with-password.yml",
	}

	for _, file := range configFiles {
		b, err := ioutil.ReadFile(file)
		if err != nil {
			t.Fatalf("cannot read config file %q; err= %q", file, err)
		}
		var c Config
		if err := yaml.UnmarshalStrict(b, &c); err != nil {
			t.Fatalf("cannot unmarshal (strict) content of %q; err= %q", file, err)
		}

		if err := Check(&c); err != nil {
			t.Errorf("expect Check() to return no error, got %q", err)
		}
	}
}

func TestCheckBad(t *testing.T) {
	testCases := []struct {
		file        string
		errContains string
	}{
		{
			file:        "testdata/bad.skip-tls-and-files.yml",
			errContains: "either use 'insecureSkipTLS: false' and specify TLS files or 'insecureSkipTLS: true' with no files",
		},
		{
			file:        "testdata/bad.invalid-ca-file.yml",
			errContains: "cannot read file in 'caCertificateFile'",
		},
		{
			file:        "testdata/bad.invalid-certificate-file.yml",
			errContains: "cannot read file in 'certificateFile'",
		},
		{
			file:        "testdata/bad.invalid-key-file.yml",
			errContains: "cannot read file in 'keyFile'",
		},
		{
			file:        "testdata/bad.invalid-key-password-file.yml",
			errContains: "cannot read file in 'keyPasswordFile'",
		},
		{
			file:        "testdata/bad.empty-key-password-file.yml",
			errContains: "file in 'keyPasswordFile' have no password",
		},
		{
			file:        "testdata/bad.newline-key-password-file.yml",
			errContains: "file in 'keyPasswordFile' have no password",
		},
		{
			file:        "testdata/bad.rsa-with-password-key-bad-pem.yml",
			errContains: "format is not PEM",
		},
		{
			file:        "testdata/bad.ec-with-password-key-bad-pem.yml",
			errContains: "format is not PEM",
		},
		{
			file:        "testdata/bad.rsa-with-password-wrong-password.yml",
			errContains: "cannot decrypt key in 'keyFile' with given password",
		},
		{
			file:        "testdata/bad.ec-with-password-wrong-password.yml",
			errContains: "cannot decrypt key in 'keyFile' with given password",
		},
	}

	for _, tc := range testCases {
		b, err := ioutil.ReadFile(tc.file)
		if err != nil {
			t.Fatalf("cannot read config file %q; err= %q", tc.file, err)
		}
		var c Config
		if err := yaml.UnmarshalStrict(b, &c); err != nil {
			t.Fatalf("cannot unmarshal (strict) content of %q; err= %q", tc.file, err)
		}

		if err := Check(&c); err == nil {
			t.Errorf("expect Check() to return error containing %q, got none", tc.errContains)
		} else if err != nil && !strings.Contains(err.Error(), tc.errContains) {
			t.Errorf("expect Check() to return error containing %q, got %q", tc.errContains, err)
		}
	}
}

// Spawns a HTTP server with TLS.
// We will test client TLS connection by getting a connecting to it.
// A *http.Server is more convenient than using net.Listener because
// we can call Shutdown to cleanup after tests.
func mustCreateServer(t *testing.T, addr string, c *Config) *http.Server {
	tlsConfig, err := tlsConfigFromStruct(c)
	if err != nil {
		t.Fatalf("cannot convert *Config to *tls.Config; err= %q", err)
	}
	// since NewTLSConfig returns client-side *tls.Config,
	// we need to modify it to use in a server.
	tlsConfig.ClientCAs = tlsConfig.RootCAs
	tlsConfig.RootCAs = nil
	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	server := &http.Server{
		Addr:      addr,
		TLSConfig: tlsConfig,
		Handler:   http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), // NOP
	}
	// we won't need to see the server's error log, since it's mostly logs
	// for failed TLS connections that we intetionally initiate
	server.ErrorLog = log.New(&bytes.Buffer{}, "", 0)

	go func() {
		if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			t.Fatalf("server cannot listen and serve requests; err= %q", err)
		}
	}()
	time.Sleep(time.Millisecond) // wait a bit for the server to startup

	return server
}

func TestPingGood(t *testing.T) {
	rsaServer := mustCreateServer(t, ":42421", &Config{
		CACertificateFile: "testdata/files/rsa.ca-certificate.pem",
		CertificateFile:   "testdata/files/rsa-listener.certificate.pem",
		KeyFile:           "testdata/files/rsa-listener.key.pem",
	})
	defer rsaServer.Shutdown(context.Background())
	ecServer := mustCreateServer(t, ":42422", &Config{
		CACertificateFile: "testdata/files/ec.ca-certificate.pem",
		CertificateFile:   "testdata/files/ec-listener.certificate.pem",
		KeyFile:           "testdata/files/ec-listener.key.pem",
	})
	defer ecServer.Shutdown(context.Background())

	testCases := []struct {
		listenerAddr string
		serverName   string
		config       Config
	}{
		{
			listenerAddr: ":42421",
			serverName:   "rsa-listener.client.locol.dev",
			config: Config{
				CACertificateFile: "testdata/files/rsa.ca-certificate.pem",
				CertificateFile:   "testdata/files/rsa-no-password.certificate.pem",
				KeyFile:           "testdata/files/rsa-no-password.key.pem",
			},
		},
		{
			listenerAddr: ":42421",
			serverName:   "rsa-listener.client.locol.dev",
			config: Config{
				CACertificateFile: "testdata/files/rsa.ca-certificate.pem",
				CertificateFile:   "testdata/files/rsa-with-password.certificate.pem",
				KeyFile:           "testdata/files/rsa-with-password.key.pem",
				KeyPasswordFile:   "testdata/files/rsa-with-password.key.password",
			},
		},
		{
			listenerAddr: ":42422",
			serverName:   "ec-listener.client.locol.dev",
			config: Config{
				CACertificateFile: "testdata/files/ec.ca-certificate.pem",
				CertificateFile:   "testdata/files/ec-no-password.certificate.pem",
				KeyFile:           "testdata/files/ec-no-password.key.pem",
			},
		},
		{
			listenerAddr: ":42422",
			serverName:   "ec-listener.client.locol.dev",
			config: Config{
				CACertificateFile: "testdata/files/ec.ca-certificate.pem",
				CertificateFile:   "testdata/files/ec-with-password.certificate.pem",
				KeyFile:           "testdata/files/ec-with-password.key.pem",
				KeyPasswordFile:   "testdata/files/ec-with-password.key.password",
			},
		},
	}

	for _, tc := range testCases {
		if err := Ping(&tc.config, tc.listenerAddr, tc.serverName); err != nil {
			t.Errorf("expected Ping() to return no error, got %q", err)
		}
		// also check PingInsecureSkipVerify with the same config
		if err := PingInsecureSkipVerify(&tc.config, tc.listenerAddr); err != nil {
			t.Errorf("expected PingInsecureSkipVerify() to return no error, got %q", err)
		}
	}
}

func TestPingBad(t *testing.T) {
	rsaServer := mustCreateServer(t, ":42421", &Config{
		CACertificateFile: "testdata/files/rsa.ca-certificate.pem",
		CertificateFile:   "testdata/files/rsa-listener.certificate.pem",
		KeyFile:           "testdata/files/rsa-listener.key.pem",
	})
	defer rsaServer.Shutdown(context.Background())
	ecServer := mustCreateServer(t, ":42422", &Config{
		CACertificateFile: "testdata/files/ec.ca-certificate.pem",
		CertificateFile:   "testdata/files/ec-listener.certificate.pem",
		KeyFile:           "testdata/files/ec-listener.key.pem",
	})
	defer ecServer.Shutdown(context.Background())

	testCases := []struct {
		listenerAddr string
		serverName   string
		config       Config
		errContains  string
	}{
		{
			listenerAddr: ":42421",
			serverName:   "rsa-listener.client.locol.dev",
			config: Config{
				CACertificateFile: "testdata/files/ec.ca-certificate.pem",
				CertificateFile:   "testdata/files/ec-no-password.certificate.pem",
				KeyFile:           "testdata/files/ec-no-password.key.pem",
			},
			errContains: "certificate signed by unknown authority",
		},
		{
			listenerAddr: ":42422",
			serverName:   "ec-listener.client.locol.dev",
			config: Config{
				CACertificateFile: "testdata/files/rsa.ca-certificate.pem",
				CertificateFile:   "testdata/files/rsa-no-password.certificate.pem",
				KeyFile:           "testdata/files/rsa-no-password.key.pem",
			},
			errContains: "certificate signed by unknown authority",
		},
		{
			listenerAddr: ":42421",
			serverName:   "rsa-listener.client.locol.dev",
			config: Config{
				CACertificateFile: "testdata/files/ca-certificate.pem",
				CertificateFile:   "testdata/files/ec-no-password.certificate.pem",
				KeyFile:           "testdata/files/ec-no-password.key.pem",
			},
			errContains: "remote error: tls: bad certificate",
		},
		{
			listenerAddr: ":42421",
			serverName:   "rsa-listener.client.locol.dev",
			config: Config{
				CACertificateFile: "testdata/files/invalid-file.pem",
				CertificateFile:   "testdata/files/rsa-with-password.certificate.pem",
				KeyFile:           "testdata/files/rsa-with-password.key.pem",
				KeyPasswordFile:   "testdata/files/rsa-with-password.key.password",
			},
			errContains: "cannot read file in 'caCertificateFile'",
		},
		{
			listenerAddr: ":42421",
			serverName:   "rsa-listener.client.locol.dev",
			config: Config{
				CACertificateFile: "testdata/files/ca-certificate.pem",
				CertificateFile:   "testdata/files/invalid-file.pem",
				KeyFile:           "testdata/files/rsa-with-password.key.pem",
				KeyPasswordFile:   "testdata/files/rsa-with-password.key.password",
			},
			errContains: "cannot read file in 'certificateFile'",
		},
		{
			listenerAddr: ":42421",
			serverName:   "rsa-listener.client.locol.dev",
			config: Config{
				CACertificateFile: "testdata/files/ca-certificate.pem",
				CertificateFile:   "testdata/files/rsa-with-password.certificate.pem",
				KeyFile:           "testdata/files/invalid-file.pem",
				KeyPasswordFile:   "testdata/files/rsa-with-password.key.password",
			},
			errContains: "cannot read file in 'keyFile'",
		},
		{
			listenerAddr: ":42421",
			serverName:   "rsa-listener.client.locol.dev",
			config: Config{
				CACertificateFile: "testdata/files/ca-certificate.pem",
				CertificateFile:   "testdata/files/rsa-with-password.certificate.pem",
				KeyFile:           "testdata/files/rsa-with-password.key.pem",
				KeyPasswordFile:   "testdata/files/invalid-file.key.password",
			},
			errContains: "cannot read file in 'keyPasswordFile'",
		},
		{
			listenerAddr: ":42421",
			serverName:   "rsa-listener.client.locol.dev",
			config: Config{
				CACertificateFile: "testdata/files/ca-certificate.pem",
				CertificateFile:   "testdata/files/rsa-with-password.certificate.pem",
				KeyFile:           "testdata/files/rsa-with-password.key.pem",
				KeyPasswordFile:   "testdata/files/wrong.key.password",
			},
			errContains: "cannot decrypt key in 'keyFile' with given password",
		},
	}

	for _, tc := range testCases {
		if err := Ping(&tc.config, tc.listenerAddr, tc.serverName); err == nil {
			t.Errorf("expected Ping() to return error containing %q, got none", tc.errContains)
		} else if err != nil && !strings.Contains(err.Error(), tc.errContains) {
			t.Errorf("expected Ping() to return error containing %q, got %q", tc.errContains, err)
		}

		// probably don't need to check PingInsecureSkipVerify here
		// as TestPingGood() and other test cases already cover those paths
	}
}
