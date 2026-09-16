package tls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/safe"
)

func TestGetBestCertificate(t *testing.T) {
	// TODO Add tests for defaultCert
	testCases := []struct {
		desc          string
		domainToCheck string
		dynamicCert   string
		expectedCert  string
		uppercase     bool
	}{
		{
			desc:          "Empty Store, returns no certs",
			domainToCheck: "snitest.com",
			dynamicCert:   "",
			expectedCert:  "",
		},
		{
			desc:          "Best Match with no corresponding",
			domainToCheck: "snitest.com",
			dynamicCert:   "snitest.org",
			expectedCert:  "",
		},
		{
			desc:          "Best Match",
			domainToCheck: "snitest.com",
			dynamicCert:   "snitest.com",
			expectedCert:  "snitest.com",
		},
		{
			desc:          "Best Match with dynamic wildcard",
			domainToCheck: "www.snitest.com",
			dynamicCert:   "*.snitest.com",
			expectedCert:  "*.snitest.com",
		},
		{
			desc:          "Best Match with dynamic wildcard only, case-insensitive",
			domainToCheck: "bar.www.snitest.com",
			dynamicCert:   "*.www.snitest.com",
			expectedCert:  "*.www.snitest.com",
			uppercase:     true,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()
			dynamicMap := dynamicCertificates{}

			if test.dynamicCert != "" {
				cert, err := loadTestCert(test.dynamicCert, test.uppercase)
				require.NoError(t, err)
				dynamicMap[strings.ToLower(test.dynamicCert)] = []*CertificateData{{Certificate: cert}}
			}

			store := &CertificateStore{
				DynamicCerts: safe.New(dynamicMap),
				CertCache:    cache.New(1*time.Hour, 10*time.Minute),
			}

			var expected *tls.Certificate
			if test.expectedCert != "" {
				cert, err := loadTestCert(test.expectedCert, test.uppercase)
				require.NoError(t, err)
				expected = cert
			}

			clientHello := &tls.ClientHelloInfo{
				ServerName: test.domainToCheck,
			}

			actual := store.GetBestCertificate(clientHello)
			assert.Equal(t, expected, actual)
		})
	}
}

// TestGetBestCertificate_SharedSAN ensures the selection stays deterministic
// when distinct certificates share a SAN matching the server name (https://github.com/traefik/traefik/issues/13286).
func TestGetBestCertificate_SharedSAN(t *testing.T) {
	wildcardCert := &CertificateData{Certificate: &tls.Certificate{}}
	exactCert := &CertificateData{Certificate: &tls.Certificate{}}

	// Both certificates have a SAN matching app.example.test, but the exact-only
	// certificate must always win as its identifier sorts last.
	for range 100 {
		dynamicMap := dynamicCertificates{
			"*.app.example.test,app.example.test": {wildcardCert},
			"app.example.test":                    {exactCert},
		}

		store := &CertificateStore{
			DynamicCerts: safe.New(dynamicMap),
			CertCache:    cache.New(1*time.Hour, 10*time.Minute),
		}

		clientHello := &tls.ClientHelloInfo{ServerName: "app.example.test"}
		assert.Same(t, exactCert.Certificate, store.GetBestCertificate(clientHello))
	}
}

func TestGetBestCertificate_SignatureSchemePreference(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	rsaCert := newTestCertificate(t, "server.example.com", rsaKey)
	ecdsaCert := newTestCertificate(t, "server.example.com", ecdsaKey)

	store := NewCertificateStore(nil)
	store.DynamicCerts.Set(dynamicCertificates{
		"server.example.com": {
			{Certificate: rsaCert},
			{Certificate: ecdsaCert},
		},
	})

	testCases := []struct {
		desc             string
		signatureSchemes []tls.SignatureScheme
		expected         *tls.Certificate
	}{
		{
			desc:             "RSA only",
			signatureSchemes: []tls.SignatureScheme{tls.PSSWithSHA256},
			expected:         rsaCert,
		},
		{
			desc:             "ECDSA only",
			signatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
			expected:         ecdsaCert,
		},
		{
			desc:             "client prefers ECDSA",
			signatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.PSSWithSHA256},
			expected:         ecdsaCert,
		},
		{
			desc:             "client prefers RSA",
			signatureSchemes: []tls.SignatureScheme{tls.PSSWithSHA256, tls.ECDSAWithP256AndSHA256},
			expected:         rsaCert,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			clientHello := &tls.ClientHelloInfo{
				ServerName:        "server.example.com",
				SupportedVersions: []uint16{tls.VersionTLS13},
				SignatureSchemes:  test.signatureSchemes,
			}

			assert.Same(t, test.expected, store.GetBestCertificate(clientHello))
		})
	}
}

func TestAppendCertificate_SharedSAN(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	rsaCert := &CertificateData{Certificate: newTestCertificate(t, "server.example.com", rsaKey)}
	ecdsaCert := &CertificateData{Certificate: newTestCertificate(t, "server.example.com", ecdsaKey)}
	certificates := make(map[string]dynamicCertificates)

	appendCertificate(certificates, []string{"server.example.com"}, DefaultTLSStoreName, rsaCert)
	appendCertificate(certificates, []string{"server.example.com"}, DefaultTLSStoreName, ecdsaCert)
	appendCertificate(certificates, []string{"server.example.com"}, DefaultTLSStoreName, rsaCert)

	assert.Equal(t, []*CertificateData{rsaCert, ecdsaCert}, certificates[DefaultTLSStoreName]["server.example.com"])
}

func newTestCertificate(t *testing.T, domain string, privateKey crypto.Signer) *tls.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	require.NoError(t, err)

	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)

	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}),
	)
	require.NoError(t, err)

	return &certificate
}

func loadTestCert(certName string, uppercase bool) (*tls.Certificate, error) {
	replacement := "wildcard"
	if uppercase {
		replacement = "uppercase_wildcard"
	}

	staticCert, err := tls.LoadX509KeyPair(
		fmt.Sprintf("../../integration/fixtures/https/%s.cert", strings.ReplaceAll(certName, "*", replacement)),
		fmt.Sprintf("../../integration/fixtures/https/%s.key", strings.ReplaceAll(certName, "*", replacement)),
	)
	if err != nil {
		return nil, err
	}

	return &staticCert, nil
}
