package tls

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"maps"
	"net"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/safe"
)

// CertificateData holds runtime data for runtime TLS certificate handling.
type CertificateData struct {
	Hash        string
	Certificate *tls.Certificate
}

type dynamicCertificates map[string][]*CertificateData

// CertificateStore store for dynamic certificates.
type CertificateStore struct {
	DynamicCerts       *safe.Safe
	DefaultCertificate *CertificateData
	CertCache          *cache.Cache

	certificateCandidatesCache *cache.Cache
	ocspStapler                *ocspStapler
}

// NewCertificateStore create a store for dynamic certificates.
func NewCertificateStore(ocspStapler *ocspStapler) *CertificateStore {
	var dynamicCerts safe.Safe
	dynamicCerts.Set(make(dynamicCertificates))

	return &CertificateStore{
		DynamicCerts:               &dynamicCerts,
		CertCache:                  cache.New(1*time.Hour, 10*time.Minute),
		certificateCandidatesCache: cache.New(1*time.Hour, 10*time.Minute),
		ocspStapler:                ocspStapler,
	}
}

// GetAllDomains return a slice with all the certificate domain.
func (c *CertificateStore) GetAllDomains() []string {
	allDomains := c.getDefaultCertificateDomains()

	// Get dynamic certificates
	if c.DynamicCerts != nil && c.DynamicCerts.Get() != nil {
		for domain := range c.DynamicCerts.Get().(dynamicCertificates) {
			allDomains = append(allDomains, domain)
		}
	}

	return allDomains
}

// GetDefaultCertificate returns the default certificate.
func (c *CertificateStore) GetDefaultCertificate() *tls.Certificate {
	if c == nil {
		return nil
	}

	if c.ocspStapler != nil && c.DefaultCertificate.Hash != "" {
		if staple, ok := c.ocspStapler.GetStaple(c.DefaultCertificate.Hash); ok {
			// We are updating the OCSPStaple of the certificate without any synchronization
			// as this should not cause any issue.
			c.DefaultCertificate.Certificate.OCSPStaple = staple
		}
	}

	return c.DefaultCertificate.Certificate
}

// GetBestCertificate returns a hostname-valid certificate selected according to the client's signature scheme preferences.
func (c *CertificateStore) GetBestCertificate(clientHello *tls.ClientHelloInfo) *tls.Certificate {
	if c == nil {
		return nil
	}

	serverName := strings.ToLower(strings.TrimSpace(clientHello.ServerName))
	if len(serverName) == 0 {
		// If no ServerName is provided, Check for local IP address matches
		host, _, err := net.SplitHostPort(clientHello.Conn.LocalAddr().String())
		if err != nil {
			log.Debug().Err(err).Msg("Could not split host/port")
		}
		serverName = strings.TrimSpace(host)
	}

	var candidates []*CertificateData
	if c.certificateCandidatesCache != nil {
		if cached, ok := c.certificateCandidatesCache.Get(serverName); ok {
			candidates = cached.([]*CertificateData)
		}
	}

	if candidates == nil && c.DynamicCerts != nil && c.DynamicCerts.Get() != nil {
		candidates = make([]*CertificateData, 0)
		certs := c.DynamicCerts.Get().(dynamicCertificates)
		// Preserve the existing exact-name-before-wildcard precedence when certificates support the same signature scheme.
		sorted := slices.SortedFunc(maps.Keys(certs), func(certKey string, certKey2 string) int {
			return strings.Compare(certKey2, certKey)
		})

		for _, certDomains := range sorted {
			if matchDomain(serverName, certDomains) {
				candidates = append(candidates, certs[certDomains]...)
			}
		}

		if c.certificateCandidatesCache != nil {
			c.certificateCandidatesCache.SetDefault(serverName, candidates)
		}
	}

	if len(candidates) == 0 {
		return nil
	}

	// Do not cache this result because clients for the same hostname can advertise different signature schemes.
	// Trying one signature scheme at a time makes the client preference order
	// drive certificate selection while SupportsCertificate applies all the
	// other TLS compatibility checks.
	for _, signatureScheme := range clientHello.SignatureSchemes {
		probe := *clientHello
		probe.SignatureSchemes = []tls.SignatureScheme{signatureScheme}

		for _, candidate := range candidates {
			if err := probe.SupportsCertificate(candidate.Certificate); err == nil {
				return c.prepareCertificate(candidate)
			}
		}
	}

	if len(clientHello.SignatureSchemes) == 0 {
		for _, candidate := range candidates {
			if err := clientHello.SupportsCertificate(candidate.Certificate); err == nil {
				return c.prepareCertificate(candidate)
			}
		}
	}

	// Match crypto/tls fallback behavior so the handshake reports the actual
	// incompatibility instead of falling back to an unrelated default certificate.
	return c.prepareCertificate(candidates[0])
}

func (c *CertificateStore) prepareCertificate(certificateData *CertificateData) *tls.Certificate {
	if c.ocspStapler != nil && certificateData.Hash != "" {
		if staple, ok := c.ocspStapler.GetStaple(certificateData.Hash); ok {
			// We are updating the OCSPStaple of the certificate without any synchronization
			// as this should not cause any issue.
			certificateData.Certificate.OCSPStaple = staple
		}
	}

	return certificateData.Certificate
}

// GetCertificate returns the first certificate matching all the given domains.
func (c *CertificateStore) GetCertificate(domains []string) *CertificateData {
	if c == nil {
		return nil
	}

	sort.Strings(domains)
	domainsKey := strings.Join(domains, ",")

	if cert, ok := c.CertCache.Get(domainsKey); ok {
		return cert.(*CertificateData)
	}

	if c.DynamicCerts != nil && c.DynamicCerts.Get() != nil {
		for certDomains, certificates := range c.DynamicCerts.Get().(dynamicCertificates) {
			if domainsKey == certDomains {
				cert := certificates[0]
				c.CertCache.SetDefault(domainsKey, cert)
				return cert
			}

			var matchedDomains []string
			for certDomain := range strings.SplitSeq(certDomains, ",") {
				for _, checkDomain := range domains {
					if certDomain == checkDomain {
						matchedDomains = append(matchedDomains, certDomain)
					}
				}
			}

			if len(matchedDomains) == len(domains) {
				cert := certificates[0]
				c.CertCache.SetDefault(domainsKey, cert)
				return cert
			}
		}
	}

	return nil
}

// ResetCache clears the cache in the store.
func (c *CertificateStore) ResetCache() {
	if c.CertCache != nil {
		c.CertCache.Flush()
	}
	if c.certificateCandidatesCache != nil {
		c.certificateCandidatesCache.Flush()
	}
}

func (c *CertificateStore) getDefaultCertificateDomains() []string {
	if c.DefaultCertificate == nil {
		return nil
	}

	defaultCert := c.DefaultCertificate.Certificate.Leaf

	var allCerts []string
	if len(defaultCert.Subject.CommonName) > 0 {
		allCerts = append(allCerts, defaultCert.Subject.CommonName)
	}

	allCerts = append(allCerts, defaultCert.DNSNames...)

	for _, ipSan := range defaultCert.IPAddresses {
		allCerts = append(allCerts, ipSan.String())
	}

	return allCerts
}

// appendCertificate appends a Certificate to a certificates map keyed by store name.
func appendCertificate(certs map[string]dynamicCertificates, subjectAltNames []string, storeName string, cert *CertificateData) {
	// Guarantees the order to produce a unique cert key.
	sort.Strings(subjectAltNames)
	certKey := strings.Join(subjectAltNames, ",")

	if certs[storeName] == nil {
		certs[storeName] = make(dynamicCertificates)
	}

	for _, existing := range certs[storeName][certKey] {
		if existing.Certificate == cert.Certificate ||
			(len(existing.Certificate.Certificate) > 0 && len(cert.Certificate.Certificate) > 0 &&
				bytes.Equal(existing.Certificate.Certificate[0], cert.Certificate.Certificate[0])) {
			log.Debug().Msgf("Skipping addition of certificate for domain(s) %q, to TLS Store %s, as it already exists for this store.", certKey, storeName)
			return
		}
	}

	log.Debug().Msgf("Adding certificate for domain(s) %s", certKey)
	certs[storeName][certKey] = append(certs[storeName][certKey], cert)
}

func parseCertificate(cert *Certificate) (tls.Certificate, []string, error) {
	certContent, err := cert.CertFile.Read()
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("unable to read CertFile: %w", err)
	}

	keyContent, err := cert.KeyFile.Read()
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("unable to read KeyFile: %w", err)
	}

	tlsCert, err := tls.X509KeyPair(certContent, keyContent)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("unable to generate TLS certificate: %w", err)
	}

	var SANs []string
	if tlsCert.Leaf.Subject.CommonName != "" {
		SANs = append(SANs, strings.ToLower(tlsCert.Leaf.Subject.CommonName))
	}
	if tlsCert.Leaf.DNSNames != nil {
		for _, dnsName := range tlsCert.Leaf.DNSNames {
			if dnsName != tlsCert.Leaf.Subject.CommonName {
				SANs = append(SANs, strings.ToLower(dnsName))
			}
		}
	}
	if tlsCert.Leaf.IPAddresses != nil {
		for _, ip := range tlsCert.Leaf.IPAddresses {
			if ip.String() != tlsCert.Leaf.Subject.CommonName {
				SANs = append(SANs, strings.ToLower(ip.String()))
			}
		}
	}

	return tlsCert, SANs, err
}

// matchDomain returns whether the server name matches the cert domains.
// The server name, from TLS SNI, must not have trailing dots (https://datatracker.ietf.org/doc/html/rfc6066#section-3).
// This is enforced by https://github.com/golang/go/blob/d3d7998756c33f69706488cade1cd2b9b10a4c7f/src/crypto/tls/handshake_messages.go#L423-L427.
func matchDomain(serverName, certDomains string) bool {
	for certDomain := range strings.SplitSeq(certDomains, ",") {
		// TODO: assert equality after removing the trailing dots?
		if serverName == certDomain {
			return true
		}

		for len(certDomain) > 0 && certDomain[len(certDomain)-1] == '.' {
			certDomain = certDomain[:len(certDomain)-1]
		}

		labels := strings.Split(serverName, ".")
		labels[0] = "*"
		if certDomain == strings.Join(labels, ".") {
			return true
		}
	}
	return false
}
