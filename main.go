package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/pavlo-v-chernykh/keystore-go/v4"
)

var (
	keystoreMux    sync.Mutex
	inOnEventFetch atomic.Bool // re-entrancy guard
)

func main() {

	settings := NewSettingType(true)

	domain := settings.Get(TLS_DOMAIN)
	if domain == "" {
		log.Fatal("TLS_DOMAIN must be set")
	}
	acmeURL := settings.Get(ACME_URL)
	caCertPath := settings.Get(ACME_CA_CERT)

	keystorePath := settings.Get(KEYSTORE_PATH)
	keystorePass := settings.Get(KEYSTORE_PASS)
	keystoreAlias := settings.Get(KEYSTORE_ALIAS)

	truststorePath := settings.Get(TRUSTSTORE_PATH)
	truststorePass := settings.Get(TRUSTSTORE_PASS)
	truststoreAlias := settings.Get(TRUSTSTORE_ALIAS)

	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.Email = settings.Get(ACME_EMAIL)
	if certmagic.DefaultACME.Email == "" {
		certmagic.DefaultACME.Email = "admin@" + domain
	}
	if acmeURL != "" {
		certmagic.DefaultACME.CA = acmeURL
	}

	if caCertPath != "" {
		rootPEM, err := os.ReadFile(caCertPath)
		if err != nil {
			log.Fatalf("unable to read CA cert file: %v", err)
		}
		rootPool := x509.NewCertPool()
		count := 0
		rest := rootPEM
		for {
			block, nxt := pem.Decode(rest)
			if block == nil {
				break
			}
			rest = nxt
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				log.Fatalf("failed to parse CA cert: %v", err)
			}
			rootPool.AddCert(cert)
			count++
			log.Printf("Loaded CA certificate CN=%s", cert.Subject.CommonName)
		}
		if count == 0 {
			log.Fatalf("no CA certificates found in %s", caCertPath)
		}
		certmagic.DefaultACME.TrustedRoots = rootPool
		log.Printf("Configured %d trusted roots for CertMagic", count)

		err = saveToTruststore(rootPEM, truststorePath, truststorePass, truststoreAlias)
		if err != nil {
			log.Fatalf("saveToTruststore failed: %v", err)
		}
		log.Printf("Truststore written to %s", truststorePath)
	}

	cfg := certmagic.NewDefault()

	cfg.OnEvent = func(ctx context.Context, event string, data map[string]any) error {
		log.Printf("📜 CertMagic event: %s", event)
		if inOnEventFetch.Load() {
			return nil
		}

		jsonData, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			log.Printf("failed to marshal event data: %v", err)
		}
		log.Printf("Event data: %s", jsonData)

		switch event {
		case "cert_obtained", "cert_renewed", "cached_managed_cert":
			fmt.Println("Processing event:", event, domain)
			inOnEventFetch.Store(true)
			defer inOnEventFetch.Store(false)
			fmt.Println("Processing event:", event, domain)
			// Load cert from CertMagic rather than expecting it in event data
			var got certmagic.Certificate
			var loadErr error
			//			for _, d := range getEventDomains() {
			got, loadErr = cfg.CacheManagedCertificate(ctx, domain)
			if loadErr == nil && !got.Empty() {
				break
			}
			//			}
			if loadErr != nil || got.Empty() {
				log.Printf("could not load managed certificate after %s: %v", event, loadErr)
				return nil // don't interfere with CertMagic's flow
			}

			// Update JKS
			keystoreMux.Lock()
			defer keystoreMux.Unlock()

			if err := saveToKeystore(got, keystorePath, keystorePass, keystoreAlias); err != nil {
				log.Printf("failed to save keystore after %s: %v", event, err)
				return nil
			}
			log.Printf("✅ Keystore updated at %s", keystorePath)
		}

		fmt.Println("Event processing complete:", event, domain)

		return nil
	}

	ctx := context.Background()
	if err := cfg.ManageSync(ctx, []string{domain}); err != nil {
		log.Fatalf("ManageSync failed: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(fmt.Sprintf("Hello from %s", domain))); err != nil {
			log.Printf("failed to write response: %v", err)
		}
	})
	httpServer := &http.Server{
		Addr:    ":80",
		Handler: certmagic.DefaultACME.HTTPChallengeHandler(mux), // use helper on the default config
	}

	log.Fatal(httpServer.ListenAndServe())
}

func saveToKeystore(cert certmagic.Certificate, path, password, alias string) error {

	fmt.Println("Saving certificate to keystore:", path)
	// Build cert chain
	var chain []keystore.Certificate
	for _, der := range cert.Certificate.Certificate {
		parsedCert, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("parse certificate: %w", err)
		}
		chain = append(chain, keystore.Certificate{
			Type:    "X509",
			Content: parsedCert.Raw,
		})
	}

	derBytes, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	entry := keystore.PrivateKeyEntry{
		CreationTime:     time.Now(),
		PrivateKey:       derBytes, // already crypto.PrivateKey
		CertificateChain: chain,
	}

	fmt.Println("Certificate has", len(chain), "certificates in the chain")

	ks := keystore.New()
	if err := ks.SetPrivateKeyEntry(alias, entry, []byte(password)); err != nil {
		return fmt.Errorf("SetPrivateKeyEntry failed: %w", err)
	}

	return atomicWriteJKS(ks, path, password)
}

func saveToTruststore(rootPEM []byte, path, pass, aliasPrefix string) error {
	ks := keystore.New()
	rest := rootPEM
	count := 0
	for {
		block, nxt := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = nxt
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse CA cert: %w", err)
		}
		alias := aliasPrefix
		if count > 0 {
			alias = fmt.Sprintf("%s-%d", aliasPrefix, count)
		}
		count++
		entry := keystore.TrustedCertificateEntry{
			CreationTime: time.Now(),
			Certificate: keystore.Certificate{
				Type:    "X509",
				Content: cert.Raw,
			},
		}
		if err := ks.SetTrustedCertificateEntry(alias, entry); err != nil {
			return fmt.Errorf("SetTrustedCertificateEntry failed: %w", err)
		}
		log.Printf("Truststore alias %s = CN %s", alias, cert.Subject.CommonName)
	}
	if count == 0 {
		return fmt.Errorf("no valid certificates in CA bundle")
	}
	return atomicWriteJKS(ks, path, pass)
}

func atomicWriteJKS(ks keystore.KeyStore, path, pass string) error {
	fmt.Println("Writing keystore to:", path)
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Printf("failed to close temp file: %v", err)
		}
	}()
	if err := ks.Store(f, []byte(pass)); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
