package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/pavlo-v-chernykh/keystore-go/v4"
)

var keystoreMux sync.Mutex

func main() {
	// ---- Print all environment variables (sorted) ----
	mask := strings.EqualFold(os.Getenv("ENV_DUMP_RAW"), "true") == false
	dumpEnv(mask)

	domain := os.Getenv("TLS_DOMAIN")
	if domain == "" {
		log.Fatal("TLS_DOMAIN must be set")
	}
	acmeURL := os.Getenv("ACME_URL")
	caCertPath := os.Getenv("ACME_CA_CERT")

	keystorePath := getenvDefault("KEYSTORE_PATH", "keystore.jks")
	keystorePass := getenvDefault("KEYSTORE_PASS", "changeit")
	keystoreAlias := getenvDefault("KEYSTORE_ALIAS", "server")

	truststorePath := getenvDefault("TRUSTSTORE_PATH", "truststore.jks")
	truststorePass := getenvDefault("TRUSTSTORE_PASS", "changeit")
	truststoreAlias := getenvDefault("TRUSTSTORE_ALIAS", "rootca")

	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.Email = os.Getenv("ACME_EMAIL")
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
		switch event {
		case "cert_obtained", "cert_renewed":
			cert, ok := data["certificate"].(certmagic.Certificate)
			if !ok {
				return fmt.Errorf("event %s: certificate missing or wrong type", event)
			}

			log.Printf("📜 CertMagic event: %s → updating keystore", event)

			keystoreMux.Lock()
			defer keystoreMux.Unlock()

			if err := saveToKeystore(cert, keystorePath, keystorePass, keystoreAlias); err != nil {
				return fmt.Errorf("failed to save keystore: %w", err)
			}
			log.Printf("✅ Keystore updated at %s", keystorePath)
		}
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

func getenvDefault(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// ----------------- env dump helpers -----------------

func dumpEnv(maskSensitive bool) {
	env := os.Environ()
	type kv struct{ k, v string }
	var list []kv
	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		k := parts[0]
		v := ""
		if len(parts) > 1 {
			v = parts[1]
		}
		list = append(list, kv{k: k, v: v})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].k < list[j].k })

	// width for alignment
	maxk := 0
	for _, p := range list {
		if len(p.k) > maxk {
			maxk = len(p.k)
		}
	}

	log.Printf("---- Environment (%d vars) ----", len(list))
	for _, p := range list {
		val := maybeMask(p.k, p.v, maskSensitive)
		// k padded right to maxk
		log.Printf("%-*s = %s", maxk, p.k, val)
	}
	log.Printf("---- End Environment ----")
}

func maybeMask(name, value string, mask bool) string {
	if !mask {
		return value
	}
	// Heuristic: mask likely secrets
	nameLower := strings.ToLower(name)
	if strings.Contains(nameLower, "pass") ||
		strings.Contains(nameLower, "password") ||
		strings.Contains(nameLower, "secret") ||
		strings.Contains(nameLower, "token") ||
		strings.Contains(nameLower, "key") ||
		strings.Contains(nameLower, "private") {
		return maskTail(value)
	}
	return value
}

func maskTail(s string) string {
	if s == "" {
		return ""
	}
	// keep last 4 chars if long enough
	if len(s) <= 4 {
		return "****"
	}
	return strings.Repeat("*", len(s)-4) + s[len(s)-4:]
}
