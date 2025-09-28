package main

import (
	"os"

	"github.com/olekukonko/tablewriter"
)

type SettingsType struct {
	m map[string]SettingType
}

type SettingType struct {
	Description string
	Value       string
}

func NewSettingType(print bool) *SettingsType {
	s := &SettingsType{m: make(map[string]SettingType)}

	s.Set(TLS_DOMAIN, "TLS domain name", "")
	s.Set(ACME_URL, "ACME server URL (e.g. https://acme-staging-v02.api.letsencrypt.org/directory)", "")
	s.Set(ACME_CA_CERT, "Path to custom CA certificate file (PEM format)", "")
	s.Set(KEYSTORE_PATH, "Path to Java KeyStore file", "keystore.jks")
	s.Set(KEYSTORE_PASS, "Password for Java KeyStore", "password")
	s.Set(KEYSTORE_ALIAS, "Alias for certificate entry in Java KeyStore", "server")
	s.Set(TRUSTSTORE_PATH, "Path to Java TrustStore file", "truststore.jks")
	s.Set(TRUSTSTORE_PASS, "Password for Java TrustStore", "password")
	s.Set(TRUSTSTORE_ALIAS, "Alias for CA certificate entry in Java TrustStore", "rootca")
	s.Set(ACME_EMAIL, "Email address for ACME registration and recovery contact", "")

	if print {
		table := tablewriter.NewWriter(os.Stdout)

		table.Header("KEY", "Description", "value")
		for key, setting := range s.m {
			table.Append([]string{key, setting.Description, setting.Value})
		}
		table.Render()
	}
	return s
}

func (s *SettingsType) Get(id string) string {
	return s.m[id].Value
}

func (s *SettingsType) Has(id string) bool {
	return len(s.m[id].Value) > 0
}

func (s *SettingsType) Set(id string, description string, defaultValue string) {
	if value, ok := os.LookupEnv(id); ok {
		s.m[id] = SettingType{Description: description, Value: value}
	} else {
		s.m[id] = SettingType{Description: description, Value: defaultValue}
	}
}

const (
	TLS_DOMAIN       = "TLS_DOMAIN"
	ACME_URL         = "ACME_URL"
	ACME_CA_CERT     = "ACME_CA_CERT"
	KEYSTORE_PATH    = "KEYSTORE_PATH"
	KEYSTORE_PASS    = "KEYSTORE_PASS"
	KEYSTORE_ALIAS   = "KEYSTORE_ALIAS"
	TRUSTSTORE_PATH  = "TRUSTSTORE_PATH"
	TRUSTSTORE_PASS  = "TRUSTSTORE_PASS"
	TRUSTSTORE_ALIAS = "TRUSTSTORE_ALIAS"
	ACME_EMAIL       = "ACME_EMAIL"
)
