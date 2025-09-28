# ACME2JKS Keystore/Truststore Exporter

ACME2JKS is a small **Go webserver** that uses [CertMagic](https://github.com/caddyserver/certmagic) to automatically obtain and renew TLS certificates via ACME (Let’s Encrypt or a custom ACME CA).
It then exports the obtained certificates into **Java-compatible keystores and truststores** (`.jks`), making it easy to integrate with Java applications such as **Tomcat**, **Jetty**, **Spring Boot**, etc.

---

## ✨ Features

* 🔑 **Automatic certificate management**
  Uses CertMagic with ACME (HTTP-01 challenge) to obtain and renew TLS certificates for your domain.

* 📦 **Java keystore export**
  Creates/updates a `keystore.jks` containing the private key and full certificate chain.
  Useful for Java servers that require a JKS keystore instead of PEM files.

* 🔒 **Java truststore export**
  Loads your custom CA root certificate(s) from a PEM bundle and writes them into a `truststore.jks`.
  Supports **multiple CA roots** (alias names are auto-generated).

* 🔄 **Auto-updates on renewal**
  When CertMagic renews a certificate, the keystore is automatically regenerated.
  Truststore is written at startup.

* ⚙️ **Custom ACME server support**
  Works with Let’s Encrypt or your own **private ACME CA**, using a custom directory URL and root certificate.

* 🌍 **Port 80 only**
  Runs an HTTP server on port `:80` for:

  * ACME HTTP-01 challenges
  * Optional application endpoints (simple demo handler is included).

---

## 🚀 Usage

### Prerequisites

* Go 1.21+
* Your domain must resolve to the machine running this program.
* Port 80 must be reachable from the internet (required for HTTP-01 challenge).

### Build & Run

```bash
go build -o acme-jks-exporter
./acme-jks-exporter
```

Or run directly:

```bash
go run main.go
```

---

## ⚙️ Configuration

All configuration is done via **environment variables**:

| Variable           | Description                                                                                                | Default            |
| ------------------ | ---------------------------------------------------------------------------------------------------------- | ------------------ |
| `TLS_DOMAIN`       | Domain to issue certificate for (required)                                                                 | –                  |
| `ACME_URL`         | ACME server directory URL (e.g. Let’s Encrypt staging/prod, or private CA)                                 | Let’s Encrypt prod |
| `ACME_CA_CERT`     | Path to PEM bundle of custom ACME CA root(s). If set, used both for CertMagic trust and truststore export. | –                  |
| `ACME_EMAIL`       | Contact email for ACME registration                                                                        | `admin@<domain>`   |
| `KEYSTORE_PATH`    | Path to generated keystore file                                                                            | `keystore.jks`     |
| `KEYSTORE_PASS`    | Password for the keystore                                                                                  | `changeit`         |
| `KEYSTORE_ALIAS`   | Alias name for the private key entry                                                                       | `server`           |
| `TRUSTSTORE_PATH`  | Path to generated truststore file                                                                          | `truststore.jks`   |
| `TRUSTSTORE_PASS`  | Password for the truststore                                                                                | `changeit`         |
| `TRUSTSTORE_ALIAS` | Base alias name for truststore entries (aliases are suffixed if multiple certs are present)                | `rootca`           |

---

## 🖥 Example

Using a private ACME server with a custom CA root:

```bash
export TLS_DOMAIN="mydomain.local"
export ACME_URL="https://my-acme-server.example/acme/directory"
export ACME_CA_CERT="/etc/pki/ca-bundle.pem"
export ACME_EMAIL="me@mydomain.local"

export KEYSTORE_PATH="/etc/ssl/keystores/myapp.jks"
export KEYSTORE_PASS="supersecret"
export KEYSTORE_ALIAS="tomcat"

export TRUSTSTORE_PATH="/etc/ssl/keystores/mytruststore.jks"
export TRUSTSTORE_PASS="trustsecret"
export TRUSTSTORE_ALIAS="myca"

go run main.go
```

Results:

* `myapp.jks` → Contains private key + full certificate chain.
* `mytruststore.jks` → Contains all CA roots from `/etc/pki/ca-bundle.pem`.

---

## 🔧 How it Works

1. **CertMagic configuration**

   * Sets up an `ACMEIssuer` with the given ACME URL and email.
   * If `ACME_CA_CERT` is provided, the root cert(s) are loaded into a custom trust pool.

2. **Certificate management**

   * Calls `cfg.ManageSync()` for your domain.
   * CertMagic handles issuance and renewal in the background.

3. **Event handling**

   * `cfg.OnEvent` listens for `"cert_obtained"` and `"cert_renewed"`.
   * When triggered, it regenerates the `keystore.jks`.

4. **Keystore generation**

   * Converts the Go `crypto.PrivateKey` into PKCS#8 DER.
   * Stores the private key and certificate chain in a JKS keystore.

5. **Truststore generation**

   * Reads the PEM bundle from `ACME_CA_CERT`.
   * Adds each certificate as a trusted entry in `truststore.jks`.

6. **Web server**

   * Starts an HTTP server on port `:80`.
   * Serves ACME challenges automatically.
   * Example handler responds with a greeting on `/`.

---

## 📂 Output Files

* `keystore.jks`
  Contains the issued certificate and private key.
  Used by Java servers to terminate TLS.

* `truststore.jks`
  Contains the trusted root CA(s).
  Used by Java clients to trust your ACME CA.

---

