// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path"
	"runtime"
	"testing"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

var sm2testdata = []struct {
	commonName   string
	filename     string
	password     string
	includeChain bool
}{
	{
		"pkcs12-test",
		"testdata/gmcert_pkcs12-withoutca.p12",
		"123456",
		false,
	},
	{
		"test-withca",
		"testdata/gmcert_pkcs12-test-withca.p12",
		"123456",
		true,
	},
}

func readFile(p12file string) ([]byte, error) {
	_, filename, _, _ := runtime.Caller(0)
	filepath := path.Join(path.Dir(filename), p12file)
	return os.ReadFile(filepath)
}

func TestSM2Pfx(t *testing.T) {
	for i, tc := range sm2testdata {
		p12data, err := readFile(tc.filename)
		if err != nil {
			t.Fatal(err)
		}
		if !tc.includeChain {
			priv, cert, err := Decode(p12data, tc.password)
			if err != nil {
				t.Fatal(err)
			}
			sm2Priv, ok := priv.(*sm2.PrivateKey)
			if !ok {
				t.Errorf("case %v, it's not a sm2 private key", i)
			}
			if !sm2Priv.PublicKey.Equal(cert.PublicKey) {
				t.Errorf("case %v, public key is different", i)
			}
			if cert.Subject.CommonName != tc.commonName {
				t.Errorf("case %v expected common name to be %q, but found %q", i, tc.commonName, cert.Subject.CommonName)
			}
			// encode and decode with ShangMi2024
			p12, err := ShangMi2024.Encode(sm2Priv, cert, nil, "password")
			if err != nil {
				t.Fatal(err)
			}
			priv, cert, err = Decode(p12, "password")
			if err != nil {
				t.Fatal(err)
			}
			sm2Priv, ok = priv.(*sm2.PrivateKey)
			if !ok {
				t.Errorf("case %v, it's not a sm2 private key", i)
			}
			if !sm2Priv.PublicKey.Equal(cert.PublicKey) {
				t.Errorf("case %v, public key is different", i)
			}
			if cert.Subject.CommonName != tc.commonName {
				t.Errorf("case %v expected common name to be %q, but found %q", i, tc.commonName, cert.Subject.CommonName)
			}
		} else {
			pk, cert, caCerts, err := DecodeChain(p12data, tc.password)
			if err != nil {
				t.Fatal(err)
			}
			sm2Priv, ok := pk.(*sm2.PrivateKey)
			if !ok {
				t.Errorf("case %v, it's not a sm2 private key", i)
			}
			if !sm2Priv.PublicKey.Equal(cert.PublicKey) {
				t.Errorf("case %v, public key is different", i)
			}
			if cert.Subject.CommonName != tc.commonName {
				t.Errorf("case %v expected common name to be %q, but found %q", i, tc.commonName, cert.Subject.CommonName)
			}
			if len(caCerts) == 0 {
				t.Errorf("case %v, ca cert expected", i)
			}
			// encode and decode with ShangMi2024
			p12, err := ShangMi2024.Encode(sm2Priv, cert, caCerts, "password")
			if err != nil {
				t.Fatal(err)
			}
			pk, cert, caCerts, err = DecodeChain(p12, "password")
			if err != nil {
				t.Fatal(err)
			}
			sm2Priv, ok = pk.(*sm2.PrivateKey)
			if !ok {
				t.Errorf("case %v, it's not a sm2 private key", i)
			}
			if !sm2Priv.PublicKey.Equal(cert.PublicKey) {
				t.Errorf("case %v, public key is different", i)
			}
			if cert.Subject.CommonName != tc.commonName {
				t.Errorf("case %v expected common name to be %q, but found %q", i, tc.commonName, cert.Subject.CommonName)
			}
			if len(caCerts) == 0 {
				t.Errorf("case %v, ca cert expected", i)
			}
		}
	}
}

func TestPfx(t *testing.T) {
	for commonName, base64P12 := range testdata {
		p12, _ := base64.StdEncoding.DecodeString(base64P12)

		priv, cert, err := Decode(p12, "")
		if err != nil {
			t.Fatal(err)
		}

		if err := priv.(*rsa.PrivateKey).Validate(); err != nil {
			t.Errorf("error while validating private key: %v", err)
		}

		if cert.Subject.CommonName != commonName {
			t.Errorf("expected common name to be %q, but found %q", commonName, cert.Subject.CommonName)
		}
	}
}

func TestPfxWithModernCiphers(t *testing.T) {
	for commonName, base64P12 := range testdata {
		p12, _ := base64.StdEncoding.DecodeString(base64P12)

		priv, cert, err := Decode(p12, "")
		if err != nil {
			t.Fatal(err)
		}

		if err := priv.(*rsa.PrivateKey).Validate(); err != nil {
			t.Errorf("error while validating private key: %v", err)
		}

		if cert.Subject.CommonName != commonName {
			t.Errorf("expected common name to be %q, but found %q", commonName, cert.Subject.CommonName)
		}

		p12New, err := Modern2023.Encode(priv, cert, nil, "password")
		if err != nil {
			t.Fatal(err)
		}
		privNew, cerNew, err := Decode(p12New, "password")
		if err != nil {
			t.Fatal(err)
		}
		if err := privNew.(*rsa.PrivateKey).Validate(); err != nil {
			t.Errorf("error while validating private key: %v", err)
		}
		if cerNew.Subject.CommonName != commonName {
			t.Errorf("expected common name to be %q, but found %q", commonName, cerNew.Subject.CommonName)
		}
	}
}

func TestPEM(t *testing.T) {
	for commonName, base64P12 := range testdata {
		p12, _ := base64.StdEncoding.DecodeString(base64P12)

		blocks, err := ToPEM(p12, "")
		if err != nil {
			t.Fatalf("error while converting to PEM: %s", err)
		}

		var pemData []byte
		for _, b := range blocks {
			pemData = append(pemData, pem.EncodeToMemory(b)...)
		}

		cert, err := tls.X509KeyPair(pemData, pemData)
		if err != nil {
			t.Errorf("err while converting to key pair: %v", err)
		}
		config := tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		config.BuildNameToCertificate()

		if _, exists := config.NameToCertificate[commonName]; !exists {
			t.Errorf("did not find our cert in PEM?: %v", config.NameToCertificate)
		}
	}
}

func TestTrustStore(t *testing.T) {
	for commonName, base64P12 := range testdata {
		p12, _ := base64.StdEncoding.DecodeString(base64P12)

		_, cert, err := Decode(p12, "")
		if err != nil {
			t.Fatal(err)
		}

		pfxData, err := EncodeTrustStore(rand.Reader, []*smx509.Certificate{cert}, "password")
		if err != nil {
			t.Fatal(err)
		}

		decodedCerts, err := DecodeTrustStore(pfxData, "password")
		if err != nil {
			t.Fatal(err)
		}

		if len(decodedCerts) != 1 {
			t.Fatal("Unexpected number of certs")
		}

		if decodedCerts[0].Subject.CommonName != commonName {
			t.Errorf("expected common name to be %q, but found %q", commonName, decodedCerts[0].Subject.CommonName)
		}
	}
}

func TestPBES2_AES256CBC(t *testing.T) {
	// This P12 PDU is a self-signed certificate exported via Windows certmgr.
	// It is encrypted with the following options (verified via openssl): PBES2, PBKDF2, AES-256-CBC, Iteration 2000, PRF hmacWithSHA256
	commonName := "*.ad.standalone.com"
	base64P12 := `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`
	p12, _ := base64.StdEncoding.DecodeString(base64P12)
	pk, cert, caCerts, err := DecodeChain(p12, "password")
	if err != nil {
		t.Fatal(err)
	}

	rsaPk, ok := pk.(*rsa.PrivateKey)
	if !ok {
		t.Error("could not cast to rsa private key")
	}
	if !rsaPk.PublicKey.Equal(cert.PublicKey) {
		t.Error("public key embedded in private key not equal to public key of certificate")
	}
	if cert.Subject.CommonName != commonName {
		t.Errorf("unexpected leaf cert common name, got %s, want %s", cert.Subject.CommonName, commonName)
	}
	if len(caCerts) != 0 {
		t.Errorf("unexpected # of caCerts: got %d, want 0", len(caCerts))
	}
}

func TestPBES2_AES128CBC(t *testing.T) {
	//PKCS7 Encrypted data: PBES2, PBKDF2, AES-128-CBC, Iteration 2048, PRF hmacWithSHA256
	commonName := "example-com"
	base64P12 := `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`

	p12, _ := base64.StdEncoding.DecodeString(base64P12)
	pk, cert, caCerts, err := DecodeChain(p12, "rHyQTJsubhfxcpH5JttyilHE6BBsNoZp")
	if err != nil {
		t.Fatal(err)
	}

	rsaPk, ok := pk.(*rsa.PrivateKey)
	if !ok {
		t.Error("could not cast to rsa private key")
	}
	if !rsaPk.PublicKey.Equal(cert.PublicKey) {
		t.Error("public key embedded in private key not equal to public key of certificate")
	}
	if cert.Subject.CommonName != commonName {
		t.Errorf("unexpected leaf cert common name, got %s, want %s", cert.Subject.CommonName, commonName)
	}
	if len(caCerts) != 0 {
		t.Errorf("unexpected # of caCerts: got %d, want 0", len(caCerts))
	}
}

func TestPBES2_AES192CBC(t *testing.T) {
	//PKCS7 Encrypted data: PBES2, PBKDF2, AES-192-CBC, Iteration 2048, PRF hmacWithSHA256
	commonName := "example-com"
	base64P12 := `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`

	p12, _ := base64.StdEncoding.DecodeString(base64P12)
	pk, cert, caCerts, err := DecodeChain(p12, "password")
	if err != nil {
		t.Fatal(err)
	}

	rsaPk, ok := pk.(*rsa.PrivateKey)
	if !ok {
		t.Error("could not cast to rsa private key")
	}
	if !rsaPk.PublicKey.Equal(cert.PublicKey) {
		t.Error("public key embedded in private key not equal to public key of certificate")
	}
	if cert.Subject.CommonName != commonName {
		t.Errorf("unexpected leaf cert common name, got %s, want %s", cert.Subject.CommonName, commonName)
	}
	if len(caCerts) != 0 {
		t.Errorf("unexpected # of caCerts: got %d, want 0", len(caCerts))
	}
}

// PBE-SHA1-RC2-128
const encryptedPkcs8Key1 = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIGxMBwGCiqGSIb3DQEMAQUwDgQIgGZ6tBRXF4oCAggABIGQ4w2KkYUWu7/d3hJk
Ns7ZwCy2xZmIxmU9GTybuH7fXwP38UOYlG9uPeSlP5uB3Brf0tWxC4jmRCjs7weT
gbAZ6PsB2Bm5uaGBcAcoWmcP6zZQ3ZRc1TLX2ZQ/f3Et6zQQdMVABxwnnzjt6fkG
HupHzh20Yu+oSuih2xOeqgprJhJ55MiU3jK9ZKAamH+GUW3Z
-----END ENCRYPTED PRIVATE KEY-----
`

// PBE-SHA1-3DES
const encryptedPkcs8Key2 = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIGxMBwGCiqGSIb3DQEMAQMwDgQIkelJzp3UvagCAggABIGQYmxfWr/ltzkRXFti
96cUiyjvQBSzKWp5RRrUIugBrdNc+3dRVuJKrg/D7uS/WHJm88cT+vjN35CC0Mj6
gWm/m2Uif5caR/+xBG3cfR1viPk/xw+Wt1BDwhG6j3CavNf3xub5sUv4vC1/KuYB
GmpyFm3DnvYQsX5vIrcF7HIXKJVYkf/KLlrzveOL90E0PZwI
-----END ENCRYPTED PRIVATE KEY-----
`

// PBE-SHA1-RC2-40
const encryptedPkcs8Key3 = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIGxMBwGCiqGSIb3DQEMAQYwDgQIqJHFfKsrifgCAggABIGQzYGZMUmqsmIQ+Kns
A7pzTzvsDqWq54GAKtrCowNjYxd31WWjODQC35qB6gP+fAITlxKOB5QTiB5VDUW7
V2Q3jvacDUBwl0zsPKNVKOGwHcQU0gkFKI60uKfiJ9+6ZcnVh3TLNTKec7c7tqIa
ER59uC1RfTqtFRyRedYowSE3dodBNKtsYg+YF51Jes6gjCvM
-----END ENCRYPTED PRIVATE KEY-----
`

const encryptedEC256aes128sha1 = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHeMEkGCSqGSIb3DQEFDTA8MBsGCSqGSIb3DQEFDDAOBAgEoFG3x07DbQICCAAw
HQYJYIZIAWUDBAECBBCRN9PNX9rBqXhaHLUOsv7YBIGQFfXAPPV+COWABJdSarog
eUHFNaQ+R6x55Tz/mquNIwiOrP9DNoEd1PGtKaHaO+ACSEQwMfrGeh8BuNV69EwP
bhsob/MZeexRbrLe2YN7Y7/Y0wpujalGlliMvs35f1fpq/9RfVU+qRpFED2lT4dm
zOuhMC9Oo3oMYlbEXAT9mq33MkGKMUth2ek/bQIvnCHG
-----END ENCRYPTED PRIVATE KEY-----
`

func TestParsePKCS8PrivateKey(t *testing.T) {
	block, _ := pem.Decode([]byte(encryptedPkcs8Key1))
	_, err := ParsePKCS8PrivateKey(block.Bytes, "12345678")
	if err != nil {
		t.Errorf("ParsePKCS8PrivateKey returned: %s", err)
	}
	block, _ = pem.Decode([]byte(encryptedPkcs8Key2))
	_, err = ParsePKCS8PrivateKey(block.Bytes, "12345678")
	if err != nil {
		t.Errorf("ParsePKCS8PrivateKey returned: %s", err)
	}
	block, _ = pem.Decode([]byte(encryptedPkcs8Key3))
	_, err = ParsePKCS8PrivateKey(block.Bytes, "12345678")
	if err != nil {
		t.Errorf("ParsePKCS8PrivateKey returned: %s", err)
	}
	block, _ = pem.Decode([]byte(encryptedEC256aes128sha1))
	_, err = ParsePKCS8PrivateKey(block.Bytes, "password")
	if err != nil {
		t.Errorf("ParsePKCS8PrivateKey returned: %s", err)
	}
}

var testdata = map[string]string{
	// 'null' password test case
	"Windows Azure Tools": `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`,
	// empty string password test case
	"testing@example.com": `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
HQ8CAggA`,
}
