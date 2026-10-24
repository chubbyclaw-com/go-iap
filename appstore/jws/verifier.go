// Package jws verifies StoreKit 2 signed data offline against explicitly trusted roots.
package jws

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Config supplies trust anchors and a clock. Nil Roots trusts only Apple Root CA G3;
// nil Now uses time.Now. Configured roots are cloned and must be trusted out of band.
// Certificate validity is evaluated at the signedDate, not at verification time.
// Verification is offline: revocation/OCSP checks are not performed.
type Config struct {
	Roots *x509.CertPool
	Now   func() time.Time
}
type Verifier struct {
	roots *x509.CertPool
	now   func() time.Time
}

func NewVerifier(config Config) *Verifier {
	roots := config.Roots
	if roots == nil {
		roots = x509.NewCertPool()
		roots.AppendCertsFromPEM([]byte(rootPEM))
	} else {
		roots = roots.Clone()
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &Verifier{roots: roots, now: now}
}

// Verify verifies the entire JWS before decoding its payload into a nonnil pointer.
// Application identity, environment and ownership checks remain the caller's responsibility.
func (v *Verifier) Verify(s string, result interface{}) error {
	if result == nil || reflect.ValueOf(result).Kind() != reflect.Ptr || reflect.ValueOf(result).IsNil() {
		return errors.New("jws: destination must be a nonnil pointer")
	}
	_, payload, err := v.verify(s)
	if err != nil {
		return err
	}
	return json.Unmarshal(payload, result)
}

// ParseWithClaims returns a validated JWT, preserving the public SDK parsing APIs.
func (v *Verifier) ParseWithClaims(s string, claims jwt.Claims) (*jwt.Token, error) {
	if claims == nil || (reflect.ValueOf(claims).Kind() == reflect.Ptr && reflect.ValueOf(claims).IsNil()) {
		return nil, errors.New("jws: nil claims")
	}
	key, _, err := v.verify(s)
	if err != nil {
		return nil, err
	}
	return jwt.ParseWithClaims(s, claims, func(*jwt.Token) (interface{}, error) { return key, nil }, jwt.WithValidMethods([]string{"ES256"}), jwt.WithTimeFunc(v.now))
}

// PublicKey verifies the JWS before returning its signing key. Prefer Verify or
// ParseWithClaims when consuming signed data.
func (v *Verifier) PublicKey(s string) (*ecdsa.PublicKey, error) {
	key, _, err := v.verify(s)
	return key, err
}

func (v *Verifier) verify(s string) (*ecdsa.PublicKey, []byte, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return nil, nil, errors.New("jws: expected three compact segments")
	}
	decoded := make([][]byte, 3)
	for i, part := range parts {
		b, err := base64.RawURLEncoding.Strict().DecodeString(part)
		if err != nil || len(b) == 0 || base64.RawURLEncoding.EncodeToString(b) != part {
			return nil, nil, errors.New("jws: invalid compact Base64URL")
		}
		decoded[i] = b
	}
	var header struct {
		Alg string   `json:"alg"`
		X5C []string `json:"x5c"`
	}
	if err := json.Unmarshal(decoded[0], &header); err != nil {
		return nil, nil, fmt.Errorf("jws: header: %w", err)
	}
	if header.Alg != "ES256" {
		return nil, nil, errors.New("jws: algorithm must be ES256")
	}
	if len(header.X5C) != 3 {
		return nil, nil, errors.New("jws: expected leaf, intermediate and root x5c certificates")
	}
	if !bytes.HasPrefix(bytes.TrimSpace(decoded[1]), []byte("{")) {
		return nil, nil, errors.New("jws: payload must be a JSON object")
	}
	var payload struct {
		SignedDate *int64 `json:"signedDate"`
	}
	if err := json.Unmarshal(decoded[1], &payload); err != nil {
		return nil, nil, fmt.Errorf("jws: payload: %w", err)
	}
	// Match Apple's offline effectiveDate: signedDate when present, otherwise now.
	// signedDate is authenticated by the signature; clock skew alone is not a rejection.
	at := v.now()
	if payload.SignedDate != nil {
		at = time.UnixMilli(*payload.SignedDate)
	}
	certs := make([]*x509.Certificate, 3)
	for i, encoded := range header.X5C {
		der, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil {
			return nil, nil, fmt.Errorf("jws: x5c: %w", err)
		}
		certs[i], err = x509.ParseCertificate(der)
		if err != nil {
			return nil, nil, fmt.Errorf("jws: certificate: %w", err)
		}
	}
	if !hasOID(certs[0], asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 11, 1}) || !hasOID(certs[1], asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 2, 1}) {
		return nil, nil, errors.New("jws: missing Apple signing purpose OID")
	}
	key, ok := certs[0].PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, nil, errors.New("jws: ES256 requires a P-256 signing key")
	}
	if certs[0].IsCA || certs[0].KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, nil, errors.New("jws: invalid signing certificate usage")
	}
	intermediates := x509.NewCertPool()
	intermediates.AddCert(certs[1])
	chains, err := certs[0].Verify(x509.VerifyOptions{Roots: v.roots, Intermediates: intermediates, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		return nil, nil, fmt.Errorf("jws: certificate chain: %w", err)
	}
	match := false
	for _, chain := range chains {
		if len(chain) == 3 && bytes.Equal(chain[1].Raw, certs[1].Raw) && bytes.Equal(chain[2].Raw, certs[2].Raw) {
			match = true
		}
	}
	if !match {
		return nil, nil, errors.New("jws: x5c does not match trusted chain")
	}
	if err := jwt.SigningMethodES256.Verify(parts[0]+"."+parts[1], decoded[2], key); err != nil {
		return nil, nil, fmt.Errorf("jws: signature: %w", err)
	}
	return key, decoded[1], nil
}
func hasOID(cert *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return true
		}
	}
	return false
}
