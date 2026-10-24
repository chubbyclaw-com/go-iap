package jws

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

var testDate = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

type fixture struct {
	roots *x509.CertPool
	key   *ecdsa.PrivateKey
	chain []string
}

func makeFixture(t testing.TB, leafOID, intermediateOID bool, curve elliptic.Curve) fixture {
	t.Helper()
	key := func(c elliptic.Curve) *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(c, rand.Reader)
		require.NoError(t, err)
		return k
	}
	rootKey, interKey, leafKey := key(elliptic.P256()), key(elliptic.P256()), key(curve)
	cert := func(n int64, ca bool) *x509.Certificate {
		return &x509.Certificate{SerialNumber: big.NewInt(n), Subject: pkix.Name{CommonName: "fixture"}, NotBefore: testDate.Add(-time.Hour), NotAfter: testDate.Add(time.Hour), IsCA: ca, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign}
	}
	root, inter, leaf := cert(1, true), cert(2, true), cert(3, false)
	if leafOID {
		leaf.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 11, 1}, Value: []byte{5, 0}}}
	}
	if intermediateOID {
		inter.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 2, 1}, Value: []byte{5, 0}}}
	}
	create := func(c, p *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
		der, err := x509.CreateCertificate(rand.Reader, c, p, pub, signer)
		require.NoError(t, err)
		parsed, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return parsed
	}
	root = create(root, root, &rootKey.PublicKey, rootKey)
	inter = create(inter, root, &interKey.PublicKey, rootKey)
	leaf = create(leaf, inter, &leafKey.PublicKey, interKey)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return fixture{roots, leafKey, []string{base64.StdEncoding.EncodeToString(leaf.Raw), base64.StdEncoding.EncodeToString(inter.Raw), base64.StdEncoding.EncodeToString(root.Raw)}}
}
func (f fixture) sign(t testing.TB, method jwt.SigningMethod, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(method, claims)
	token.Header["x5c"] = f.chain
	s, err := token.SignedString(f.key)
	require.NoError(t, err)
	return s
}
func (f fixture) verifier() *Verifier {
	return NewVerifier(Config{Roots: f.roots, Now: func() time.Time { return testDate.Add(365 * 24 * time.Hour) }})
}
func TestTrustedHistoricalSignature(t *testing.T) {
	f := makeFixture(t, true, true, elliptic.P256())
	s := f.sign(t, jwt.SigningMethodES256, jwt.MapClaims{"signedDate": testDate.UnixMilli(), "transactionId": "123"})
	var payload struct {
		TransactionID string `json:"transactionId"`
	}
	require.NoError(t, f.verifier().Verify(s, &payload))
	require.Equal(t, "123", payload.TransactionID)
	require.Error(t, NewVerifier(Config{}).Verify(s, &payload), "default Apple roots must reject generated roots")
}
func TestTrustedChainPurposeOIDs(t *testing.T) {
	for _, tc := range []struct {
		name        string
		leaf, inter bool
	}{{"missing leaf", false, true}, {"missing intermediate", true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			f := makeFixture(t, tc.leaf, tc.inter, elliptic.P256())
			s := f.sign(t, jwt.SigningMethodES256, jwt.MapClaims{"signedDate": testDate.UnixMilli()})
			var dst map[string]interface{}
			require.ErrorContains(t, f.verifier().Verify(s, &dst), "OID")
		})
	}
}
func TestInvalidSignatures(t *testing.T) {
	f := makeFixture(t, true, true, elliptic.P256())
	valid := f.sign(t, jwt.SigningMethodES256, jwt.MapClaims{"signedDate": testDate.UnixMilli()})
	parts := strings.Split(valid, ".")
	inputs := []string{"", "a", "a.b", valid + ".extra", "e30.e30.AA", parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"signedDate":1704067200001}`)) + "." + parts[2], parts[0] + "." + parts[1] + ".AA", parts[0] + "." + parts[1] + "." + parts[2] + "=", parts[0] + "\n." + parts[1] + "." + parts[2]}
	for _, payload := range []jwt.MapClaims{{}, {"signedDate": -1}, {"signedDate": "wrong"}, {"signedDate": testDate.Add(2 * time.Hour).UnixMilli()}, {"signedDate": testDate.Add(366 * 24 * time.Hour).UnixMilli()}} {
		inputs = append(inputs, f.sign(t, jwt.SigningMethodES256, payload))
	}
	for _, chain := range [][]string{nil, {}, f.chain[:1], f.chain[:2], {"bad", f.chain[1], f.chain[2]}, {"MA==", f.chain[1], f.chain[2]}} {
		bad := f
		bad.chain = chain
		inputs = append(inputs, bad.sign(t, jwt.SigningMethodES256, jwt.MapClaims{"signedDate": testDate.UnixMilli()}))
	}
	wrongCurve := makeFixture(t, true, true, elliptic.P384())
	inputs = append(inputs, wrongCurve.sign(t, jwt.SigningMethodES384, jwt.MapClaims{"signedDate": testDate.UnixMilli()}))
	for _, s := range inputs {
		var dst map[string]interface{}
		require.NotPanics(t, func() { require.Error(t, f.verifier().Verify(s, &dst)) })
	}
	// The chain is otherwise trusted: rejection must specifically enforce ES256/P-256.
	var dst map[string]interface{}
	require.ErrorContains(t, wrongCurve.verifier().Verify(wrongCurve.sign(t, jwt.SigningMethodES384, jwt.MapClaims{"signedDate": testDate.UnixMilli()}), &dst), "ES256")
}
func FuzzVerifier(f *testing.F) {
	chain := makeFixture(f, true, true, elliptic.P256())
	v := chain.verifier()
	f.Add(chain.sign(f, jwt.SigningMethodES256, jwt.MapClaims{"signedDate": testDate.UnixMilli()}))
	f.Add("")
	f.Add("e30.e30.AA")
	f.Fuzz(func(t *testing.T, s string) { var dst map[string]interface{}; _ = v.Verify(s, &dst) })
}

func TestOfflineEffectiveDate(t *testing.T) {
	f := makeFixture(t, true, true, elliptic.P256())
	v := NewVerifier(Config{Roots: f.roots, Now: func() time.Time { return testDate.Add(-30 * time.Second) }})
	for _, claims := range []jwt.MapClaims{{"transactionId": "123"}, {"signedDate": testDate.UnixMilli(), "transactionId": "123"}} {
		t.Run(fmt.Sprint(claims), func(t *testing.T) {
			var dst map[string]interface{}
			require.NoError(t, v.Verify(f.sign(t, jwt.SigningMethodES256, claims), &dst))
		})
	}
}

func TestRejectNullPayload(t *testing.T) {
	f := makeFixture(t, true, true, elliptic.P256())
	v := NewVerifier(Config{Roots: f.roots, Now: func() time.Time { return testDate }})
	var dst map[string]interface{}
	require.Error(t, v.Verify(f.sign(t, jwt.SigningMethodES256, nil), &dst))
}

func TestES256RequiresP256Leaf(t *testing.T) {
	f := makeFixture(t, true, true, elliptic.P384())
	token := jwt.NewWithClaims(jwt.SigningMethodES384, jwt.MapClaims{"signedDate": testDate.UnixMilli()})
	token.Header["x5c"] = f.chain
	token.Header["alg"] = "ES256"
	signed, err := token.SignedString(f.key)
	require.NoError(t, err)
	var dst map[string]interface{}
	require.ErrorContains(t, f.verifier().Verify(signed, &dst), "P-256")
}
