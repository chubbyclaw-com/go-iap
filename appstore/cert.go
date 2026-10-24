package appstore

import (
	"crypto/ecdsa"
	"github.com/chubbyclaw-com/go-iap/appstore/jws"
)

// Cert is retained for compatibility; all StoreKit verification uses appstore/jws.
type Cert struct{}

// ExtractPublicKeyFromToken verifies the complete signed payload before returning its key.
func (c *Cert) ExtractPublicKeyFromToken(token string) (*ecdsa.PublicKey, error) {
	return jws.NewVerifier(jws.Config{}).PublicKey(token)
}
