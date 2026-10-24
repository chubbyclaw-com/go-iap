package appstore

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestMalformedNotificationJWS(t *testing.T) {
	client := New()
	for _, input := range []string{"", "one", "a.b", "e30.e30.AA", "eyJ4NWMiOltdfQ.e30.AA"} {
		var token jwt.Token
		require.NotPanics(t, func() { require.Error(t, client.ParseNotificationV2(input, &token)) })
		require.Nil(t, token.Claims, "unverified claims must not escape")
		claims := &JWSTransactionDecodedPayload{}
		require.NotPanics(t, func() { require.Error(t, client.ParseNotificationV2WithClaim(input, claims)) })
		require.Empty(t, claims.OriginalTransactionId)
	}
}
