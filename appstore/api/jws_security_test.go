package api

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestMalformedJWS(t *testing.T) {
	client := NewStoreClient(&StoreConfig{})
	for _, input := range []string{"", "one", "a.b", "e30.e30.AA", "eyJ4NWMiOltdfQ.e30.AA"} {
		t.Run(input, func(t *testing.T) {
			require.NotPanics(t, func() {
				value, err := client.ParseJWSEncodeString(input)
				require.Error(t, err)
				require.Nil(t, value)
			})
			require.NotPanics(t, func() { _, err := client.ParseSignedTransaction(input); require.Error(t, err) })
			_, err := client.ParseSignedTransactions([]string{input})
			require.Error(t, err)
		})
	}
}
