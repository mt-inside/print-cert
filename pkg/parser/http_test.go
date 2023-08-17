package parser

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mt-inside/print-cert/pkg/state"
)

func TestParseDraft03(t *testing.T) {
	hs := http.Header{}
	hs.Add("x-ratelimit-limit", "42, 69;w=1, 101;w=3600")
	hs.Add("x-ratelimit-remaining", "3")
	hs.Add("x-ratelimit-reset", "11")

	res := Ratelimit(hs)

	require.Equal(t,
		&state.HttpRatelimit{
			Bucket: 42,
			Remain: 3,
			Reset:  11 * time.Second,
			Policies: []state.HttpRatelimitPolicy{
				state.HttpRatelimitPolicy{
					Bucket: 69,
					Window: 1 * time.Second,
				},
				state.HttpRatelimitPolicy{
					Bucket: 101,
					Window: 1 * time.Hour,
				},
			},
		},
		res,
	)
}

// func TestParseDraft07(t *testing.T) {
// 	hs := http.Header{}
// 	hs.Add("x-ratelimit", "limit=42, remaining=3, reset=11")
// 	hs.Add("x-ratelimit-policy", "69;w=1, 101;w=3600")

// 	res := Ratelimit(hs)

// 	require.Equal(t,
// 		&state.HttpRatelimit{
// 			Bucket: 42,
// 			Remain: 3,
// 			Reset:  11 * time.Second,
// 			Policies: []state.HttpRatelimitPolicy{
// 				state.HttpRatelimitPolicy{
// 					Bucket: 69,
// 					Window: 1 * time.Second,
// 				},
// 				state.HttpRatelimitPolicy{
// 					Bucket: 101,
// 					Window: 1 * time.Hour,
// 				},
// 			},
// 		},
// 		res,
// 	)
// }
