package parser

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mt-inside/print-cert/pkg/state"
)

/* As of Aug '23 these headers are draft standard [https://datatracker.ietf.org/doc/draft-ietf-httpapi-ratelimit-headers/]
* This draft has version 0-7
* Current Envoy (1.28) emits only draft 3
* Thus that's all we support atm
 */
func Ratelimit(hs http.Header) *state.HttpRatelimit {
	/* Note on the log levels:
	 * - nothing is an Error, cause we can gracefully recover
	 * - Info for parse errors, cause either we don't code that case yet, or the origin is buggy
	 * - Debug for algo trace
	 */

	if limitH := hs.Get("x-ratelimit-limit"); limitH != "" {
		return parseDraft03(hs)
	} else if limitH := hs.Get("x-ratelimit"); limitH != "" {
		return parseDraft07(hs)
	} else {
		log.Debug("No ratelimit header")
		return nil
	}
}

func parseDraft03(hs http.Header) *state.HttpRatelimit {

	/* Format
	 * ratelimit-limit: 42, 69;w=1, 101;w=3600 (first expiring bucket, then policies)
	 * ratelimit-remaining: 3
	 * ratelimit-reset: 11 (seconds)
	 */

	// REQUIRED by the spec
	limitH := hs.Get("x-ratelimit-limit")

	policies := strings.Split(limitH, ", ")
	log.Debug("Found ratelimit policies", "count", len(policies)-1)
	if len(policies) < 1 {
		log.Info("x-ratelimit-limit doesn't contain mandatory expiring-limit")
		return nil
	}
	expiring, err := strconv.Atoi(policies[0])
	if err != nil {
		log.Info("x-ratelimit-limit's expiring-limit doesn't parse", "error", err)
		return nil
	}

	// RECOMMENDED by the spec
	remain, err := strconv.Atoi(hs.Get("x-ratelimit-remaining"))
	if err != nil {
		log.Info("can't parse ratelimit remaining", "error", err)
	}

	// REQUIRED by the spec
	resetN, err := strconv.Atoi(hs.Get("x-ratelimit-reset"))
	if err != nil {
		log.Info("can't parse ratelimit reset duration", "error", err)
	}

	r := &state.HttpRatelimit{
		Bucket: uint64(expiring),
		Remain: uint64(remain),
		Reset:  time.Duration(resetN) * time.Second,
	}

	for _, policy := range policies[1:] {
		sections := strings.Split(policy, ";")
		log.Debug("Parsed policy", "sections", len(sections))

		if len(sections) < 1 {
			log.Info("unknown x-ratelimit-limit policy format", "error", fmt.Errorf("expecting policy to have at least 1 ;-delimited section"))
			return nil
		}
		bucket, err := strconv.Atoi(sections[0])
		if err != nil {
			log.Info("can't parse ratelimit bucket size", "error", err)
			return nil
		}

		policy := state.HttpRatelimitPolicy{Bucket: uint64(bucket)}

		for _, section := range sections[1:] {
			kv := strings.Split(section, "=")
			if len(kv) != 2 {
				log.Info("unknown x-ratelimit-limit format", "error", fmt.Errorf("expecting policy section to have form foo=bar"))
				return nil
			}
			switch kv[0] {
			// MANDATORY
			case "w":
				window, err := strconv.Atoi(kv[1])
				if err != nil {
					log.Info("can't parse ratelimit window", "error", err)
				} else {
					policy.Window = time.Duration(window) * time.Second
				}
			default:
				log.Debug("Unhandled policy statement", "statement", section)
			}
		}

		r.Policies = append(r.Policies, policy)
	}

	return r
}

func parseDraft07(hs http.Header) *state.HttpRatelimit {
	/* Format
	 * ratelimit: limit=42, remaining=3, reset=11 (seconds)
	 * ratelimit-policy: 69;w=1, 101;w=3600
	 */

	panic("TODO: parse ratelimit headers draft 07")
}

func CORS(hs http.Header) *state.HttpCORS {
	if origin := hs.Get("access-control-allow-origin"); origin != "" {
		cors := &state.HttpCORS{
			Origin: origin,
			MaxAge: 5, // default
		}

		if methods := hs.Values("access-control-allow-methods"); len(methods) != 0 {
			cors.Methods = methods
		}

		if headers := hs.Values("access-control-allow-headers"); len(headers) != 0 {
			cors.Headers = headers
		}

		if exposeHeaders := hs.Values("access-control-expose-headers"); len(exposeHeaders) != 0 {
			cors.ExposeHeaders = exposeHeaders
		}

		if maxAge := hs.Get("access-control-max-age"); maxAge != "" {
			if n, err := strconv.ParseInt(maxAge, 10, 64); err != nil {
				cors.MaxAge = n
			}
		}

		if creds := hs.Get("access-control-allow-credentials"); creds != "" {
			if b, err := strconv.ParseBool(creds); err != nil {
				cors.Credentials = b
			}
		}

		return cors
	}

	return nil
}
