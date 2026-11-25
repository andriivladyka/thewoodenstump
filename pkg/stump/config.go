package stump

import "strings"

// Public settings shared by every service, from the stump-config ConfigMap.
type Public struct {
	URL           string // base URL agents use, for example https://stump.lab.internal:20443
	TermsVersion  string
	Price         string // USD per key per year
	Environment   string // lab or prod
	TrialEnabled  bool
	X402Enabled   bool
	StripeEnabled bool
}

func PublicFromEnv() Public {
	return Public{
		URL:           strings.TrimRight(Env("STUMP_PUBLIC_URL", "http://localhost:8080"), "/"),
		TermsVersion:  Env("STUMP_TERMS_VERSION", "2026-11-24"),
		Price:         Env("STUMP_PRICE_USD", "12.00"),
		Environment:   Env("STUMP_ENVIRONMENT", "lab"),
		TrialEnabled:  EnvBool("PAYMENTS_TRIAL", false),
		X402Enabled:   EnvBool("PAYMENTS_X402", false),
		StripeEnabled: EnvBool("PAYMENTS_STRIPE", false),
	}
}

// PurchaseTerms is the machine-readable answer to a call without a key
// (HTTP 402) and part of the Agent Card.
func (p Public) PurchaseTerms() map[string]any {
	rails := []map[string]any{}
	if p.TrialEnabled {
		rails = append(rails, map[string]any{"rail": "trial", "price": "0.00",
			"note": "free 30-day key for wallets on the tester allowlist"})
	}
	rails = append(rails,
		map[string]any{"rail": "x402", "asset": "USDC", "network": "base", "enabled": p.X402Enabled},
		map[string]any{"rail": "stripe", "method": "card", "enabled": p.StripeEnabled})
	return map[string]any{
		"error":         "payment_required",
		"message":       "A key is required. Buy one with POST /v1/keys.",
		"price":         map[string]string{"amount": p.Price, "currency": "USD", "period": "365 days"},
		"terms_version": p.TermsVersion,
		"terms_url":     p.URL + "/.well-known/terms.json",
		"agent_card":    p.URL + "/.well-known/agent-card.json",
		"buy": map[string]any{
			"method": "POST", "url": p.URL + "/v1/keys",
			"body": map[string]string{"wallet": "0x...", "chain_id": "84532 or 8453",
				"terms_version": p.TermsVersion, "agent_card_url": "https://...", "rail": "trial | x402 | stripe"},
		},
		"rails": rails,
	}
}
