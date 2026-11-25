package stump

import "strings"

// Public settings shared by every service, from the stump-config ConfigMap.
type Public struct {
	URL           string // base URL agents use, for example https://stump.lab.internal:20443
	TermsVersion  string
	Price         string // USD per key per year
	Environment   string // lab, beta or prod
	Status        string // operating, read_only or sunset; set by the operator
	SunsetDate    string // YYYY-MM-DD once a shutdown is announced
	StatusURL     string // off-server mirror of status and discovery files
	Contact       string // abuse, takedown and legal requests
	TrialEnabled  bool
	TrialOpen     bool // any wallet gets a trial key, not only the allowlist
	X402Enabled   bool
	StripeEnabled bool
}

func PublicFromEnv() Public {
	return Public{
		URL:           strings.TrimRight(Env("STUMP_PUBLIC_URL", "http://localhost:8080"), "/"),
		TermsVersion:  Env("STUMP_TERMS_VERSION", "2026-11-24"),
		Price:         Env("STUMP_PRICE_USD", "12.00"),
		Environment:   Env("STUMP_ENVIRONMENT", "lab"),
		Status:        Env("STUMP_STATUS", "operating"),
		SunsetDate:    Env("STUMP_SUNSET_DATE", ""),
		StatusURL:     strings.TrimRight(Env("STUMP_STATUS_URL", ""), "/"),
		Contact:       Env("STUMP_CONTACT_EMAIL", ""),
		TrialEnabled:  EnvBool("PAYMENTS_TRIAL", false),
		TrialOpen:     EnvBool("TRIAL_OPEN", false),
		X402Enabled:   EnvBool("PAYMENTS_X402", false),
		StripeEnabled: EnvBool("PAYMENTS_STRIPE", false),
	}
}

// ReadOnly reports whether writes are switched off: the operator's kill
// switch, and always once a sunset is announced.
func (p Public) ReadOnly() bool { return p.Status == "read_only" || p.Status == "sunset" }

// PurchaseTerms is the machine-readable answer to a call without a key
// (HTTP 402) and part of the Agent Card.
func (p Public) PurchaseTerms() map[string]any {
	rails := []map[string]any{}
	if p.TrialEnabled {
		note := "free 30-day key for wallets on the tester allowlist"
		if p.TrialOpen {
			note = "free 30-day key for any wallet during the public beta; ask again to renew"
		}
		rails = append(rails, map[string]any{"rail": "trial", "price": "0.00", "note": note})
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
