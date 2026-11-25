// Package ports holds the interfaces that keep payments and the chain
// swappable: lab runs the trial adapter and a dry-run chain.
package ports

import (
	"context"
	"errors"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

// ErrPaymentsDisabled means the rail exists but is switched off here.
var ErrPaymentsDisabled = errors.New("payments_disabled")

// ErrNotEligible means the buyer cannot use this rail (for example, a wallet
// that is not on the trial allowlist).
var ErrNotEligible = errors.New("not_eligible")

// Purchase is what a rail decides about one key request.
type Purchase struct {
	Plan       string
	ValidDays  int
	PaymentRef string // for example a transaction hash, or trial:<order>
}

// PurchaseRequest is a key request after validation.
type PurchaseRequest struct {
	OrderID string
	Wallet  common.Address
	ChainID int64
}

// PaymentProvider is one payment rail.
type PaymentProvider interface {
	Name() string
	Enabled() bool
	// Start either settles the purchase at once (trial) or returns an error.
	Start(ctx context.Context, req PurchaseRequest) (*Purchase, error)
}

// Trial gives free keys to wallets on the tester allowlist, or to any
// wallet when Open (the public beta).
type Trial struct {
	On        bool
	Open      bool
	Days      int
	allowlist map[common.Address]bool
}

// NewTrial parses a comma- or whitespace-separated list of addresses.
func NewTrial(on, open bool, days int, allowlist string) *Trial {
	t := &Trial{On: on, Open: open, Days: days, allowlist: map[common.Address]bool{}}
	for _, a := range strings.FieldsFunc(allowlist, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		if common.IsHexAddress(a) {
			t.allowlist[common.HexToAddress(a)] = true
		}
	}
	return t
}

func (t *Trial) Name() string                  { return "trial" }
func (t *Trial) Enabled() bool                 { return t.On }
func (t *Trial) Allowed(a common.Address) bool { return t.Open || t.allowlist[a] }

// Listed reports whether the wallet is on the allowlist (first-party bots
// and tests), which skips the open-trial limits.
func (t *Trial) Listed(a common.Address) bool { return t.allowlist[a] }

func (t *Trial) Start(_ context.Context, req PurchaseRequest) (*Purchase, error) {
	if !t.On {
		return nil, ErrPaymentsDisabled
	}
	if !t.Allowed(req.Wallet) {
		return nil, ErrNotEligible
	}
	return &Purchase{Plan: "trial", ValidDays: t.Days, PaymentRef: "trial:" + req.OrderID}, nil
}

// X402 will answer with 402 payment terms and verify settlement through a
// facilitator. Until it is switched on, it refuses every purchase.
type X402 struct{ On bool }

func (x *X402) Name() string  { return "x402" }
func (x *X402) Enabled() bool { return x.On }
func (x *X402) Start(context.Context, PurchaseRequest) (*Purchase, error) {
	return nil, ErrPaymentsDisabled
}

// Stripe will create Checkout sessions and handle signed webhooks.
type Stripe struct{ On bool }

func (s *Stripe) Name() string  { return "stripe" }
func (s *Stripe) Enabled() bool { return s.On }
func (s *Stripe) Start(context.Context, PurchaseRequest) (*Purchase, error) {
	return nil, ErrPaymentsDisabled
}
