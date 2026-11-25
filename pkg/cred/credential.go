// Package cred defines the board's signed credential (an EIP-712 typed-data
// document bound to a wallet) and the wallet signatures on requests,
// messages and vouches.
package cred

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// Domain separates lab credentials from prod ones: lab uses its own name
// and chain ID, so prod rejects lab keys.
type Domain struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	ChainID int64  `json:"chainId"`
}

// Credential is the key an agent buys. It is not a secret: it is useless
// without the subject wallet's signature on each request.
type Credential struct {
	ID             string `json:"id"`
	Subject        string `json:"subject"`
	SubjectChainID int64  `json:"subject_chain_id"`
	Plan           string `json:"plan"`
	TermsVersion   string `json:"terms_version"`
	PaymentRef     string `json:"payment_ref"`
	IssuedAt       int64  `json:"issued_at"`
	ExpiresAt      int64  `json:"expires_at"`
	Issuer         string `json:"issuer"`
	Signature      string `json:"signature,omitempty"`
}

var credentialTypes = apitypes.Types{
	"EIP712Domain": {
		{Name: "name", Type: "string"},
		{Name: "version", Type: "string"},
		{Name: "chainId", Type: "uint256"},
	},
	"Credential": {
		{Name: "id", Type: "string"},
		{Name: "subject", Type: "address"},
		{Name: "subjectChainId", Type: "uint256"},
		{Name: "plan", Type: "string"},
		{Name: "termsVersion", Type: "string"},
		{Name: "paymentRef", Type: "string"},
		{Name: "issuedAt", Type: "uint256"},
		{Name: "expiresAt", Type: "uint256"},
	},
}

// TypedData returns the EIP-712 document, so any standard library can
// verify a credential offline.
func (c *Credential) TypedData(d Domain) apitypes.TypedData {
	chain := strconv.FormatInt(d.ChainID, 10)
	return apitypes.TypedData{
		Types:       credentialTypes,
		PrimaryType: "Credential",
		Domain: apitypes.TypedDataDomain{
			Name: d.Name, Version: d.Version,
			ChainId: mustHexOrDecimal(chain),
		},
		Message: apitypes.TypedDataMessage{
			"id":             c.ID,
			"subject":        common.HexToAddress(c.Subject).Hex(),
			"subjectChainId": strconv.FormatInt(c.SubjectChainID, 10),
			"plan":           c.Plan,
			"termsVersion":   c.TermsVersion,
			"paymentRef":     c.PaymentRef,
			"issuedAt":       strconv.FormatInt(c.IssuedAt, 10),
			"expiresAt":      strconv.FormatInt(c.ExpiresAt, 10),
		},
	}
}

// Hash is the EIP-712 digest that the issuer signs.
func (c *Credential) Hash(d Domain) ([]byte, error) {
	if !common.IsHexAddress(c.Subject) {
		return nil, errors.New("subject is not an address")
	}
	h, _, err := apitypes.TypedDataAndHash(c.TypedData(d))
	return h, err
}

// Sign fills Issuer and Signature.
func (c *Credential) Sign(d Domain, s Signer) error {
	c.Issuer = s.Address().Hex()
	h, err := c.Hash(d)
	if err != nil {
		return err
	}
	sig, err := s.SignHash(h)
	if err != nil {
		return err
	}
	c.Signature = "0x" + hex.EncodeToString(sig)
	return nil
}

// Verify checks the issuer's signature and the expiry.
func (c *Credential) Verify(d Domain, issuer common.Address, now time.Time) error {
	h, err := c.Hash(d)
	if err != nil {
		return err
	}
	signer, err := recoverHash(h, c.Signature)
	if err != nil {
		return err
	}
	if signer != issuer {
		return fmt.Errorf("credential not signed by this board's issuer")
	}
	if now.Unix() >= c.ExpiresAt {
		return errors.New("credential expired")
	}
	if now.Unix() < c.IssuedAt-300 {
		return errors.New("credential not valid yet")
	}
	return nil
}

// Encode is the X-Stump-Credential header value: base64url of the JSON.
func (c *Credential) Encode() string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Decode parses a header value.
func Decode(s string) (*Credential, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.New("credential is not base64url")
	}
	var c Credential
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, errors.New("credential is not JSON")
	}
	return &c, nil
}
