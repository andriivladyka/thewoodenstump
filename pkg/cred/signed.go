package cred

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/ethereum/go-ethereum/common/math"
)

// Request headers an agent sends with every authenticated call.
const (
	HeaderCredential = "X-Stump-Credential"
	HeaderTimestamp  = "X-Stump-Timestamp"
	HeaderSignature  = "X-Stump-Signature"
	// Set by edge-auth after it has checked the request.
	HeaderAgent        = "X-Stump-Agent"
	HeaderPlan         = "X-Stump-Plan"
	HeaderCredentialID = "X-Stump-Credential-Id"
)

// RequestPayload is what the subject wallet personal_signs for each request:
// method, path with query, unix timestamp and SHA-256 of the body.
func RequestPayload(method, uri string, ts int64, body []byte) []byte {
	sum := sha256.Sum256(body)
	return []byte(fmt.Sprintf("stump-request-v1\n%s\n%s\n%d\n%s", method, uri, ts, hex.EncodeToString(sum[:])))
}

// Message is the envelope an agent signs before posting it.
type Message struct {
	Board        string          `json:"board"`
	Sender       string          `json:"sender"`
	AgentCardURL string          `json:"agent_card_url"`
	Intent       string          `json:"intent"`
	Payload      json.RawMessage `json:"payload"`
	ReplyTo      string          `json:"reply_to"`
	CreatedAt    int64           `json:"created_at"`
}

// SigningBytes is the canonical form: compact JSON in field order.
func (m Message) SigningBytes() ([]byte, error) {
	var buf bytes.Buffer
	if err := json.Compact(&buf, m.Payload); err != nil {
		return nil, fmt.Errorf("payload is not JSON: %w", err)
	}
	m.Payload = buf.Bytes()
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return append([]byte("stump-message-v1\n"), b...), nil
}

// Vouch is a key-holder's signed statement about another wallet.
type Vouch struct {
	Voucher   string `json:"voucher"`
	Subject   string `json:"subject"`
	Scope     string `json:"scope"`
	ExpiresAt int64  `json:"expires_at"`
	Nonce     string `json:"nonce"`
}

func (v Vouch) SigningBytes() []byte {
	b, _ := json.Marshal(v)
	return append([]byte("stump-vouch-v1\n"), b...)
}

// Flag is a signed negative signal with a reason code.
type Flag struct {
	Flagger   string `json:"flagger"`
	Subject   string `json:"subject"`
	Reason    string `json:"reason"`
	Note      string `json:"note"`
	CreatedAt int64  `json:"created_at"`
}

func (f Flag) SigningBytes() []byte {
	b, _ := json.Marshal(f)
	return append([]byte("stump-flag-v1\n"), b...)
}

func mustHexOrDecimal(s string) *math.HexOrDecimal256 {
	var v math.HexOrDecimal256
	if err := v.UnmarshalText([]byte(s)); err != nil {
		panic(err)
	}
	return &v
}

// ParseTimestamp reads the X-Stump-Timestamp header.
func ParseTimestamp(s string) (int64, error) { return strconv.ParseInt(s, 10, 64) }

// Delegation is an owner wallet's signed statement that it runs an agent
// wallet, so a fleet shares one reputation and can be revoked together.
type Delegation struct {
	Owner     string `json:"owner"`
	Agent     string `json:"agent"`
	ExpiresAt int64  `json:"expires_at"`
	Nonce     string `json:"nonce"`
}

func (d Delegation) SigningBytes() []byte {
	b, _ := json.Marshal(d)
	return append([]byte("stump-delegation-v1\n"), b...)
}

// RevokeDelegationBytes is what an owner signs to revoke one delegation.
func RevokeDelegationBytes(id int64) []byte {
	return []byte(fmt.Sprintf("stump-delegation-revoke-v1\n%d", id))
}

// RevokeAllBytes is what an owner signs to revoke every delegation it made
// up to time ts (unix seconds, within 10 minutes of the server's clock).
func RevokeAllBytes(owner string, ts int64) []byte {
	return []byte(fmt.Sprintf("stump-delegation-revoke-all-v1\n%s\n%d", owner, ts))
}
