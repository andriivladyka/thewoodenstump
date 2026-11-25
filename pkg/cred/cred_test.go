package cred

import (
	"encoding/json"
	"testing"
	"time"
)

var lab = Domain{Name: "The Wooden Stump (lab)", Version: "1", ChainID: 84532}

func newCred(subject string, now time.Time) *Credential {
	return &Credential{ID: "c1", Subject: subject, SubjectChainID: 84532, Plan: "trial",
		TermsVersion: "2026-11-24", PaymentRef: "trial:o1",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(30 * 24 * time.Hour).Unix()}
}

func TestCredentialRoundTrip(t *testing.T) {
	issuer, agent := GenerateKeySigner(), GenerateKeySigner()
	now := time.Now()
	c := newCred(agent.Address().Hex(), now)
	if err := c.Sign(lab, issuer); err != nil {
		t.Fatal(err)
	}
	got, err := Decode(c.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Verify(lab, issuer.Address(), now); err != nil {
		t.Fatalf("valid credential rejected: %v", err)
	}
	if err := got.Verify(lab, agent.Address(), now); err == nil {
		t.Fatal("credential accepted for the wrong issuer")
	}
	prod := Domain{Name: "The Wooden Stump", Version: "1", ChainID: 8453}
	if err := got.Verify(prod, issuer.Address(), now); err == nil {
		t.Fatal("lab credential accepted under the prod domain")
	}
	if err := got.Verify(lab, issuer.Address(), now.Add(31*24*time.Hour)); err == nil {
		t.Fatal("expired credential accepted")
	}
	got.ExpiresAt++
	if err := got.Verify(lab, issuer.Address(), now); err == nil {
		t.Fatal("tampered credential accepted")
	}
}

func TestRequestSignature(t *testing.T) {
	agent := GenerateKeySigner()
	p := RequestPayload("POST", "/v1/boards/general/messages", 1700000000, []byte(`{"a":1}`))
	sig, err := SignText(agent, p)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := RecoverText(p, sig)
	if err != nil || addr != agent.Address() {
		t.Fatalf("recovered %v, %v", addr, err)
	}
	other := RequestPayload("POST", "/v1/boards/general/messages", 1700000000, []byte(`{"a":2}`))
	if addr, _ := RecoverText(other, sig); addr == agent.Address() {
		t.Fatal("signature valid for a different body")
	}
}

func TestMessageCanonicalForm(t *testing.T) {
	a := Message{Board: "general", Sender: "0xabc", Intent: "offer", Payload: json.RawMessage(`{ "x" : 1 }`)}
	b := a
	b.Payload = json.RawMessage(`{"x":1}`)
	ab, _ := a.SigningBytes()
	bb, _ := b.SigningBytes()
	if string(ab) != string(bb) {
		t.Fatalf("whitespace changed the signed bytes:\n%s\n%s", ab, bb)
	}
}
