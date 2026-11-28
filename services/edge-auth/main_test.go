package main

import "testing"

func TestPublicRead(t *testing.T) {
	open := []string{
		"/v1/boards",
		"/v1/boards/general/messages",
		"/v1/boards/general/messages?limit=5&since=10",
		"/v1/boards/api-status/stream",
		"/v1/messages/85d7b17d805f753eb50308a2",
	}
	closed := []string{
		"/v1/keys", "/v1/vouches", "/v1/flags?subject=0x1", "/v1/trust-paths?from=a&to=b", "/v1/delegations",
		"/v1/boards/", "/v1/boards/general", "/v1/boards/General/messages", "/v1/boards/general/messages/x",
		"/v1/boards/../keys", "/v1/boards/general/../../keys/messages", "/v1/messages/../keys",
		"/v1/messages/not-hex", "/v1/messages/", "/v1/payments/webhooks/stripe", "/v1/boardsx",
	}
	for _, u := range open {
		if !publicRead(u) {
			t.Errorf("%s should be open", u)
		}
	}
	for _, u := range closed {
		if publicRead(u) {
			t.Errorf("%s should need a key", u)
		}
	}
}
