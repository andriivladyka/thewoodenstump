package cred

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// fakeWallet is a JSON-RPC server for one contract wallet that accepts
// signatures made by its owner key, as a real ERC-1271 wallet would.
func fakeWallet(t *testing.T, contract common.Address, owner *KeySigner) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Params []json.RawMessage `json:"params"`
		}
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &req)
		var call struct{ To, Data string }
		json.Unmarshal(req.Params[0], &call)
		data, _ := hex.DecodeString(strings.TrimPrefix(call.Data, "0x"))
		if common.HexToAddress(call.To) != contract || hex.EncodeToString(data[:4]) != "1626ba7e" {
			w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"message":"execution reverted"}}`))
			return
		}
		hash, sig := data[4:36], data[4+32*3:4+32*3+65]
		signer, err := recoverHash(hash, "0x"+hex.EncodeToString(sig))
		res := "0x" + strings.Repeat("00", 32)
		if err == nil && signer == owner.Address() {
			res = "0x1626ba7e" + strings.Repeat("00", 28)
		}
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"` + res + `"}`))
	}))
}

func TestVerifierEOAAndContract(t *testing.T) {
	ctx := context.Background()
	owner, stranger := GenerateKeySigner(), GenerateKeySigner()
	contract := common.HexToAddress("0x00000000000000000000000000000000000c0de1")
	data := []byte("stump-request-v1\nGET\n/v1/boards\n1\nx")
	sig, _ := SignText(owner, data)

	var none *Verifier
	if err := none.VerifyText(ctx, data, sig, owner.Address()); err != nil {
		t.Fatalf("EOA signature rejected without RPC: %v", err)
	}
	if err := none.VerifyText(ctx, data, sig, contract); err == nil {
		t.Fatal("contract wallet accepted without RPC")
	}

	srv := fakeWallet(t, contract, owner)
	defer srv.Close()
	v := &Verifier{RPCURL: srv.URL}
	if err := v.VerifyText(ctx, data, sig, contract); err != nil {
		t.Fatalf("contract wallet signature rejected: %v", err)
	}
	bad, _ := SignText(stranger, data)
	if err := v.VerifyText(ctx, data, bad, contract); err == nil {
		t.Fatal("contract wallet accepted a stranger's signature")
	}
	if err := v.VerifyText(ctx, data, bad, common.HexToAddress("0x00000000000000000000000000000000000000ff")); err == nil {
		t.Fatal("non-contract address accepted a stranger's signature")
	}
}
