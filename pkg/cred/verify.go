package cred

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
)

// Verifier checks that a wallet signed some bytes with personal_sign.
// Plain (EOA) wallets are checked by recovering the key. For smart-contract
// wallets it asks the contract through ERC-1271 isValidSignature, which
// needs a chain RPC; without one, contract wallets are refused.
type Verifier struct {
	RPCURL string
	HTTP   *http.Client
}

// ERC-1271: bytes4(keccak256("isValidSignature(bytes32,bytes)")).
var erc1271Magic = []byte{0x16, 0x26, 0xba, 0x7e}

// ErrNoRPC means the signature may be from a contract wallet, but there is
// no chain RPC to ask.
var ErrNoRPC = errors.New("signature does not match the wallet; contract wallets need a chain RPC, which is not configured here")

// VerifyText returns nil if wallet signed data.
func (v *Verifier) VerifyText(ctx context.Context, data []byte, sigHex string, wallet common.Address) error {
	if signer, err := RecoverText(data, sigHex); err == nil && signer == wallet {
		return nil
	}
	if v == nil || v.RPCURL == "" {
		return ErrNoRPC
	}
	sig, err := hex.DecodeString(strings.TrimPrefix(sigHex, "0x"))
	if err != nil {
		return errors.New("signature is not hex")
	}
	ok, err := v.isValidSignature(ctx, wallet, accounts.TextHash(data), sig)
	if err != nil {
		return fmt.Errorf("contract wallet check failed: %w", err)
	}
	if !ok {
		return errors.New("contract wallet rejected the signature")
	}
	return nil
}

// isValidSignature does eth_call isValidSignature(bytes32 hash, bytes sig).
func (v *Verifier) isValidSignature(ctx context.Context, wallet common.Address, hash, sig []byte) (bool, error) {
	// ABI: selector, hash, offset of bytes (0x40), length, data padded to 32.
	var call bytes.Buffer
	call.Write(erc1271Magic)
	call.Write(hash)
	call.Write(common.LeftPadBytes([]byte{0x40}, 32))
	call.Write(common.LeftPadBytes(big(len(sig)), 32))
	call.Write(sig)
	if pad := len(sig) % 32; pad != 0 {
		call.Write(make([]byte, 32-pad))
	}
	req, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "eth_call",
		"params": []any{map[string]string{"to": wallet.Hex(), "data": "0x" + hex.EncodeToString(call.Bytes())}, "latest"}})
	hc := v.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second}
	}
	hreq, _ := http.NewRequestWithContext(ctx, "POST", v.RPCURL, bytes.NewReader(req))
	hreq.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(hreq)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	var out struct {
		Result string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, err
	}
	if out.Error != nil {
		return false, nil // reverted or not a contract: not valid
	}
	res, err := hex.DecodeString(strings.TrimPrefix(out.Result, "0x"))
	if err != nil || len(res) < 4 {
		return false, nil
	}
	return bytes.Equal(res[:4], erc1271Magic), nil
}

func big(n int) []byte {
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n)}, b...)
		n >>= 8
	}
	return b
}
