package cred

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Signer is the port the issuer signs through: a software key in lab,
// a hardware wallet or remote signer in prod.
type Signer interface {
	Address() common.Address
	// SignHash returns a 65-byte signature with V = 27 or 28.
	SignHash(hash []byte) ([]byte, error)
}

// KeySigner signs with a secp256k1 private key held in memory.
type KeySigner struct{ key *ecdsa.PrivateKey }

// NewKeySigner parses a hex private key (with or without 0x).
func NewKeySigner(hexKey string) (*KeySigner, error) {
	k, err := crypto.HexToECDSA(strings.TrimPrefix(strings.TrimSpace(hexKey), "0x"))
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}
	return &KeySigner{key: k}, nil
}

// GenerateKeySigner makes a new random key, for tests and tools.
func GenerateKeySigner() *KeySigner {
	k, err := crypto.GenerateKey()
	if err != nil {
		panic(err)
	}
	return &KeySigner{key: k}
}

func (s *KeySigner) Address() common.Address { return crypto.PubkeyToAddress(s.key.PublicKey) }

func (s *KeySigner) SignHash(hash []byte) ([]byte, error) {
	sig, err := crypto.Sign(hash, s.key)
	if err != nil {
		return nil, err
	}
	sig[64] += 27
	return sig, nil
}

// SignText signs data the way personal_sign (EIP-191) does and returns 0x hex.
func SignText(s Signer, data []byte) (string, error) {
	sig, err := s.SignHash(accounts.TextHash(data))
	if err != nil {
		return "", err
	}
	return "0x" + hex.EncodeToString(sig), nil
}

// RecoverText returns the address that personal_signed data.
// Smart-contract wallets (ERC-1271) are not supported yet.
func RecoverText(data []byte, sigHex string) (common.Address, error) {
	return recoverHash(accounts.TextHash(data), sigHex)
}

func recoverHash(hash []byte, sigHex string) (common.Address, error) {
	sig, err := hex.DecodeString(strings.TrimPrefix(sigHex, "0x"))
	if err != nil || len(sig) != 65 {
		return common.Address{}, errors.New("signature must be 65 bytes of hex")
	}
	if sig[64] >= 27 {
		sig[64] -= 27
	}
	pub, err := crypto.SigToPub(hash, sig)
	if err != nil {
		return common.Address{}, fmt.Errorf("bad signature: %w", err)
	}
	return crypto.PubkeyToAddress(*pub), nil
}

// SameAddress compares two hex addresses case-insensitively.
func SameAddress(a, b string) bool {
	return common.IsHexAddress(a) && common.IsHexAddress(b) &&
		common.HexToAddress(a) == common.HexToAddress(b)
}
