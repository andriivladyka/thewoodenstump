package cred

import (
	"os"
	"strconv"
)

// DomainFromEnv reads STUMP_DOMAIN_NAME and STUMP_CHAIN_ID.
func DomainFromEnv() Domain {
	name := os.Getenv("STUMP_DOMAIN_NAME")
	if name == "" {
		name = "The Wooden Stump (lab)"
	}
	chain, err := strconv.ParseInt(os.Getenv("STUMP_CHAIN_ID"), 10, 64)
	if err != nil {
		chain = 84532 // Base Sepolia
	}
	return Domain{Name: name, Version: "1", ChainID: chain}
}
