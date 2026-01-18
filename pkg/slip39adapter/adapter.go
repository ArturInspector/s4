package slip39adapter

import (
	"encoding/base64"
	"fmt"

	slip39 "github.com/gavincarr/go-slip39"
)

// ShareToSlip39Mnemonic wraps a single s4 share string into a 1-of-1 SLIP-39
// mnemonic. The share is base64-encoded to satisfy SLIP-39 length constraints.
func ShareToSlip39Mnemonic(share string) (string, error) {
	if share == "" {
		return "", fmt.Errorf("share must not be empty")
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(share))
	mnemonics, err := slip39.GenerateMnemonics(
		1,
		[]slip39.MemberGroupParameters{
			{MemberThreshold: 1, MemberCount: 1},
		},
		[]byte(encoded),
	)
	if err != nil {
		return "", fmt.Errorf("generate slip39 mnemonic: %w", err)
	}
	return mnemonics[0][0], nil
}

// SharesToSlip39Mnemonics converts each s4 share into a separate 1-of-1 SLIP-39
// mnemonic string.
func SharesToSlip39Mnemonics(shares []string) ([]string, error) {
	out := make([]string, len(shares))
	for i, share := range shares {
		mn, err := ShareToSlip39Mnemonic(share)
		if err != nil {
			return nil, fmt.Errorf("share %d: %w", i+1, err)
		}
		out[i] = mn
	}
	return out, nil
}

// Slip39MnemonicToShare unwraps a 1-of-1 SLIP-39 mnemonic produced by this
// adapter back into the original s4 share string.
func Slip39MnemonicToShare(mnemonic string) (string, error) {
	if mnemonic == "" {
		return "", fmt.Errorf("mnemonic must not be empty")
	}
	secret, err := slip39.CombineMnemonics([]string{mnemonic})
	if err != nil {
		return "", fmt.Errorf("combine slip39 mnemonics: %w", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(string(secret))
	if err != nil {
		return "", fmt.Errorf("decode slip39 payload: %w", err)
	}
	return string(decoded), nil
}

// Slip39MnemonicsToShares converts multiple SLIP-39 mnemonics (created by this
// adapter) back to s4 share strings.
func Slip39MnemonicsToShares(mnemonics []string) ([]string, error) {
	out := make([]string, len(mnemonics))
	for i, mn := range mnemonics {
		share, err := Slip39MnemonicToShare(mn)
		if err != nil {
			return nil, fmt.Errorf("mnemonic %d: %w", i+1, err)
		}
		out[i] = share
	}
	return out, nil
}
