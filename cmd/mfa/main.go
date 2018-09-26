package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

func main() {
	if err := print(os.Stderr, os.Args[1:]...); err != nil {
		fmt.Fprintf(os.Stderr, "mfa: %v\n", err)
		os.Exit(1)
	}
}

// service is used to identify this service when interacting with the keychain.
const service = "mfa"

func print(w io.Writer, accounts ...string) error {
	for _, account := range accounts {
		s, err := secret(service, account)
		if err != nil {
			return err
		}
		n, err := totp(s, now())
		if err != nil {
			return err
		}
		fmt.Printf("%06d\n", n)
	}
	return nil
}

// now returns a TOTP challenge for now.
func now() int64 { return int64(time.Now().Unix() / 30) }

// totp computes the response code for a challenge using the secret.
func totp(secret string, c int64) (int, error) {
	k, err := base32.StdEncoding.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return -1, err
	}

	hash := hmac.New(sha1.New, k)
	if err := binary.Write(hash, binary.BigEndian, c); err != nil {
		return -1, err
	}

	p := hash.Sum(nil)
	i := p[19] & 0x0f
	n := binary.BigEndian.Uint32(p[i : i+4])
	n &= 0x7fffffff

	return int(n % 1000000), nil
}
