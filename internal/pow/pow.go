// Package pow is a small hashcash check for heavy probe tasks.
// It stays off unless IPD_POW=true.
package pow

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

// Issue returns "bits:nonceMaterial" the client must extend with ":solution".
func Issue(bits int) string {
	if bits <= 0 {
		bits = 12
	}
	if bits > 20 {
		bits = 20
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	return strconv.Itoa(bits) + ":" + hex.EncodeToString(b[:])
}

// Verify checks a header value "bits:material:solution".
func Verify(header string) bool {
	parts := strings.Split(header, ":")
	if len(parts) != 3 {
		return false
	}
	bits, err := strconv.Atoi(parts[0])
	if err != nil || bits <= 0 || bits > 24 {
		return false
	}
	sum := sha256.Sum256([]byte(parts[0] + ":" + parts[1] + ":" + parts[2]))
	return leadingZeroBits(sum[:]) >= bits
}

// Solve finds a solution. Tests use a small bit count.
func Solve(challenge string) string {
	parts := strings.Split(challenge, ":")
	if len(parts) != 2 {
		return ""
	}
	bits, err := strconv.Atoi(parts[0])
	if err != nil {
		return ""
	}
	for i := 0; i < 1<<22; i++ {
		sol := strconv.FormatInt(int64(i), 16)
		token := challenge + ":" + sol
		if Verify(token) && leadingMatches(token, bits) {
			return token
		}
	}
	return ""
}

func leadingMatches(token string, bits int) bool {
	sum := sha256.Sum256([]byte(token))
	return leadingZeroBits(sum[:]) >= bits
}

func leadingZeroBits(b []byte) int {
	n := 0
	for _, c := range b {
		if c == 0 {
			n += 8
			continue
		}
		for m := byte(0x80); m > 0; m >>= 1 {
			if c&m != 0 {
				return n
			}
			n++
		}
		break
	}
	return n
}
