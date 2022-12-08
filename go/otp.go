// Package otp contains the implementation of the One Time Password (OTP) algorithm.
// It's done by an article from https://zserge.com/posts/one-time-passwords/
package otp

import (
	"bytes"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math/rand"
	"time"
)

// KeySize is the size of the secret key in bytes.
const KeySize = 64

// CryptoRandSource represents a source of uniformly-distributed random int64 values in the range [0, 1<<63).
type CryptoRandSource struct{}

// Int63 returns a non-negative random 63-bit integer as an int64 from CryptoRandSource.
func (CryptoRandSource) Int63() int64 {
	var b [8]byte
	_, err := crand.Read(b[:])
	if err != nil {
		panic(err) // fail - can't continue
	}
	return int64(binary.LittleEndian.Uint64(b[:]) & (1<<63 - 1))
}

// Seed is fake CryptoRandSource Seed implementation for Source interface.
func (CryptoRandSource) Seed(int64) {}

// Secret generates a new secret key.
func Secret(size int) (string, error) {
	var r rand.Source = CryptoRandSource{}
	if size == 0 {
		size = KeySize
	}

	b := make([]byte, size)

	_, err := rand.New(r).Read(b)
	if err != nil {
		return "", err
	}
	return base32.StdEncoding.EncodeToString(b), nil
}

// Code generates a new code for the given secret key.
func Code(secret string, counter int64) (string, error) {
	if counter < 0 {
		counter = time.Now().Unix() / 30
	}

	// decode Base-32 secret key
	key := make([]byte, KeySize)
	if _, err := base32.StdEncoding.Decode(key, bytes.ToUpper([]byte(secret))); err != nil {
		return "", err
	}

	// write counter as 8 bytes, big-endian
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(counter))

	hash := hmac.New(sha1.New, key)
	hash.Write(b)
	b = hash.Sum(nil)

	// find offset, lower 4 bits of the last byte
	offset := b[len(b)-1] & 0xF
	// read 4 bytes from offset as 32-bit integer
	n := binary.BigEndian.Uint32(b[offset : offset+4])

	// covert it to decimal and return last 6 digits
	s := fmt.Sprintf("%06d", int(n&0x7FFFFFFF))
	return s[len(s)-6:], nil
}
