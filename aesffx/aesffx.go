package aesffx

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
)

const (
	minRadix      = 2
	maxRadix      = 65536
	minLength     = 2
	maxLength     = uint32(1<<32 - 1)
	defaultRounds = 10
)

// FF1Cipher represents the parameters needed for AES-FF1.
type FF1Cipher struct {
	key       []byte
	tweak     []byte
	radix     int
	minLen    int
	maxLen    uint32
	numRounds int
	aesBlock  cipher.Block
}

// NewCipher creates a new cipher capable of encrypting and decrypting messages
// using the AES-FF1 mode for format-preserving encryption.
func NewCipher(radix int, key, tweak []byte) (*FF1Cipher, error) {
	if radix < minRadix || radix > maxRadix {
		return nil, fmt.Errorf("radix must be between 2 and 65536")
	}

	keyLen := len(key)
	if keyLen != 16 && keyLen != 24 && keyLen != 32 {
		return nil, fmt.Errorf("key length must be 16, 24, or 32 bytes")
	}

	if uint32(len(tweak)) > maxLength {
		return nil, fmt.Errorf("tweak length must be less than 2^32")
	}

	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	minLen := minLength
	if radix >= 10 {
		minLen = 6 // FF1 spec recommends minimum 6 for decimal
	}

	return &FF1Cipher{
		key:       key,
		tweak:     tweak,
		radix:     radix,
		minLen:    minLen,
		maxLen:    maxLength,
		numRounds: defaultRounds,
		aesBlock:  aesBlock,
	}, nil
}

// Encrypt encrypts the given plaintext string (in the specified radix).
func (f *FF1Cipher) Encrypt(plaintext string) (string, error) {
	n := len(plaintext)
	if n < f.minLen || uint32(n) > f.maxLen {
		return "", fmt.Errorf("plaintext length must be between %d and %d", f.minLen, f.maxLen)
	}

	// Convert string to numeral array
	X, err := stringToNumerals(plaintext, f.radix)
	if err != nil {
		return "", err
	}

	u := n / 2
	v := n - u

	A := X[:u]
	B := X[u:]

	// Precompute values
	b := int(math.Ceil(math.Ceil(float64(v)*math.Log2(float64(f.radix))) / 8.0))
	d := 4*int(math.Ceil(float64(b)/4.0)) + 4

	radixBig := big.NewInt(int64(f.radix))

	// Fixed P block
	P := f.calculateP(n, u, b, d)

	for i := 0; i < f.numRounds; i++ {
		// Determine m based on round
		var m int
		var modulus *big.Int
		if i%2 == 0 {
			m = u
			modulus = new(big.Int).Exp(radixBig, big.NewInt(int64(m)), nil)
		} else {
			m = v
			modulus = new(big.Int).Exp(radixBig, big.NewInt(int64(m)), nil)
		}

		// Q varies by round and B
		Q := f.calculateQ(B, i, b)

		// R = PRF(P || Q)
		R, err := f.prf(append(P, Q...))
		if err != nil {
			return "", err
		}

		// S = first d bytes of R || CIPH(R⊕[1]) || CIPH(R⊕[2]) || ...
		S := f.extendPRF(R, d)

		// Convert S to big integer
		y := new(big.Int).SetBytes(S)

		// c = (NUM(A) + y) mod radix^m
		numA := numeralsToNum(A, f.radix)
		c := new(big.Int).Add(numA, y)
		c.Mod(c, modulus)

		// Convert c back to numeral string of length m
		C := numToNumerals(c, f.radix, m)

		// Swap for next round
		A = B
		B = C
	}

	// Concatenate A and B
	result := append(A, B...)
	return numeralsToString(result, f.radix), nil
}

// Decrypt decrypts the given ciphertext string.
func (f *FF1Cipher) Decrypt(ciphertext string) (string, error) {
	n := len(ciphertext)
	if n < f.minLen || uint32(n) > f.maxLen {
		return "", fmt.Errorf("ciphertext length must be between %d and %d", f.minLen, f.maxLen)
	}

	// Convert string to numeral array
	X, err := stringToNumerals(ciphertext, f.radix)
	if err != nil {
		return "", err
	}

	u := n / 2
	v := n - u

	A := X[:u]
	B := X[u:]

	// Precompute values
	b := int(math.Ceil(math.Ceil(float64(v)*math.Log2(float64(f.radix))) / 8.0))
	d := 4*int(math.Ceil(float64(b)/4.0)) + 4

	radixBig := big.NewInt(int64(f.radix))

	// Fixed P block
	P := f.calculateP(n, u, b, d)

	for i := f.numRounds - 1; i >= 0; i-- {
		// Determine m based on round
		var m int
		var modulus *big.Int
		if i%2 == 0 {
			m = u
			modulus = new(big.Int).Exp(radixBig, big.NewInt(int64(m)), nil)
		} else {
			m = v
			modulus = new(big.Int).Exp(radixBig, big.NewInt(int64(m)), nil)
		}

		// Q varies by round and A
		Q := f.calculateQ(A, i, b)

		// R = PRF(P || Q)
		R, err := f.prf(append(P, Q...))
		if err != nil {
			return "", err
		}

		// S = first d bytes of R || CIPH(R⊕[1]) || CIPH(R⊕[2]) || ...
		S := f.extendPRF(R, d)

		// Convert S to big integer
		y := new(big.Int).SetBytes(S)

		// c = (NUM(B) - y) mod radix^m
		numB := numeralsToNum(B, f.radix)
		c := new(big.Int).Sub(numB, y)
		c.Mod(c, modulus)

		// Convert c back to numeral string of length m
		C := numToNumerals(c, f.radix, m)

		// Swap for next round
		B = A
		A = C
	}

	// Concatenate A and B
	result := append(A, B...)
	return numeralsToString(result, f.radix), nil
}

// calculateP creates the P block according to FF1 spec
func (f *FF1Cipher) calculateP(n, u, b, d int) []byte {
	// P = [1]^1 || [2]^1 || [1]^1 || [radix]^3 || [10]^1 || [u mod 256]^1 || [n]^4 || [t]^4
	P := make([]byte, 16)
	P[0] = 1 // version
	P[1] = 2 // method
	P[2] = 1 // addition
	// radix (3 bytes, big-endian)
	P[3] = byte((f.radix >> 16) & 0xff)
	P[4] = byte((f.radix >> 8) & 0xff)
	P[5] = byte(f.radix & 0xff)
	P[6] = 10            // num rounds
	P[7] = byte(u % 256) // split (u mod 256)
	binary.BigEndian.PutUint32(P[8:12], uint32(n))
	binary.BigEndian.PutUint32(P[12:16], uint32(len(f.tweak)))

	return P
}

// calculateQ creates the Q block according to FF1 spec
func (f *FF1Cipher) calculateQ(B []byte, round int, b int) []byte {
	// Q = T || [0]^((-t-b-1) mod 16) || [i]^1 || [NUM_radix(B)]^b
	t := len(f.tweak)

	// Calculate padding needed
	padLen := ((-t - b - 1) % 16)
	if padLen < 0 {
		padLen += 16
	}

	Q := make([]byte, 0, t+padLen+1+b)
	Q = append(Q, f.tweak...)
	Q = append(Q, make([]byte, padLen)...)
	Q = append(Q, byte(round))

	// Convert B to a number and encode in b bytes
	numB := numeralsToNum(B, f.radix)
	bBytes := numB.Bytes()

	// Pad to b bytes
	if len(bBytes) < b {
		padding := make([]byte, b-len(bBytes))
		bBytes = append(padding, bBytes...)
	} else if len(bBytes) > b {
		bBytes = bBytes[len(bBytes)-b:]
	}

	Q = append(Q, bBytes...)
	return Q
}

// prf implements the PRF function using AES-CBC-MAC
func (f *FF1Cipher) prf(data []byte) ([]byte, error) {
	// Pad to multiple of 16 bytes
	padLen := (16 - (len(data) % 16)) % 16
	if padLen > 0 {
		padding := make([]byte, padLen)
		data = append(data, padding...)
	}

	// CBC-MAC with zero IV
	mac := make([]byte, 16)

	// Process all blocks
	for i := 0; i < len(data); i += 16 {
		block := data[i : i+16]
		// XOR with previous output
		for j := 0; j < 16; j++ {
			mac[j] ^= block[j]
		}
		// Encrypt
		f.aesBlock.Encrypt(mac, mac)
	}

	return mac, nil
}

// extendPRF extends the PRF output R to d bytes
// S = R || CIPH(R⊕[1]) || CIPH(R⊕[2]) || ... || CIPH(R⊕[⌈d/16⌉-1])
func (f *FF1Cipher) extendPRF(R []byte, d int) []byte {
	S := make([]byte, 0, d)
	S = append(S, R...)

	// How many additional blocks do we need?
	numBlocks := int(math.Ceil(float64(d) / 16.0))

	for i := 1; i < numBlocks; i++ {
		// Create [i]^16 - 16 byte representation of i
		iBytes := make([]byte, 16)
		binary.BigEndian.PutUint32(iBytes[12:16], uint32(i))

		// XOR R with [i]^16
		xored := make([]byte, 16)
		for j := 0; j < 16; j++ {
			xored[j] = R[j] ^ iBytes[j]
		}

		// Encrypt
		block := make([]byte, 16)
		f.aesBlock.Encrypt(block, xored)
		S = append(S, block...)
	}

	// Return first d bytes
	return S[:d]
}

// Helper functions for numeral conversion

func stringToNumerals(s string, radix int) ([]byte, error) {
	numerals := make([]byte, len(s))
	for i, c := range s {
		var val int
		if c >= '0' && c <= '9' {
			val = int(c - '0')
		} else if c >= 'a' && c <= 'z' {
			val = int(c-'a') + 10
		} else if c >= 'A' && c <= 'Z' {
			val = int(c-'A') + 10
		} else {
			return nil, fmt.Errorf("invalid character '%c' for radix %d", c, radix)
		}

		if val >= radix {
			return nil, fmt.Errorf("character '%c' out of range for radix %d", c, radix)
		}
		numerals[i] = byte(val)
	}
	return numerals, nil
}

func numeralsToString(numerals []byte, radix int) string {
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
	result := make([]byte, len(numerals))
	for i, n := range numerals {
		if int(n) < len(alphabet) {
			result[i] = alphabet[n]
		} else {
			result[i] = '?'
		}
	}
	return string(result)
}

func numeralsToNum(numerals []byte, radix int) *big.Int {
	result := big.NewInt(0)
	radixBig := big.NewInt(int64(radix))

	for _, n := range numerals {
		result.Mul(result, radixBig)
		result.Add(result, big.NewInt(int64(n)))
	}

	return result
}

func numToNumerals(num *big.Int, radix int, length int) []byte {
	result := make([]byte, length)
	radixBig := big.NewInt(int64(radix))
	tmp := new(big.Int).Set(num)
	mod := new(big.Int)

	for i := length - 1; i >= 0; i-- {
		tmp.DivMod(tmp, radixBig, mod)
		result[i] = byte(mod.Int64())
	}

	return result
}
