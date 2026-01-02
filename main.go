package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"trial_ffx/aesffx"
)

func main() {
	// Example 1: Encrypting numeric strings (radix 10)
	fmt.Println("=== Example 1: Numeric Encryption (Radix 10) ===")
	numericExample()
	fmt.Println()

	// Example 2: Encrypting hexadecimal strings (radix 16)
	fmt.Println("=== Example 2: Hexadecimal Encryption (Radix 16) ===")
	hexExample()
	fmt.Println()

	// Example 3: Encrypting alphanumeric (radix 36)
	fmt.Println("=== Example 3: Alphanumeric Encryption (Radix 36) ===")
	alphanumericExample()
	fmt.Println()

	// Example 4: Credit card number encryption
	fmt.Println("=== Example 4: Credit Card Encryption ===")
	creditCardExample()
	fmt.Println()

	// Example 5: NIST test vectors
	fmt.Println("=== Example 5: NIST FF1 Test Vectors ===")
	nistTestVectors()
}

func numericExample() {
	// 128-bit AES key (16 bytes)
	key := []byte("examplekey123456") // Must be exactly 16 bytes

	// Tweak for additional variability
	tweak := []byte("mytweak")

	// Create cipher with radix 10 (for decimal numbers)
	cipher, err := aesffx.NewCipher(10, key, tweak)
	if err != nil {
		log.Fatal("Error creating cipher:", err)
	}

	// Plaintext (must be at least 6 characters for radix >= 10 in FF1)
	plaintext := "1234567890"
	fmt.Printf("Plaintext:  %s\n", plaintext)

	// Encrypt
	ciphertext, err := cipher.Encrypt(plaintext)
	if err != nil {
		log.Fatal("Error encrypting:", err)
	}
	fmt.Printf("Ciphertext: %s\n", ciphertext)

	// Decrypt
	decrypted, err := cipher.Decrypt(ciphertext)
	if err != nil {
		log.Fatal("Error decrypting:", err)
	}
	fmt.Printf("Decrypted:  %s\n", decrypted)

	// Verify
	if plaintext == decrypted {
		fmt.Println("✓ Encryption/Decryption successful!")
	} else {
		fmt.Println("✗ Decryption failed!")
	}
}

func hexExample() {
	key := []byte("mysecretkey12345")
	tweak := []byte("hextweak")

	// Radix 16 for hexadecimal (0-9, a-f)
	cipher, err := aesffx.NewCipher(16, key, tweak)
	if err != nil {
		log.Fatal("Error creating cipher:", err)
	}

	plaintext := "deadbeef1234"
	fmt.Printf("Plaintext:  %s\n", plaintext)

	ciphertext, err := cipher.Encrypt(plaintext)
	if err != nil {
		log.Fatal("Error encrypting:", err)
	}
	fmt.Printf("Ciphertext: %s\n", ciphertext)

	decrypted, err := cipher.Decrypt(ciphertext)
	if err != nil {
		log.Fatal("Error decrypting:", err)
	}
	fmt.Printf("Decrypted:  %s\n", decrypted)

	if plaintext == decrypted {
		fmt.Println("✓ Encryption/Decryption successful!")
	}
}

func alphanumericExample() {
	key := []byte("alphanumkey98765")
	tweak := []byte("alphatweak")

	// Radix 36 for alphanumeric (0-9, a-z)
	cipher, err := aesffx.NewCipher(36, key, tweak)
	if err != nil {
		log.Fatal("Error creating cipher:", err)
	}

	// Must be lowercase for radix 36
	plaintext := "hello123world"
	fmt.Printf("Plaintext:  %s\n", plaintext)

	ciphertext, err := cipher.Encrypt(plaintext)
	if err != nil {
		log.Fatal("Error encrypting:", err)
	}
	fmt.Printf("Ciphertext: %s\n", ciphertext)

	decrypted, err := cipher.Decrypt(ciphertext)
	if err != nil {
		log.Fatal("Error decrypting:", err)
	}
	fmt.Printf("Decrypted:  %s\n", decrypted)

	if plaintext == decrypted {
		fmt.Println("✓ Encryption/Decryption successful!")
	}
}

// Credit card number encryption
func creditCardExample() {
	key := []byte("ccencryptionkey1")
	tweak := []byte("cc")

	cipher, err := aesffx.NewCipher(10, key, tweak)
	if err != nil {
		log.Fatal("Error creating cipher:", err)
	}

	// Example credit card number (16 digits)
	ccNumber := "4532123456789012"
	fmt.Printf("Original CC:  %s\n", ccNumber)

	encryptedCC, err := cipher.Encrypt(ccNumber)
	if err != nil {
		log.Fatal("Error encrypting:", err)
	}
	fmt.Printf("Encrypted CC: %s\n", encryptedCC)

	decryptedCC, err := cipher.Decrypt(encryptedCC)
	if err != nil {
		log.Fatal("Error decrypting:", err)
	}
	fmt.Printf("Decrypted CC: %s\n", decryptedCC)

	if ccNumber == decryptedCC {
		fmt.Println("✓ Format-preserving encryption successful!")
		fmt.Println("  (Still 16 digits, but encrypted)")
	}
}

// NIST FF1 test vectors from NIST SP 800-38G
func nistTestVectors() {
	// Sample 1: AES-128, radix 10
	fmt.Println("NIST Sample #1 (AES-128, Radix 10):")
	key1, _ := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	tweak1 := []byte("")
	plaintext1 := "0123456789"
	expectedCT1 := "2433477484" // From NIST spec

	cipher1, err := aesffx.NewCipher(10, key1, tweak1)
	if err != nil {
		log.Fatal("Error creating cipher:", err)
	}

	ct1, err := cipher1.Encrypt(plaintext1)
	if err != nil {
		log.Fatal("Error encrypting:", err)
	}

	fmt.Printf("  Plaintext:  %s\n", plaintext1)
	fmt.Printf("  Ciphertext: %s\n", ct1)
	fmt.Printf("  Expected:   %s\n", expectedCT1)

	if ct1 == expectedCT1 {
		fmt.Println("  ✓ Matches NIST test vector!")
	} else {
		fmt.Println("  ✗ Does not match NIST test vector")
	}

	// Verify decryption
	pt1, _ := cipher1.Decrypt(ct1)
	if pt1 == plaintext1 {
		fmt.Println("  ✓ Decryption successful!")
	}
	fmt.Println()

	// Sample 2: AES-128, radix 10 with tweak
	fmt.Println("NIST Sample #2 (AES-128, Radix 10, with tweak):")
	key2, _ := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	tweak2, _ := hex.DecodeString("39383736353433323130")
	plaintext2 := "0123456789"
	expectedCT2 := "6124200773" // From NIST spec

	cipher2, err := aesffx.NewCipher(10, key2, tweak2)
	if err != nil {
		log.Fatal("Error creating cipher:", err)
	}

	ct2, err := cipher2.Encrypt(plaintext2)
	if err != nil {
		log.Fatal("Error encrypting:", err)
	}

	fmt.Printf("  Plaintext:  %s\n", plaintext2)
	fmt.Printf("  Ciphertext: %s\n", ct2)
	fmt.Printf("  Expected:   %s\n", expectedCT2)

	if ct2 == expectedCT2 {
		fmt.Println("  ✓ Matches NIST test vector!")
	} else {
		fmt.Println("  ✗ Does not match NIST test vector")
	}

	pt2, _ := cipher2.Decrypt(ct2)
	if pt2 == plaintext2 {
		fmt.Println("  ✓ Decryption successful!")
	}
}

// Helper function to generate a hex key from a string
func generateKeyFromString(s string) []byte {
	if len(s) >= 16 {
		return []byte(s[:16])
	}
	// Pad with zeros if too short
	padded := s + string(make([]byte, 16-len(s)))
	return []byte(padded)
}

// Helper function to create a key from hex string
func keyFromHex(hexStr string) ([]byte, error) {
	key, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("key must be 16, 24, or 32 bytes")
	}
	return key, nil
}

/*
Usage:
% go mod init trial_ffx
% go mod tidy
% go run main.go

# Run all tests in the current directory
go test

# Run all tests in the current directory and subdirectories
go test ./...

# Run tests with verbose output (shows each test function)
go test -v

# Run tests in a specific package
go test ./aesff1

# Run a specific test function
go test -run TestFunctionName

# Run tests with coverage report
go test -cover

# Generate detailed coverage report
go test -coverprofile=coverage.out
go tool cover -html=coverage.out

References:
- NIST SP 800-38G Rev. 1: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf
- FF1 Specification: https://csrc.nist.gov/projects/block-cipher-techniques/bcm/modes-development
*/

/*
% go mod init trial_ffx
% go mod tidy
% go run main.go

# Run all tests in the current directory
go test

# Run all tests in the current directory and subdirectories
go test ./...

# Run tests with verbose output (shows each test function)
go test -v

# Run tests in a specific package
go test ./aesffx

# Run a specific test function
go test -run TestFunctionName

# Run tests with coverage report
go test -cover

# Generate detailed coverage report
go test -coverprofile=coverage.out
go tool cover -html=coverage.out

Ref: https://csrc.nist.gov/csrc/media/projects/block-cipher-techniques/documents/bcm/proposed-modes/ffx/ffx-spec.pdf
*/
