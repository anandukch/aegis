package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

func Encrypt(plaintext string, key []byte) (ciphertext, nonce string, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", fmt.Errorf("create gcm: %w", err)
	}

	nonceBytes := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonceBytes); err != nil {
		return "", "", fmt.Errorf("generate nonce: %w", err)
	}

	encrypted := gcm.Seal(nil, nonceBytes, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(encrypted),
		base64.StdEncoding.EncodeToString(nonceBytes),
		nil
}

func Decrypt(ciphertext, nonce string, key []byte) (string, error) {
	ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("decode ciphertext: %w", err)
	}

	nonceBytes, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		return "", fmt.Errorf("decode nonce: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create gcm: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonceBytes, ciphertextBytes, nil)
	if err != nil {
		return "", errors.New("decryption failed: authentication tag mismatch")
	}

	return string(plaintext), nil
}

func MaskValue(value, fieldType string) string {
	switch fieldType {
	case "email":
		return maskEmail(value)
	case "phone":
		return maskPhone(value)
	case "card_number":
		return maskCard(value)
	case "aadhaar":
		return maskAadhaar(value)
	case "pan":
		return maskPAN(value)
	case "name":
		return maskName(value)
	case "dob":
		return maskDOB(value)
	default:
		return "***"
	}
}

func maskEmail(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 || len(parts[0]) == 0 {
		return "***"
	}
	return string(parts[0][0]) + "***@" + parts[1]
}

func maskPhone(phone string) string {
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, phone)
	if len(digits) < 4 {
		return "******"
	}
	return "******" + digits[len(digits)-4:]
}

func maskCard(card string) string {
	digits := strings.ReplaceAll(strings.ReplaceAll(card, " ", ""), "-", "")
	if len(digits) < 4 {
		return "****-****-****-****"
	}
	last4 := digits[len(digits)-4:]
	return "****-****-****-" + last4
}

func maskAadhaar(aadhaar string) string {
	digits := strings.ReplaceAll(aadhaar, "-", "")
	if len(digits) < 4 {
		return "XXXX-XXXX-XXXX"
	}
	return "XXXX-XXXX-" + digits[len(digits)-4:]
}

func maskPAN(pan string) string {
	normalized := NormalizePAN(pan)
	if !IsPAN(normalized) {
		return "*****"
	}
	return normalized[:5] + "****" + string(normalized[9])
}

func maskName(name string) string {
	words := strings.Fields(name)
	masked := make([]string, len(words))
	for i, w := range words {
		if len(w) == 0 {
			continue
		}
		masked[i] = string(w[0]) + "***"
	}
	return strings.Join(masked, " ")
}

func maskDOB(dob string) string {
	parts := strings.Split(dob, "-")
	if len(parts) == 3 {
		return "****-**-" + parts[2]
	}
	return "****-**-**"
}
