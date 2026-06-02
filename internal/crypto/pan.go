package crypto

import (
	"errors"
	"regexp"
	"strings"
)

var (
	ErrInvalidPAN = errors.New("invalid PAN format: expected ABCDE1234F")

	panRegex = regexp.MustCompile(`^[A-Z]{5}[0-9]{4}[A-Z]$`)
)

func NormalizePAN(pan string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(pan), " ", ""))
}

func IsPAN(value string) bool {
	return panRegex.MatchString(NormalizePAN(value))
}

// DetectFieldType returns "pan" when value matches PAN format, otherwise "".
func DetectFieldType(value string) string {
	if IsPAN(value) {
		return "pan"
	}
	return ""
}

func ValidatePAN(value string) (string, error) {
	normalized := NormalizePAN(value)
	if !IsPAN(normalized) {
		return "", ErrInvalidPAN
	}
	return normalized, nil
}
