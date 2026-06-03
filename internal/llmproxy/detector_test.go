package llmproxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDetectPII_EmailAndCard(t *testing.T) {
	prompt := "email john@example.com about card 4111111111114242"
	matches := DetectPII(prompt)
	assert.Len(t, matches, 2)

	types := map[string]bool{}
	for _, m := range matches {
		types[m.FieldType] = true
	}
	assert.True(t, types["email"])
	assert.True(t, types["card_number"])
}

func TestDetectPII_PhoneAndPAN(t *testing.T) {
	prompt := "call 9876543210 with PAN ABCDE1234F"
	matches := DetectPII(prompt)
	assert.Len(t, matches, 2)
}

func TestReplaceMatches(t *testing.T) {
	prompt := "email john@example.com"
	matches := DetectPII(prompt)
	replaced := replaceMatches(prompt, matches, map[string]string{
		"john@example.com": "tok_abc",
	})
	assert.Equal(t, "email tok_abc", replaced)
}

func TestDetectPII_NoOverlapDuplicatePhone(t *testing.T) {
	prompt := "numbers 9876543210 and 9876543210"
	matches := DetectPII(prompt)
	assert.Len(t, matches, 2)
}
