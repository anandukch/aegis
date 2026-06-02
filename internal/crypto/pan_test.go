package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsPAN_Valid(t *testing.T) {
	cases := []string{
		"ABCDE1234F",
		"abcde1234f",
		"ABCDE 1234F",
		" abcde1234f ",
	}
	for _, c := range cases {
		assert.True(t, IsPAN(c), "expected valid PAN: %q", c)
	}
}

func TestIsPAN_Invalid(t *testing.T) {
	cases := []string{
		"",
		"ABCDE1234",
		"ABCD1234F",
		"ABCDE12345",
		"1234567890",
		"ABCDE1234FF",
	}
	for _, c := range cases {
		assert.False(t, IsPAN(c), "expected invalid PAN: %q", c)
	}
}

func TestValidatePAN_Normalizes(t *testing.T) {
	got, err := ValidatePAN("abcde1234f")
	require.NoError(t, err)
	assert.Equal(t, "ABCDE1234F", got)
}

func TestValidatePAN_Invalid(t *testing.T) {
	_, err := ValidatePAN("not-a-pan")
	require.ErrorIs(t, err, ErrInvalidPAN)
}

func TestDetectFieldType(t *testing.T) {
	assert.Equal(t, "pan", DetectFieldType("ABCDE1234F"))
	assert.Equal(t, "", DetectFieldType("john@example.com"))
}

func TestMaskPAN(t *testing.T) {
	result := MaskValue("ABCDE1234F", "pan")
	assert.Equal(t, "ABCDE****F", result)
}

func TestMaskPAN_Invalid(t *testing.T) {
	result := MaskValue("bad", "pan")
	assert.Equal(t, "*****", result)
}
