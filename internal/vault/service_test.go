package vault

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/anandudevops/aegis/internal/crypto"
	"github.com/anandudevops/aegis/internal/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func init() {
	os.Setenv("VAULT_MASTER_KEY", "12345678901234567890123456789012")
}

var testKey = []byte("12345678901234567890123456789012")

type mockRepo struct {
	mock.Mock
}

func (m *mockRepo) Create(record *models.VaultRecord) error {
	return m.Called(record).Error(0)
}

func (m *mockRepo) FindByToken(token string) (*models.VaultRecord, error) {
	args := m.Called(token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.VaultRecord), args.Error(1)
}

func (m *mockRepo) SoftDelete(token string) error {
	return m.Called(token).Error(0)
}

func encryptedRecord(t *testing.T, plaintext, fieldType string) *models.VaultRecord {
	t.Helper()
	enc, nonce, err := crypto.Encrypt(plaintext, testKey)
	require.NoError(t, err)
	return &models.VaultRecord{
		ID:        uuid.New(),
		Token:     "tok_" + uuid.New().String(),
		FieldType: fieldType,
		EncValue:  enc,
		Nonce:     nonce,
	}
}

func TestTokenize_StoresRecord(t *testing.T) {
	m := &mockRepo{}
	m.On("Create", mock.AnythingOfType("*models.VaultRecord")).Return(nil)

	svc := NewService(m)
	record, err := svc.Tokenize("email", "john@example.com", uuid.New().String())

	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(record.Token, "tok_"))
	assert.Equal(t, "email", record.FieldType)
	assert.NotEmpty(t, record.EncValue)
	m.AssertExpectations(t)
}

func TestTokenize_RepoError(t *testing.T) {
	m := &mockRepo{}
	m.On("Create", mock.Anything).Return(errors.New("db error"))

	svc := NewService(m)
	_, err := svc.Tokenize("email", "john@example.com", "")
	assert.Error(t, err)
}

func TestTokenize_InvalidPAN(t *testing.T) {
	svc := NewService(&mockRepo{})
	_, err := svc.Tokenize("pan", "invalid-pan", "")
	assert.ErrorIs(t, err, crypto.ErrInvalidPAN)
}

func TestTokenize_NormalizesPAN(t *testing.T) {
	m := &mockRepo{}
	m.On("Create", mock.MatchedBy(func(r *models.VaultRecord) bool {
		return r.FieldType == "pan" && r.EncValue != ""
	})).Return(nil).Run(func(args mock.Arguments) {
		record := args.Get(0).(*models.VaultRecord)
		dec, err := crypto.Decrypt(record.EncValue, record.Nonce, testKey)
		require.NoError(t, err)
		assert.Equal(t, "ABCDE1234F", dec)
	})

	svc := NewService(m)
	record, err := svc.Tokenize("pan", "abcde1234f", uuid.New().String())
	require.NoError(t, err)
	assert.Equal(t, "pan", record.FieldType)
	m.AssertExpectations(t)
}

func TestDetokenize_AdminFull(t *testing.T) {
	rec := encryptedRecord(t, "john@example.com", "email")
	m := &mockRepo{}
	m.On("FindByToken", rec.Token).Return(rec, nil)

	svc := NewService(m)
	value, level, err := svc.Detokenize(rec.Token, "ADMIN")
	require.NoError(t, err)
	assert.Equal(t, "john@example.com", value)
	assert.Equal(t, "FULL", level)
}

func TestDetokenize_AnalystMaskedEmail(t *testing.T) {
	rec := encryptedRecord(t, "john@example.com", "email")
	m := &mockRepo{}
	m.On("FindByToken", rec.Token).Return(rec, nil)

	svc := NewService(m)
	value, level, err := svc.Detokenize(rec.Token, "ANALYST")
	require.NoError(t, err)
	assert.Equal(t, "MASKED", level)
	assert.True(t, strings.HasPrefix(value, "j***@"))
}

func TestDetokenize_AnalystDeniedCard(t *testing.T) {
	rec := encryptedRecord(t, "4111111111114242", "card_number")
	m := &mockRepo{}
	m.On("FindByToken", rec.Token).Return(rec, nil)

	svc := NewService(m)
	_, level, err := svc.Detokenize(rec.Token, "ANALYST")
	assert.Error(t, err)
	assert.Equal(t, "DENIED", level)
}

func TestDetokenize_ServiceFullCard(t *testing.T) {
	rec := encryptedRecord(t, "4111111111114242", "card_number")
	m := &mockRepo{}
	m.On("FindByToken", rec.Token).Return(rec, nil)

	svc := NewService(m)
	value, level, err := svc.Detokenize(rec.Token, "SERVICE")
	require.NoError(t, err)
	assert.Equal(t, "FULL", level)
	assert.Equal(t, "4111111111114242", value)
}

func TestDetokenize_ViewerMasked(t *testing.T) {
	rec := encryptedRecord(t, "9876543210", "phone")
	m := &mockRepo{}
	m.On("FindByToken", rec.Token).Return(rec, nil)

	svc := NewService(m)
	value, level, err := svc.Detokenize(rec.Token, "VIEWER")
	require.NoError(t, err)
	assert.Equal(t, "MASKED", level)
	assert.Equal(t, "******3210", value)
}

func TestDetokenize_NotFound(t *testing.T) {
	m := &mockRepo{}
	m.On("FindByToken", "tok_bad").Return(nil, errors.New("token not found"))

	svc := NewService(m)
	_, _, err := svc.Detokenize("tok_bad", "ADMIN")
	assert.Error(t, err)
}

func TestDelete_SoftDeletes(t *testing.T) {
	m := &mockRepo{}
	m.On("SoftDelete", "tok_abc").Return(nil)

	svc := NewService(m)
	err := svc.Delete("tok_abc")
	assert.NoError(t, err)
	m.AssertExpectations(t)
}

func TestResolveAccess(t *testing.T) {
	cases := []struct {
		role, field, want string
	}{
		{"ADMIN", "email", "FULL"},
		{"ADMIN", "card_number", "FULL"},
		{"ANALYST", "email", "MASKED"},
		{"ANALYST", "card_number", "DENIED"},
		{"ANALYST", "phone", "MASKED"},
		{"SERVICE", "card_number", "FULL"},
		{"SERVICE", "email", "MASKED"},
		{"VIEWER", "email", "MASKED"},
		{"UNKNOWN", "email", "DENIED"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, resolveAccess(tc.role, tc.field), "%s / %s", tc.role, tc.field)
	}
}
