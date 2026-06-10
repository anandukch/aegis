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

func (m *mockRepo) FindAll() ([]*models.VaultRecord, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.VaultRecord), args.Error(1)
}

func (m *mockRepo) UpdateEncDEK(id uuid.UUID, encDEK string) error {
	return m.Called(id, encDEK).Error(0)
}

func (m *mockRepo) UpdateEnvelope(id uuid.UUID, encValue, nonce, encDEK string) error {
	return m.Called(id, encValue, nonce, encDEK).Error(0)
}

func (m *mockRepo) SoftDelete(token string) error {
	return m.Called(token).Error(0)
}

// legacyRecord creates a vault record encrypted directly with testKey (no EncDEK),
// simulating records created before envelope encryption was introduced.
func legacyRecord(t *testing.T, plaintext, fieldType string) *models.VaultRecord {
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

// envelopeRecord creates a vault record using the full envelope encryption path.
func envelopeRecord(t *testing.T, plaintext, fieldType string) *models.VaultRecord {
	t.Helper()
	dek, err := crypto.GenerateDEK()
	require.NoError(t, err)
	enc, nonce, err := crypto.Encrypt(plaintext, dek)
	require.NoError(t, err)
	encDEK, err := crypto.WrapDEK(dek, testKey)
	require.NoError(t, err)
	return &models.VaultRecord{
		ID:        uuid.New(),
		Token:     "tok_" + uuid.New().String(),
		FieldType: fieldType,
		EncValue:  enc,
		Nonce:     nonce,
		EncDEK:    encDEK,
	}
}

// --- Tokenize tests ---

func TestTokenize_StoresRecord(t *testing.T) {
	m := &mockRepo{}
	m.On("Create", mock.AnythingOfType("*models.VaultRecord")).Return(nil)

	svc := NewService(m)
	record, err := svc.Tokenize("email", "john@example.com", uuid.New().String())

	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(record.Token, "tok_"))
	assert.Equal(t, "email", record.FieldType)
	assert.NotEmpty(t, record.EncValue)
	assert.NotEmpty(t, record.EncDEK)
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
		return r.FieldType == "pan" && r.EncValue != "" && r.EncDEK != ""
	})).Return(nil).Run(func(args mock.Arguments) {
		record := args.Get(0).(*models.VaultRecord)

		dek, err := crypto.UnwrapDEK(record.EncDEK, testKey)
		require.NoError(t, err)
		dec, err := crypto.Decrypt(record.EncValue, record.Nonce, dek)
		require.NoError(t, err)
		assert.Equal(t, "ABCDE1234F", dec)
	})

	svc := NewService(m)
	record, err := svc.Tokenize("pan", "abcde1234f", uuid.New().String())
	require.NoError(t, err)
	assert.Equal(t, "pan", record.FieldType)
	m.AssertExpectations(t)
}

// --- Detokenize tests (legacy path — no EncDEK) ---

func TestDetokenize_LegacyAdminFull(t *testing.T) {
	rec := legacyRecord(t, "john@example.com", "email")
	m := &mockRepo{}
	m.On("FindByToken", rec.Token).Return(rec, nil)

	svc := NewService(m)
	value, level, err := svc.Detokenize(rec.Token, "ADMIN")
	require.NoError(t, err)
	assert.Equal(t, "john@example.com", value)
	assert.Equal(t, "FULL", level)
}

func TestDetokenize_LegacyAnalystMaskedEmail(t *testing.T) {
	rec := legacyRecord(t, "john@example.com", "email")
	m := &mockRepo{}
	m.On("FindByToken", rec.Token).Return(rec, nil)

	svc := NewService(m)
	value, level, err := svc.Detokenize(rec.Token, "ANALYST")
	require.NoError(t, err)
	assert.Equal(t, "MASKED", level)
	assert.True(t, strings.HasPrefix(value, "j***@"))
}

// --- Detokenize tests (envelope path — with EncDEK) ---

func TestDetokenize_EnvelopeAdminFull(t *testing.T) {
	rec := envelopeRecord(t, "john@example.com", "email")
	m := &mockRepo{}
	m.On("FindByToken", rec.Token).Return(rec, nil)

	svc := NewService(m)
	value, level, err := svc.Detokenize(rec.Token, "ADMIN")
	require.NoError(t, err)
	assert.Equal(t, "john@example.com", value)
	assert.Equal(t, "FULL", level)
}

func TestDetokenize_EnvelopeAnalystMasked(t *testing.T) {
	rec := envelopeRecord(t, "john@example.com", "email")
	m := &mockRepo{}
	m.On("FindByToken", rec.Token).Return(rec, nil)

	svc := NewService(m)
	value, level, err := svc.Detokenize(rec.Token, "ANALYST")
	require.NoError(t, err)
	assert.Equal(t, "MASKED", level)
	assert.True(t, strings.HasPrefix(value, "j***@"))
}

func TestDetokenize_AnalystDeniedCard(t *testing.T) {
	rec := envelopeRecord(t, "4111111111114242", "card_number")
	m := &mockRepo{}
	m.On("FindByToken", rec.Token).Return(rec, nil)

	svc := NewService(m)
	_, level, err := svc.Detokenize(rec.Token, "ANALYST")
	assert.Error(t, err)
	assert.Equal(t, "DENIED", level)
}

func TestDetokenize_ServiceFullCard(t *testing.T) {
	rec := envelopeRecord(t, "4111111111114242", "card_number")
	m := &mockRepo{}
	m.On("FindByToken", rec.Token).Return(rec, nil)

	svc := NewService(m)
	value, level, err := svc.Detokenize(rec.Token, "SERVICE")
	require.NoError(t, err)
	assert.Equal(t, "FULL", level)
	assert.Equal(t, "4111111111114242", value)
}

func TestDetokenize_ViewerMasked(t *testing.T) {
	rec := envelopeRecord(t, "9876543210", "phone")
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

// --- Key rotation test ---

func TestRotateKeys_ReWrapsEncDEKOnly(t *testing.T) {
	newKEK := []byte("99999999999999999999999999999999")

	rec1 := envelopeRecord(t, "alice@example.com", "email")
	rec2 := envelopeRecord(t, "9876543210", "phone")

	originalEncDEK1 := rec1.EncDEK
	originalEncValue1 := rec1.EncValue

	m := &mockRepo{}
	m.On("FindAll").Return([]*models.VaultRecord{rec1, rec2}, nil)
	m.On("UpdateEncDEK", rec1.ID, mock.AnythingOfType("string")).Return(nil).Run(func(args mock.Arguments) {
		newEncDEK := args.String(1)
		assert.NotEqual(t, originalEncDEK1, newEncDEK, "enc_dek should change after rotation")

		// enc_value must still decrypt correctly with the unwrapped new DEK
		dek, err := crypto.UnwrapDEK(newEncDEK, newKEK)
		require.NoError(t, err)
		plaintext, err := crypto.Decrypt(rec1.EncValue, rec1.Nonce, dek)
		require.NoError(t, err)
		assert.Equal(t, "alice@example.com", plaintext)
		assert.Equal(t, originalEncValue1, rec1.EncValue, "enc_value must be untouched")
	})
	m.On("UpdateEncDEK", rec2.ID, mock.AnythingOfType("string")).Return(nil)

	svc := NewService(m)
	rotated, err := svc.RotateKeys(newKEK)
	require.NoError(t, err)
	assert.Equal(t, 2, rotated)
	m.AssertExpectations(t)
}

func TestRotateKeys_SkipsLegacyRecords(t *testing.T) {
	newKEK := []byte("99999999999999999999999999999999")

	legacy := legacyRecord(t, "alice@example.com", "email")
	envelope := envelopeRecord(t, "bob@example.com", "email")

	m := &mockRepo{}
	m.On("FindAll").Return([]*models.VaultRecord{legacy, envelope}, nil)
	m.On("UpdateEncDEK", envelope.ID, mock.AnythingOfType("string")).Return(nil)

	svc := NewService(m)
	rotated, err := svc.RotateKeys(newKEK)
	require.NoError(t, err)
	assert.Equal(t, 1, rotated, "legacy record without enc_dek must be skipped")
	m.AssertExpectations(t)
}

func TestRotateKeys_RejectsShortKey(t *testing.T) {
	svc := NewService(&mockRepo{})
	_, err := svc.RotateKeys([]byte("tooshort"))
	assert.Error(t, err)
}

// --- MigrateToEnvelope test ---

func TestMigrateToEnvelope_MigratesLegacyRecords(t *testing.T) {
	legacy := legacyRecord(t, "alice@example.com", "email")
	already := envelopeRecord(t, "bob@example.com", "phone")

	m := &mockRepo{}
	m.On("FindAll").Return([]*models.VaultRecord{legacy, already}, nil)
	m.On("UpdateEnvelope", legacy.ID,
		mock.AnythingOfType("string"),
		mock.AnythingOfType("string"),
		mock.AnythingOfType("string"),
	).Return(nil).Run(func(args mock.Arguments) {
		newEncValue := args.String(1)
		newNonce := args.String(2)
		newEncDEK := args.String(3)

		assert.NotEmpty(t, newEncDEK)

		// Verify round-trip: unwrap new DEK and decrypt new enc_value
		dek, err := crypto.UnwrapDEK(newEncDEK, testKey)
		require.NoError(t, err)
		plaintext, err := crypto.Decrypt(newEncValue, newNonce, dek)
		require.NoError(t, err)
		assert.Equal(t, "alice@example.com", plaintext)
	})

	svc := NewService(m)
	migrated, err := svc.MigrateToEnvelope()
	require.NoError(t, err)
	assert.Equal(t, 1, migrated, "already-migrated record must be skipped")
	m.AssertExpectations(t)
}

// --- Delete test ---

func TestDelete_SoftDeletes(t *testing.T) {
	m := &mockRepo{}
	m.On("SoftDelete", "tok_abc").Return(nil)

	svc := NewService(m)
	err := svc.Delete("tok_abc")
	assert.NoError(t, err)
	m.AssertExpectations(t)
}

// --- resolveAccess tests ---

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
