package vault

import (
	"errors"
	"fmt"
	"os"

	"github.com/anandudevops/aegis/internal/crypto"
	"github.com/anandudevops/aegis/internal/models"
	"github.com/google/uuid"
)

// RBACResolver resolves the access level for a given role and field type.
// rbac.Service implements this interface.
type RBACResolver interface {
	ResolveAccess(roleName, fieldType string) string
}

type RepositoryInterface interface {
	Create(record *models.VaultRecord) error
	FindByToken(token string) (*models.VaultRecord, error)
	FindAll() ([]*models.VaultRecord, error)
	UpdateEncDEK(id uuid.UUID, encDEK string) error
	UpdateEnvelope(id uuid.UUID, encValue, nonce, encDEK string) error
	SoftDelete(token string) error
}

type Service struct {
	repo    RepositoryInterface
	rbacSvc RBACResolver
}

func NewService(repo RepositoryInterface, rbacSvc RBACResolver) *Service {
	return &Service{repo: repo, rbacSvc: rbacSvc}
}

func (s *Service) Tokenize(fieldType, value, createdByID string) (*models.VaultRecord, error) {
	if fieldType == "pan" {
		normalized, err := crypto.ValidatePAN(value)
		if err != nil {
			return nil, err
		}
		value = normalized
	}

	kek, err := masterKey()
	if err != nil {
		return nil, err
	}

	dek, err := crypto.GenerateDEK()
	if err != nil {
		return nil, fmt.Errorf("generate DEK: %w", err)
	}

	encValue, nonce, err := crypto.Encrypt(value, dek)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	encDEK, err := crypto.WrapDEK(dek, kek)
	if err != nil {
		return nil, fmt.Errorf("wrap DEK: %w", err)
	}

	record := &models.VaultRecord{
		ID:        uuid.New(),
		Token:     "tok_" + uuid.New().String(),
		FieldType: fieldType,
		EncValue:  encValue,
		Nonce:     nonce,
		EncDEK:    encDEK,
	}

	if createdByID != "" {
		if id, err := uuid.Parse(createdByID); err == nil {
			record.CreatedBy = id
		}
	}

	if err := s.repo.Create(record); err != nil {
		return nil, fmt.Errorf("store record: %w", err)
	}
	return record, nil
}

func (s *Service) Detokenize(token, role string) (value, accessLevel string, err error) {
	record, err := s.repo.FindByToken(token)
	if err != nil {
		return "", "", err
	}

	accessLevel = s.rbacSvc.ResolveAccess(role, record.FieldType)
	if accessLevel == "DENIED" {
		return "", "DENIED", errors.New("access denied for this field type")
	}

	kek, err := masterKey()
	if err != nil {
		return "", "", err
	}

	var plaintext string
	if record.EncDEK != "" {
		// Envelope path: unwrap DEK with KEK, then decrypt value with DEK.
		dek, err := crypto.UnwrapDEK(record.EncDEK, kek)
		if err != nil {
			return "", "", fmt.Errorf("unwrap DEK: %w", err)
		}
		plaintext, err = crypto.Decrypt(record.EncValue, record.Nonce, dek)
		if err != nil {
			return "", "", fmt.Errorf("decrypt: %w", err)
		}
	} else {
		// Legacy path: value was encrypted directly with KEK before envelope encryption was introduced.
		plaintext, err = crypto.Decrypt(record.EncValue, record.Nonce, kek)
		if err != nil {
			return "", "", fmt.Errorf("decrypt: %w", err)
		}
	}

	if accessLevel == "MASKED" {
		plaintext = crypto.MaskValue(plaintext, record.FieldType)
	}
	return plaintext, accessLevel, nil
}

// MigrateToEnvelope converts all legacy records (encrypted directly with the KEK) to envelope
// encryption. Safe to call multiple times — it skips records that already have an enc_dek.
// Returns the number of records migrated.
func (s *Service) MigrateToEnvelope() (int, error) {
	kek, err := masterKey()
	if err != nil {
		return 0, err
	}

	records, err := s.repo.FindAll()
	if err != nil {
		return 0, fmt.Errorf("find all records: %w", err)
	}

	migrated := 0
	for _, rec := range records {
		if rec.EncDEK != "" {
			continue
		}

		plaintext, err := crypto.Decrypt(rec.EncValue, rec.Nonce, kek)
		if err != nil {
			return migrated, fmt.Errorf("decrypt legacy record %s: %w", rec.ID, err)
		}

		dek, err := crypto.GenerateDEK()
		if err != nil {
			return migrated, fmt.Errorf("generate DEK for %s: %w", rec.ID, err)
		}

		encValue, nonce, err := crypto.Encrypt(plaintext, dek)
		if err != nil {
			return migrated, fmt.Errorf("re-encrypt record %s: %w", rec.ID, err)
		}

		encDEK, err := crypto.WrapDEK(dek, kek)
		if err != nil {
			return migrated, fmt.Errorf("wrap DEK for %s: %w", rec.ID, err)
		}

		if err := s.repo.UpdateEnvelope(rec.ID, encValue, nonce, encDEK); err != nil {
			return migrated, fmt.Errorf("update record %s: %w", rec.ID, err)
		}
		migrated++
	}
	return migrated, nil
}

// PartialRotationError is returned when RotateKeys fails mid-way. Rotated holds the
// count of records successfully re-wrapped before the error occurred.
type PartialRotationError struct {
	Rotated int
	Cause   error
}

func (e *PartialRotationError) Error() string {
	return fmt.Sprintf("rotation failed after %d record(s): %v", e.Rotated, e.Cause)
}

func (e *PartialRotationError) Unwrap() error { return e.Cause }

// RotateKeys re-wraps every DEK from the current KEK to newKEK. The enc_value blobs are never
// touched — only enc_dek is updated. Returns the number of records whose DEK was rotated.
// After a successful rotation, update VAULT_MASTER_KEY in the environment to newKEK.
func (s *Service) RotateKeys(newKEK []byte) (int, error) {
	if len(newKEK) != 32 {
		return 0, errors.New("new KEK must be exactly 32 bytes")
	}

	oldKEK, err := masterKey()
	if err != nil {
		return 0, err
	}

	records, err := s.repo.FindAll()
	if err != nil {
		return 0, fmt.Errorf("find all records: %w", err)
	}

	rotated := 0
	for _, rec := range records {
		if rec.EncDEK == "" {
			continue
		}

		dek, err := crypto.UnwrapDEK(rec.EncDEK, oldKEK)
		if err != nil {
			return rotated, &PartialRotationError{Rotated: rotated, Cause: fmt.Errorf("unwrap DEK for record %s: %w", rec.ID, err)}
		}

		newEncDEK, err := crypto.WrapDEK(dek, newKEK)
		if err != nil {
			return rotated, &PartialRotationError{Rotated: rotated, Cause: fmt.Errorf("re-wrap DEK for record %s: %w", rec.ID, err)}
		}

		if err := s.repo.UpdateEncDEK(rec.ID, newEncDEK); err != nil {
			return rotated, &PartialRotationError{Rotated: rotated, Cause: fmt.Errorf("update enc_dek for record %s: %w", rec.ID, err)}
		}
		rotated++
	}
	return rotated, nil
}

func (s *Service) Delete(token string) error {
	return s.repo.SoftDelete(token)
}

func (s *Service) GetMetadata(token string) (*models.VaultRecord, error) {
	return s.repo.FindByToken(token)
}

func masterKey() ([]byte, error) {
	key := []byte(os.Getenv("VAULT_MASTER_KEY"))
	if len(key) != 32 {
		return nil, errors.New("VAULT_MASTER_KEY must be exactly 32 bytes")
	}
	return key, nil
}
