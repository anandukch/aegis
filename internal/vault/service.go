package vault

import (
	"errors"
	"fmt"
	"os"

	"github.com/anandudevops/aegis/internal/crypto"
	"github.com/anandudevops/aegis/internal/models"
	"github.com/google/uuid"
)

var accessMatrix = map[string]map[string]string{
	"ADMIN": {
		"": "FULL",
	},
	"ANALYST": {
		"email":       "MASKED",
		"name":        "MASKED",
		"card_number": "DENIED",
		"":            "MASKED",
	},
	"SERVICE": {
		"card_number": "FULL",
		"":            "MASKED",
	},
	"VIEWER": {
		"": "MASKED",
	},
}

type RepositoryInterface interface {
	Create(record *models.VaultRecord) error
	FindByToken(token string) (*models.VaultRecord, error)
	SoftDelete(token string) error
}

type Service struct {
	repo RepositoryInterface
}

func NewService(repo RepositoryInterface) *Service {
	return &Service{repo: repo}
}

func (s *Service) Tokenize(fieldType, value, createdByID string) (*models.VaultRecord, error) {
	if fieldType == "pan" {
		normalized, err := crypto.ValidatePAN(value)
		if err != nil {
			return nil, err
		}
		value = normalized
	}

	key, err := masterKey()
	if err != nil {
		return nil, err
	}

	encValue, nonce, err := crypto.Encrypt(value, key)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	record := &models.VaultRecord{
		ID:        uuid.New(),
		Token:     "tok_" + uuid.New().String(),
		FieldType: fieldType,
		EncValue:  encValue,
		Nonce:     nonce,
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

	accessLevel = resolveAccess(role, record.FieldType)
	if accessLevel == "DENIED" {
		return "", "DENIED", errors.New("access denied for this field type")
	}

	key, err := masterKey()
	if err != nil {
		return "", "", err
	}

	plaintext, err := crypto.Decrypt(record.EncValue, record.Nonce, key)
	if err != nil {
		return "", "", fmt.Errorf("decrypt: %w", err)
	}

	if accessLevel == "MASKED" {
		plaintext = crypto.MaskValue(plaintext, record.FieldType)
	}
	return plaintext, accessLevel, nil
}

func (s *Service) Delete(token string) error {
	return s.repo.SoftDelete(token)
}

func (s *Service) GetMetadata(token string) (*models.VaultRecord, error) {
	return s.repo.FindByToken(token)
}

func resolveAccess(role, fieldType string) string {
	roleMap, ok := accessMatrix[role]
	if !ok {
		return "DENIED"
	}
	if level, ok := roleMap[fieldType]; ok {
		return level
	}
	return roleMap[""]
}

func masterKey() ([]byte, error) {
	key := []byte(os.Getenv("VAULT_MASTER_KEY"))
	if len(key) != 32 {
		return nil, errors.New("VAULT_MASTER_KEY must be exactly 32 bytes")
	}
	return key, nil
}
