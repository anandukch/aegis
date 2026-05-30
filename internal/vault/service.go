package vault

import (
	"errors"
	"fmt"
	"os"

	"github.com/anandudevops/aegis/internal/crypto"
	"github.com/anandudevops/aegis/internal/models"
	"github.com/google/uuid"
)

type Service struct {
	repo *Repository
}

func NewService(repo *Repository) *Service {
	return &Service{repo: repo}
}

func (s *Service) Tokenize(fieldType, value, createdByID string) (*models.VaultRecord, error) {
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

func (s *Service) Detokenize(token string) (string, *models.VaultRecord, error) {
	record, err := s.repo.FindByToken(token)
	if err != nil {
		return "", nil, err
	}

	key, err := masterKey()
	if err != nil {
		return "", nil, err
	}

	plaintext, err := crypto.Decrypt(record.EncValue, record.Nonce, key)
	if err != nil {
		return "", nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, record, nil
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
