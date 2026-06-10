package vault

import (
	"errors"
	"time"

	"github.com/anandudevops/aegis/internal/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Repository struct {
	db *gorm.DB
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) Create(record *models.VaultRecord) error {
	return r.db.Create(record).Error
}

func (r *Repository) FindByToken(token string) (*models.VaultRecord, error) {
	var record models.VaultRecord
	err := r.db.Where("token = ? AND deleted_at IS NULL", token).First(&record).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("token not found")
		}
		return nil, err
	}
	return &record, nil
}

// FindAll returns all non-deleted vault records. Used for key rotation and envelope migration.
func (r *Repository) FindAll() ([]*models.VaultRecord, error) {
	var records []*models.VaultRecord
	err := r.db.Where("deleted_at IS NULL").Find(&records).Error
	return records, err
}

// UpdateEncDEK updates only the enc_dek column for the given record. Used during key rotation
// when only the wrapped DEK changes and enc_value/nonce remain untouched.
func (r *Repository) UpdateEncDEK(id uuid.UUID, encDEK string) error {
	return r.db.Model(&models.VaultRecord{}).
		Where("id = ?", id).
		Update("enc_dek", encDEK).Error
}

// UpdateEnvelope updates enc_value, nonce, and enc_dek together. Used when migrating a legacy
// record (encrypted directly with KEK) to envelope encryption.
func (r *Repository) UpdateEnvelope(id uuid.UUID, encValue, nonce, encDEK string) error {
	return r.db.Model(&models.VaultRecord{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"enc_value": encValue,
			"nonce":     nonce,
			"enc_dek":   encDEK,
		}).Error
}

func (r *Repository) SoftDelete(token string) error {
	now := time.Now()
	result := r.db.Model(&models.VaultRecord{}).
		Where("token = ? AND deleted_at IS NULL", token).
		Update("deleted_at", now)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return errors.New("token not found")
	}
	return nil
}
