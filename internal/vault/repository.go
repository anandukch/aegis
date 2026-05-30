package vault

import (
	"errors"
	"time"

	"github.com/anandudevops/aegis/internal/models"
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
