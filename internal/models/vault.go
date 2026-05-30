package models

import (
	"time"

	"github.com/google/uuid"
)

type VaultRecord struct {
	ID        uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Token     string     `gorm:"uniqueIndex;not null" json:"token"`
	FieldType string     `gorm:"not null" json:"field_type"`
	EncValue  string     `gorm:"not null" json:"-"`
	Nonce     string     `gorm:"not null" json:"-"`
	CreatedBy uuid.UUID  `gorm:"type:uuid" json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
}
