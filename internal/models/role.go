package models

import (
	"time"

	"github.com/google/uuid"
)

type Role struct {
	ID          uuid.UUID        `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Name        string           `gorm:"uniqueIndex;not null" json:"name"`
	Description string           `json:"description"`
	IsSystem    bool             `gorm:"not null;default:false" json:"is_system"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
	Permissions []RolePermission `gorm:"foreignKey:RoleID" json:"permissions,omitempty"`
}

// RolePermission defines what access level a role has for a given field type.
// field_type="*" is the default/fallback used when no explicit entry exists for a field.
type RolePermission struct {
	ID          uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	RoleID      uuid.UUID `gorm:"type:uuid;not null" json:"role_id"`
	FieldType   string    `gorm:"not null" json:"field_type"`
	AccessLevel string    `gorm:"not null" json:"access_level"`
	CreatedAt   time.Time `json:"created_at"`
}
