package rbac

import (
	"errors"

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

func (r *Repository) CreateRole(role *models.Role) error {
	return r.db.Create(role).Error
}

func (r *Repository) FindRoleByID(id uuid.UUID) (*models.Role, error) {
	var role models.Role
	err := r.db.Preload("Permissions").Where("id = ?", id).First(&role).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("role not found")
		}
		return nil, err
	}
	return &role, nil
}

func (r *Repository) FindRoleByName(name string) (*models.Role, error) {
	var role models.Role
	err := r.db.Preload("Permissions").Where("name = ?", name).First(&role).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("role not found")
		}
		return nil, err
	}
	return &role, nil
}

func (r *Repository) FindAllRoles() ([]*models.Role, error) {
	var roles []*models.Role
	err := r.db.Preload("Permissions").Order("name").Find(&roles).Error
	return roles, err
}

func (r *Repository) UpdateRole(id uuid.UUID, name, description string) error {
	return r.db.Model(&models.Role{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"name":        name,
			"description": description,
		}).Error
}

func (r *Repository) DeleteRole(id uuid.UUID) error {
	return r.db.Where("id = ?", id).Delete(&models.Role{}).Error
}

// SetPermission upserts a permission entry for the given role and field type.
func (r *Repository) SetPermission(roleID uuid.UUID, fieldType, accessLevel string) error {
	return r.db.
		Where(models.RolePermission{RoleID: roleID, FieldType: fieldType}).
		Assign(models.RolePermission{AccessLevel: accessLevel}).
		FirstOrCreate(&models.RolePermission{}).Error
}

func (r *Repository) DeletePermission(roleID uuid.UUID, fieldType string) error {
	result := r.db.
		Where("role_id = ? AND field_type = ?", roleID, fieldType).
		Delete(&models.RolePermission{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return errors.New("permission not found")
	}
	return nil
}

func (r *Repository) GetRolePermissions(roleID uuid.UUID) ([]*models.RolePermission, error) {
	var perms []*models.RolePermission
	err := r.db.Where("role_id = ?", roleID).Find(&perms).Error
	return perms, err
}

// GetPermissionForField returns the access level for a role name and field type.
// It tries the exact field type first, then falls back to "*" (default).
func (r *Repository) GetPermissionForField(roleName, fieldType string) (string, error) {
	var perm models.RolePermission
	err := r.db.
		Joins("JOIN roles ON roles.id = role_permissions.role_id").
		Where("roles.name = ? AND role_permissions.field_type = ?", roleName, fieldType).
		First(&perm).Error
	if err == nil {
		return perm.AccessLevel, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return "", err
	}

	// Fallback to default permission (*).
	err = r.db.
		Joins("JOIN roles ON roles.id = role_permissions.role_id").
		Where("roles.name = ? AND role_permissions.field_type = ?", roleName, "*").
		First(&perm).Error
	if err == nil {
		return perm.AccessLevel, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "DENIED", nil
	}
	return "", err
}

// CountUsersWithRole returns the number of users currently assigned a given role name.
func (r *Repository) CountUsersWithRole(name string) (int64, error) {
	var count int64
	err := r.db.Table("users").Where("role = ?", name).Count(&count).Error
	return count, err
}
