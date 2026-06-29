package rbac

import (
	"fmt"
	"regexp"

	"github.com/anandudevops/aegis/internal/models"
	"github.com/google/uuid"
)

// ValidFieldTypes are the accepted field_type values for permissions.
// "*" is the catch-all default permission for a role.
var ValidFieldTypes = map[string]bool{
	"email":       true,
	"phone":       true,
	"card_number": true,
	"aadhaar":     true,
	"pan":         true,
	"name":        true,
	"dob":         true,
	"*":           true,
}

// ValidAccessLevels are the accepted access_level enum values.
var ValidAccessLevels = map[string]bool{
	"FULL":   true,
	"MASKED": true,
	"DENIED": true,
}

var roleNameRegex = regexp.MustCompile(`^[A-Za-z0-9_]{1,50}$`)

type Service struct {
	repo *Repository
}

func NewService(repo *Repository) *Service {
	return &Service{repo: repo}
}

func (s *Service) CreateRole(name, description string) (*models.Role, error) {
	if !roleNameRegex.MatchString(name) {
		return nil, fmt.Errorf("role name must be 1–50 alphanumeric/underscore characters")
	}
	role := &models.Role{
		ID:          uuid.New(),
		Name:        name,
		Description: description,
	}
	if err := s.repo.CreateRole(role); err != nil {
		return nil, fmt.Errorf("create role: %w", err)
	}
	return role, nil
}

func (s *Service) GetRole(id uuid.UUID) (*models.Role, error) {
	return s.repo.FindRoleByID(id)
}

func (s *Service) ListRoles() ([]*models.Role, error) {
	return s.repo.FindAllRoles()
}

func (s *Service) UpdateRole(id uuid.UUID, name, description string) (*models.Role, error) {
	role, err := s.repo.FindRoleByID(id)
	if err != nil {
		return nil, err
	}
	if role.IsSystem {
		return nil, fmt.Errorf("system role %q cannot be renamed", role.Name)
	}
	if !roleNameRegex.MatchString(name) {
		return nil, fmt.Errorf("role name must be 1–50 alphanumeric/underscore characters")
	}
	if err := s.repo.UpdateRole(id, name, description); err != nil {
		return nil, fmt.Errorf("update role: %w", err)
	}
	return s.repo.FindRoleByID(id)
}

func (s *Service) DeleteRole(id uuid.UUID) error {
	role, err := s.repo.FindRoleByID(id)
	if err != nil {
		return err
	}
	if role.IsSystem {
		return fmt.Errorf("system role %q cannot be deleted", role.Name)
	}
	count, err := s.repo.CountUsersWithRole(role.Name)
	if err != nil {
		return fmt.Errorf("check role assignment: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("role %q is assigned to %d user(s); reassign them before deleting", role.Name, count)
	}
	return s.repo.DeleteRole(id)
}

func (s *Service) SetPermission(roleID uuid.UUID, fieldType, accessLevel string) error {
	if _, err := s.repo.FindRoleByID(roleID); err != nil {
		return err
	}
	if !ValidFieldTypes[fieldType] {
		return fmt.Errorf("invalid field_type %q; allowed: email, phone, card_number, aadhaar, pan, name, dob, *", fieldType)
	}
	if !ValidAccessLevels[accessLevel] {
		return fmt.Errorf("invalid access_level %q; allowed: FULL, MASKED, DENIED", accessLevel)
	}
	return s.repo.SetPermission(roleID, fieldType, accessLevel)
}

func (s *Service) DeletePermission(roleID uuid.UUID, fieldType string) error {
	if _, err := s.repo.FindRoleByID(roleID); err != nil {
		return err
	}
	return s.repo.DeletePermission(roleID, fieldType)
}

// ResolveAccess returns the access level for roleName/fieldType.
// Tries exact field_type first, then falls back to "*" (default).
// Returns "DENIED" for unknown roles or when no permission is configured.
// Implements the vault.RBACResolver interface.
func (s *Service) ResolveAccess(roleName, fieldType string) string {
	level, err := s.repo.GetPermissionForField(roleName, fieldType)
	if err != nil {
		return "DENIED"
	}
	return level
}

// RoleExists reports whether a role name exists in the database.
// Implements the auth.RoleChecker interface.
func (s *Service) RoleExists(name string) bool {
	_, err := s.repo.FindRoleByName(name)
	return err == nil
}
