package auth

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/anandudevops/aegis/internal/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// RoleChecker checks whether a role name is valid (exists in the database).
// rbac.Service implements this interface.
type RoleChecker interface {
	RoleExists(name string) bool
}

type Claims struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

type Service struct {
	repo        *Repository
	roleChecker RoleChecker
}

func NewService(repo *Repository, roleChecker RoleChecker) *Service {
	return &Service{repo: repo, roleChecker: roleChecker}
}

func (s *Service) Register(username, password, role string) (*models.User, error) {
	if !s.roleChecker.RoleExists(role) {
		role = "VIEWER"
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	user := &models.User{
		ID:           uuid.New(),
		Username:     username,
		PasswordHash: string(hash),
		Role:         role,
	}

	if err := s.repo.Create(user); err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	return user, nil
}

func (s *Service) Login(username, password string) (string, *models.User, error) {
	user, err := s.repo.FindByUsername(username)
	if err != nil {
		return "", nil, errors.New("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return "", nil, errors.New("invalid credentials")
	}

	token, err := issueJWT(user)
	if err != nil {
		return "", nil, fmt.Errorf("issue jwt: %w", err)
	}
	return token, user, nil
}

func (s *Service) AssignRole(targetUserID uuid.UUID, role string) error {
	if !s.roleChecker.RoleExists(role) {
		return fmt.Errorf("invalid role: %s", role)
	}
	return s.repo.UpdateRole(targetUserID, role)
}

func issueJWT(user *models.User) (string, error) {
	secret := os.Getenv("JWT_SECRET")
	expiryHours, _ := strconv.Atoi(os.Getenv("JWT_EXPIRY_HOURS"))
	if expiryHours <= 0 {
		expiryHours = 24
	}

	claims := Claims{
		UserID: user.ID.String(),
		Role:   user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(expiryHours) * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   user.ID.String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}
