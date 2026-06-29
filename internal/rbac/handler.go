package rbac

import (
	"net/http"

	"github.com/anandudevops/aegis/internal/auth"
	"github.com/anandudevops/aegis/pkg/response"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type Handler struct {
	svc     *Service
	authSvc *auth.Service
}

func NewHandler(svc *Service, authSvc *auth.Service) *Handler {
	return &Handler{svc: svc, authSvc: authSvc}
}

// --- Legacy endpoint: GET /api/v1/roles ---
// Returns all roles and their permissions, sourced from the database.

func (h *Handler) GetRoles(c *gin.Context) {
	roles, err := h.svc.ListRoles()
	if err != nil {
		response.Error(c, http.StatusInternalServerError, "failed to fetch roles")
		return
	}
	response.Success(c, http.StatusOK, roles)
}

// --- Legacy endpoint: POST /api/v1/users/:id/role ---

func (h *Handler) AssignRole(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.Error(c, http.StatusBadRequest, "invalid user id")
		return
	}

	var req struct {
		Role string `json:"role" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.authSvc.AssignRole(userID, req.Role); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}
	response.Success(c, http.StatusOK, gin.H{"message": "role updated"})
}

// --- RBAC CRUD endpoints ---

// CreateRole handles POST /api/v1/rbac/roles
func (h *Handler) CreateRole(c *gin.Context) {
	var req struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}

	role, err := h.svc.CreateRole(req.Name, req.Description)
	if err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}
	response.Success(c, http.StatusCreated, role)
}

// ListRoles handles GET /api/v1/rbac/roles
func (h *Handler) ListRoles(c *gin.Context) {
	roles, err := h.svc.ListRoles()
	if err != nil {
		response.Error(c, http.StatusInternalServerError, "failed to fetch roles")
		return
	}
	response.Success(c, http.StatusOK, gin.H{"roles": roles})
}

// GetRole handles GET /api/v1/rbac/roles/:id
func (h *Handler) GetRole(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.Error(c, http.StatusBadRequest, "invalid role id")
		return
	}
	role, err := h.svc.GetRole(id)
	if err != nil {
		response.Error(c, http.StatusNotFound, err.Error())
		return
	}
	response.Success(c, http.StatusOK, role)
}

// UpdateRole handles PUT /api/v1/rbac/roles/:id
func (h *Handler) UpdateRole(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.Error(c, http.StatusBadRequest, "invalid role id")
		return
	}

	var req struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}

	role, err := h.svc.UpdateRole(id, req.Name, req.Description)
	if err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}
	response.Success(c, http.StatusOK, role)
}

// DeleteRole handles DELETE /api/v1/rbac/roles/:id
func (h *Handler) DeleteRole(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.Error(c, http.StatusBadRequest, "invalid role id")
		return
	}

	if err := h.svc.DeleteRole(id); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}
	response.Success(c, http.StatusOK, gin.H{"message": "role deleted"})
}

// SetPermission handles POST /api/v1/rbac/roles/:id/permissions
func (h *Handler) SetPermission(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.Error(c, http.StatusBadRequest, "invalid role id")
		return
	}

	var req struct {
		FieldType   string `json:"field_type" binding:"required"`
		AccessLevel string `json:"access_level" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.svc.SetPermission(id, req.FieldType, req.AccessLevel); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}
	response.Success(c, http.StatusOK, gin.H{
		"role_id":      id,
		"field_type":   req.FieldType,
		"access_level": req.AccessLevel,
	})
}

// DeletePermission handles DELETE /api/v1/rbac/roles/:id/permissions/:field_type
func (h *Handler) DeletePermission(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.Error(c, http.StatusBadRequest, "invalid role id")
		return
	}

	fieldType := c.Param("field_type")
	if fieldType == "" {
		response.Error(c, http.StatusBadRequest, "field_type is required")
		return
	}

	if err := h.svc.DeletePermission(id, fieldType); err != nil {
		response.Error(c, http.StatusNotFound, err.Error())
		return
	}
	response.Success(c, http.StatusOK, gin.H{"message": "permission removed"})
}
