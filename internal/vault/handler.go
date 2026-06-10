package vault

import (
	"errors"
	"net/http"

	"github.com/anandudevops/aegis/internal/audit"
	"github.com/anandudevops/aegis/internal/crypto"
	"github.com/anandudevops/aegis/pkg/response"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	svc      *Service
	auditSvc *audit.Service
}

func NewHandler(svc *Service, auditSvc *audit.Service) *Handler {
	return &Handler{svc: svc, auditSvc: auditSvc}
}

func (h *Handler) Tokenize(c *gin.Context) {
	var req struct {
		FieldType string `json:"field_type" binding:"required"`
		Value     string `json:"value" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}

	userID, _ := c.Get("user_id")
	record, err := h.svc.Tokenize(req.FieldType, req.Value, userID.(string))
	if err != nil {
		h.auditSvc.Log(userID.(string), "STORE", "", req.FieldType, "", c.ClientIP(), false, err.Error())
		if errors.Is(err, crypto.ErrInvalidPAN) {
			response.Error(c, http.StatusBadRequest, err.Error())
			return
		}
		response.Error(c, http.StatusInternalServerError, "tokenization failed")
		return
	}

	h.auditSvc.Log(userID.(string), "STORE", record.Token, record.FieldType, "FULL", c.ClientIP(), true, "")
	response.Success(c, http.StatusCreated, gin.H{
		"token":      record.Token,
		"field_type": record.FieldType,
		"created_at": record.CreatedAt,
	})
}

func (h *Handler) Detokenize(c *gin.Context) {
	var req struct {
		Token string `json:"token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}

	userID, _ := c.Get("user_id")
	role, _ := c.Get("role")
	value, accessLevel, err := h.svc.Detokenize(req.Token, role.(string))
	if err != nil {
		fieldType := ""
		if rec, fetchErr := h.svc.GetMetadata(req.Token); fetchErr == nil {
			fieldType = rec.FieldType
		}
		h.auditSvc.Log(userID.(string), "DETOKENIZE", req.Token, fieldType, accessLevel, c.ClientIP(), false, err.Error())

		if accessLevel == "DENIED" {
			response.Error(c, http.StatusForbidden, "access denied for this field type")
		} else {
			response.Error(c, http.StatusNotFound, err.Error())
		}
		return
	}

	record, _ := h.svc.GetMetadata(req.Token)
	h.auditSvc.Log(userID.(string), "DETOKENIZE", req.Token, record.FieldType, accessLevel, c.ClientIP(), true, "")

	response.Success(c, http.StatusOK, gin.H{
		"token":        req.Token,
		"field_type":   record.FieldType,
		"value":        value,
		"access_level": accessLevel,
	})
}

func (h *Handler) Delete(c *gin.Context) {
	token := c.Param("token")
	userID, _ := c.Get("user_id")

	record, err := h.svc.GetMetadata(token)
	fieldType := ""
	if err == nil {
		fieldType = record.FieldType
	}

	if err := h.svc.Delete(token); err != nil {
		h.auditSvc.Log(userID.(string), "DELETE", token, fieldType, "", c.ClientIP(), false, err.Error())
		response.Error(c, http.StatusNotFound, err.Error())
		return
	}

	h.auditSvc.Log(userID.(string), "DELETE", token, fieldType, "FULL", c.ClientIP(), true, "")
	response.Success(c, http.StatusOK, gin.H{"message": "record deleted"})
}

func (h *Handler) GetMetadata(c *gin.Context) {
	token := c.Param("token")
	record, err := h.svc.GetMetadata(token)
	if err != nil {
		response.Error(c, http.StatusNotFound, err.Error())
		return
	}
	response.Success(c, http.StatusOK, gin.H{
		"token":      record.Token,
		"field_type": record.FieldType,
		"created_at": record.CreatedAt,
		"created_by": record.CreatedBy,
	})
}

