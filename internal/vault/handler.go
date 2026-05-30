package vault

import (
	"net/http"

	"github.com/anandudevops/aegis/pkg/response"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
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
		response.Error(c, http.StatusInternalServerError, "tokenization failed")
		return
	}

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

	value, record, err := h.svc.Detokenize(req.Token)
	if err != nil {
		response.Error(c, http.StatusNotFound, err.Error())
		return
	}

	response.Success(c, http.StatusOK, gin.H{
		"token":      req.Token,
		"field_type": record.FieldType,
		"value":      value,
	})
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
