package llmproxy

import (
	"errors"
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

func (h *Handler) Chat(c *gin.Context) {
	var req struct {
		Prompt   string `json:"prompt" binding:"required"`
		Provider string `json:"provider"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}

	userID, _ := c.Get("user_id")
	reply, piiCount, provider, err := h.svc.Chat(
		c.Request.Context(),
		userID.(string),
		c.ClientIP(),
		req.Prompt,
		req.Provider,
	)
	if err != nil {
		if errors.Is(err, ErrLLMUnavailable) {
			response.Error(c, http.StatusServiceUnavailable, "LLM provider unavailable")
			return
		}
		response.Error(c, http.StatusInternalServerError, err.Error())
		return
	}

	response.Success(c, http.StatusOK, gin.H{
		"response":     reply,
		"pii_detected": piiCount,
		"provider":     provider,
	})
}
