package auth

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

func (h *Handler) Register(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required,min=8"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}

	user, err := h.svc.Register(req.Username, req.Password)
	if err != nil {
		response.Error(c, http.StatusConflict, "username already exists")
		return
	}
	response.Success(c, http.StatusCreated, gin.H{"id": user.ID, "username": user.Username})
}

func (h *Handler) Login(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}

	token, user, err := h.svc.Login(req.Username, req.Password)
	if err != nil {
		response.Error(c, http.StatusUnauthorized, "invalid credentials")
		return
	}
	response.Success(c, http.StatusOK, gin.H{
		"token": token,
		"user":  gin.H{"id": user.ID, "username": user.Username},
	})
}
