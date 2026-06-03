package llmproxy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/anandudevops/aegis/internal/audit"
	"github.com/anandudevops/aegis/internal/models"
)

const internalDetokenizeRole = "ADMIN"

var tokenPattern = regexp.MustCompile(`tok_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

type VaultAPI interface {
	Tokenize(fieldType, value, createdByID string) (*models.VaultRecord, error)
	Detokenize(token, role string) (value, accessLevel string, err error)
}

type Service struct {
	vault  VaultAPI
	audit  *audit.Service
	client LLMClient
}

func NewService(vault VaultAPI, auditSvc *audit.Service, client LLMClient) *Service {
	if client == nil {
		client = NewHTTPClient()
	}
	return &Service{
		vault:  vault,
		audit:  auditSvc,
		client: client,
	}
}

func (s *Service) Chat(ctx context.Context, actorID, ip, prompt, provider string) (string, int, string, error) {
	provider = resolveProvider(provider)
	matches := DetectPII(prompt)

	valueToToken := make(map[string]string)
	var tokensUsed []string

	if len(matches) > 0 {
		seen := make(map[string]string)
		for _, m := range matches {
			if _, ok := seen[m.Value]; ok {
				continue
			}
			record, err := s.vault.Tokenize(m.FieldType, m.Value, actorID)
			if err != nil {
				s.logProxy(actorID, ip, provider, tokensUsed, false, err.Error())
				return "", 0, provider, fmt.Errorf("vault tokenize: %w", err)
			}
			seen[m.Value] = record.Token
			valueToToken[m.Value] = record.Token
			tokensUsed = append(tokensUsed, record.Token)
		}
	}

	sanitized := replaceMatches(prompt, matches, valueToToken)

	llmResponse, err := s.client.Chat(ctx, provider, sanitized)
	if err != nil {
		s.logProxy(actorID, ip, provider, tokensUsed, false, err.Error())
		if errors.Is(err, ErrLLMUnavailable) {
			return "", len(tokensUsed), provider, err
		}
		return "", len(tokensUsed), provider, fmt.Errorf("%w: %v", ErrLLMUnavailable, err)
	}

	restored, err := s.restoreTokens(llmResponse)
	if err != nil {
		s.logProxy(actorID, ip, provider, tokensUsed, false, err.Error())
		return "", len(tokensUsed), provider, err
	}

	s.logProxy(actorID, ip, provider, tokensUsed, true, "")
	return restored, len(tokensUsed), provider, nil
}

func (s *Service) restoreTokens(text string) (string, error) {
	found := tokenPattern.FindAllString(text, -1)
	if len(found) == 0 {
		return text, nil
	}

	seen := make(map[string]string)
	out := text
	for _, token := range found {
		if _, ok := seen[token]; ok {
			continue
		}
		value, _, err := s.vault.Detokenize(token, internalDetokenizeRole)
		if err != nil {
			return "", fmt.Errorf("vault detokenize %s: %w", token, err)
		}
		seen[token] = value
		out = strings.ReplaceAll(out, token, value)
	}
	return out, nil
}

func (s *Service) logProxy(actorID, ip, provider string, tokens []string, success bool, reason string) {
	if s.audit == nil {
		return
	}
	tokenField := strings.Join(tokens, ",")
	s.audit.Log(actorID, "LLM_PROXY", tokenField, provider, fmt.Sprintf("%d", len(tokens)), ip, success, reason)
}

func resolveProvider(provider string) string {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider != "" {
		return provider
	}
	if env := strings.ToLower(os.Getenv("LLM_PROVIDER")); env != "" {
		return env
	}
	return "openai"
}
