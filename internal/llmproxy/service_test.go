package llmproxy

import (
	"context"
	"errors"
	"testing"

	"github.com/anandudevops/aegis/internal/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockVault struct {
	tokenizeFn   func(fieldType, value, createdByID string) (*models.VaultRecord, error)
	detokenizeFn func(token, role string) (string, string, error)
}

func (m *mockVault) Tokenize(fieldType, value, createdByID string) (*models.VaultRecord, error) {
	return m.tokenizeFn(fieldType, value, createdByID)
}

func (m *mockVault) Detokenize(token, role string) (string, string, error) {
	return m.detokenizeFn(token, role)
}

type mockLLM struct {
	lastPrompt string
	response   string
	err        error
}

func (m *mockLLM) Chat(_ context.Context, _, prompt string) (string, error) {
	m.lastPrompt = prompt
	if m.err != nil {
		return "", m.err
	}
	return m.response, nil
}

func TestChat_TokenizesAndRestores(t *testing.T) {
	const token = "tok_11111111-1111-1111-1111-111111111111"

	vault := &mockVault{
		tokenizeFn: func(fieldType, value, _ string) (*models.VaultRecord, error) {
			assert.Equal(t, "email", fieldType)
			assert.Equal(t, "john@example.com", value)
			return &models.VaultRecord{Token: token, FieldType: fieldType}, nil
		},
		detokenizeFn: func(tok, role string) (string, string, error) {
			assert.Equal(t, token, tok)
			assert.Equal(t, internalDetokenizeRole, role)
			return "john@example.com", "FULL", nil
		},
	}

	llm := &mockLLM{
		response: "Contact " + token + " for help",
	}

	svc := &Service{vault: vault, client: llm}
	reply, count, provider, err := svc.Chat(
		context.Background(),
		uuid.New().String(),
		"127.0.0.1",
		"email john@example.com",
		"openai",
	)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Equal(t, "openai", provider)
	assert.Equal(t, "Contact john@example.com for help", reply)
	assert.NotContains(t, llm.lastPrompt, "john@example.com")
	assert.Contains(t, llm.lastPrompt, token)
}

func TestChat_NoPIIForwardsDirectly(t *testing.T) {
	llm := &mockLLM{response: "hello"}
	vault := &mockVault{
		tokenizeFn: func(string, string, string) (*models.VaultRecord, error) {
			return nil, errors.New("should not tokenize")
		},
	}

	svc := &Service{vault: vault, client: llm}
	reply, count, _, err := svc.Chat(context.Background(), uuid.New().String(), "127.0.0.1", "hello world", "openai")
	require.NoError(t, err)
	assert.Equal(t, 0, count)
	assert.Equal(t, "hello", reply)
	assert.Equal(t, "hello world", llm.lastPrompt)
}

func TestChat_VaultFailureAborts(t *testing.T) {
	vault := &mockVault{
		tokenizeFn: func(string, string, string) (*models.VaultRecord, error) {
			return nil, errors.New("vault down")
		},
	}
	svc := &Service{vault: vault, client: &mockLLM{}}
	_, _, _, err := svc.Chat(context.Background(), uuid.New().String(), "127.0.0.1", "email john@example.com", "openai")
	assert.Error(t, err)
}

func TestChat_LLMUnavailable(t *testing.T) {
	vault := &mockVault{
		tokenizeFn: func(fieldType, _, _ string) (*models.VaultRecord, error) {
			return &models.VaultRecord{Token: "tok_11111111-1111-1111-1111-111111111111", FieldType: fieldType}, nil
		},
	}
	llm := &mockLLM{err: ErrLLMUnavailable}
	svc := &Service{vault: vault, client: llm}
	_, _, _, err := svc.Chat(context.Background(), uuid.New().String(), "127.0.0.1", "email john@example.com", "openai")
	assert.ErrorIs(t, err, ErrLLMUnavailable)
}
