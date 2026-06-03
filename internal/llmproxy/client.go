package llmproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

var ErrLLMUnavailable = errors.New("LLM provider unavailable")

type LLMClient interface {
	Chat(ctx context.Context, provider, prompt string) (string, error)
}

type HTTPClient struct {
	httpClient *http.Client
}

func NewHTTPClient() *HTTPClient {
	return &HTTPClient{
		httpClient: &http.Client{Timeout: 60 * time.Second},
	}
}

func (c *HTTPClient) Chat(ctx context.Context, _, prompt string) (string, error) {
	return c.chatOpenAI(ctx, prompt)
}

func (c *HTTPClient) chatOpenAI(ctx context.Context, prompt string) (string, error) {
	apiKey := os.Getenv("LLM_API_KEY")
	if apiKey == "" {
		return "", fmt.Errorf("LLM_API_KEY not configured")
	}

	model := os.Getenv("LLM_MODEL")
	if model == "" {
		model = "gpt-4o"
	}

	body, _ := json.Marshal(map[string]any{
		"model": model,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.openai.com/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrLLMUnavailable, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("%w: read response: %v", ErrLLMUnavailable, err)
	}
	if resp.StatusCode >= 500 {
		return "", fmt.Errorf("%w: openai status %d", ErrLLMUnavailable, resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("openai error %d: %s", resp.StatusCode, string(respBody))
	}

	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return "", fmt.Errorf("%w: parse response: %v", ErrLLMUnavailable, err)
	}
	if len(parsed.Choices) == 0 {
		return "", fmt.Errorf("%w: empty openai response", ErrLLMUnavailable)
	}
	return parsed.Choices[0].Message.Content, nil
}
