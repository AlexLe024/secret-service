package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type apiClient struct {
	baseURL string
	token   string
	http    *http.Client
}

func newClient(baseURL, token string) *apiClient {
	return &apiClient{
		baseURL: baseURL,
		token:   token,
		http:    &http.Client{},
	}
}

func (c *apiClient) do(method, path string, body any) ([]byte, int, error) {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return nil, 0, err
		}
	}

	req, err := http.NewRequest(method, c.baseURL+path, &buf)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("ошибка подключения к серверу: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}

	return data, resp.StatusCode, nil
}

func (c *apiClient) get(path string) ([]byte, int, error) {
	return c.do(http.MethodGet, path, nil)
}

func (c *apiClient) post(path string, body any) ([]byte, int, error) {
	return c.do(http.MethodPost, path, body)
}

// parseError извлекает сообщение об ошибке из JSON ответа
func parseError(data []byte, status int) error {
	var errResp struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(data, &errResp) == nil && errResp.Error != "" {
		return fmt.Errorf("сервер вернул %d: %s", status, errResp.Error)
	}
	return fmt.Errorf("сервер вернул статус %d", status)
}
