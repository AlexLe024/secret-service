package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

func newClient(baseURL, token string) *Client {
	return &Client{
		baseURL: baseURL,
		token:   token,
		http:    &http.Client{},
	}
}

func (c *Client) post(path string, body any) (map[string]any, error) {
	return c.request(http.MethodPost, path, body)
}

func (c *Client) get(path string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ошибка соединения с сервером: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		var errResp map[string]string
		_ = json.Unmarshal(data, &errResp)
		if msg, ok := errResp["error"]; ok {
			return nil, fmt.Errorf("ошибка сервера (%d): %s", resp.StatusCode, msg)
		}
		return nil, fmt.Errorf("ошибка сервера: %d", resp.StatusCode)
	}

	return data, nil
}

func (c *Client) request(method, path string, body any) (map[string]any, error) {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequest(method, c.baseURL+path, &buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ошибка соединения с сервером: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		var errResp map[string]string
		_ = json.Unmarshal(data, &errResp)
		if msg, ok := errResp["error"]; ok {
			return nil, fmt.Errorf("ошибка (%d): %s", resp.StatusCode, msg)
		}
		return nil, fmt.Errorf("ошибка сервера: %d", resp.StatusCode)
	}

	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}
