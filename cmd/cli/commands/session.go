package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Session struct {
	Token   string `json:"token"`
	BaseURL string `json:"base_url"`
}

func sessionPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".config", "secret-service")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "session.json"), nil
}

func saveSession(s Session) error {
	path, err := sessionPath()
	if err != nil {
		return err
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func loadSession() (*Session, error) {
	path, err := sessionPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("не авторизован — выполните 'ss login'")
		}
		return nil, err
	}
	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func deleteSession() error {
	path, err := sessionPath()
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func requireSession() (*Session, error) {
	s, err := loadSession()
	if err != nil {
		return nil, err
	}
	if s.Token == "" {
		return nil, fmt.Errorf("не авторизован — выполните 'ss login'")
	}
	return s, nil
}
