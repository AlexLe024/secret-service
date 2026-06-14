package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

const configDir = ".secret-service"
const sessionFile = "session.json"

type Session struct {
	Token     string `json:"token"`
	ServerURL string `json:"server_url"`
}

func configPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, configDir, sessionFile), nil
}

func saveSession(s Session) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	dir := filepath.Join(home, configDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	path := filepath.Join(dir, sessionFile)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	return json.NewEncoder(f).Encode(s)
}

func loadSession() (Session, error) {
	path, err := configPath()
	if err != nil {
		return Session{}, err
	}

	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Session{}, errors.New("не авторизован — выполните: secret-service login")
		}
		return Session{}, err
	}
	defer f.Close()

	var s Session
	if err := json.NewDecoder(f).Decode(&s); err != nil {
		return Session{}, err
	}
	return s, nil
}

func deleteSession() error {
	path, err := configPath()
	if err != nil {
		return err
	}
	return os.Remove(path)
}
