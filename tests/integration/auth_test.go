package integration

import (
	"net/http"
	"testing"
)

func TestAuth_RegisterAndLogin(t *testing.T) {
	env := NewTestEnv(t)

	t.Run("успешная регистрация", func(t *testing.T) {
		resp := env.Post("/api/v1/auth/register", map[string]string{
			"email":    "user@example.com",
			"password": "password123",
		}, "")

		if resp.StatusCode != http.StatusCreated {
			t.Errorf("ожидали 201, получили %d", resp.StatusCode)
		}

		var result map[string]any
		DecodeJSON(t, resp, &result)

		if result["email"] != "user@example.com" {
			t.Errorf("неверный email в ответе: %v", result["email"])
		}
		if result["password_hash"] != nil {
			t.Error("password_hash не должен возвращаться в ответе")
		}
	})

	t.Run("дублирующийся email", func(t *testing.T) {
		env.Post("/api/v1/auth/register", map[string]string{
			"email": "dup@example.com", "password": "password",
		}, "").Body.Close()

		resp := env.Post("/api/v1/auth/register", map[string]string{
			"email": "dup@example.com", "password": "password",
		}, "")
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusConflict {
			t.Errorf("ожидали 409, получили %d", resp.StatusCode)
		}
	})

	t.Run("успешный логин возвращает токен", func(t *testing.T) {
		env.Post("/api/v1/auth/register", map[string]string{
			"email": "login@example.com", "password": "mypassword",
		}, "").Body.Close()

		resp := env.Post("/api/v1/auth/login", map[string]string{
			"email": "login@example.com", "password": "mypassword",
		}, "")

		if resp.StatusCode != http.StatusOK {
			t.Errorf("ожидали 200, получили %d", resp.StatusCode)
		}

		var result map[string]string
		DecodeJSON(t, resp, &result)

		if result["access_token"] == "" {
			t.Error("access_token не должен быть пустым")
		}
	})

	t.Run("неверный пароль", func(t *testing.T) {
		env.Post("/api/v1/auth/register", map[string]string{
			"email": "wrong@example.com", "password": "correctpw",
		}, "").Body.Close()

		resp := env.Post("/api/v1/auth/login", map[string]string{
			"email": "wrong@example.com", "password": "incorrect",
		}, "")
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("ожидали 401, получили %d", resp.StatusCode)
		}
	})

	t.Run("запрос без токена возвращает 401", func(t *testing.T) {
		resp := env.Get("/api/v1/projects", "")
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("ожидали 401, получили %d", resp.StatusCode)
		}
	})
}
