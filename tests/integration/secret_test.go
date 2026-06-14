package integration

import (
	"net/http"
	"testing"
)

func TestSecrets(t *testing.T) {
	env := NewTestEnv(t)

	// Вспомогательная функция: создать проект и вернуть его ID
	createProject := func(t *testing.T, token, name string) string {
		t.Helper()
		resp := env.Post("/api/v1/projects", map[string]string{"name": name}, token)
		var p map[string]any
		DecodeJSON(t, resp, &p)
		return p["id"].(string)
	}

	t.Run("создание и получение значения секрета", func(t *testing.T) {
		token := env.RegisterAndLogin(t, "secret_owner@example.com", "password")
		projectID := createProject(t, token, "Secret Project")

		// Создаём секрет
		resp := env.Post("/api/v1/projects/"+projectID+"/secrets", map[string]string{
			"name":        "API_KEY",
			"description": "Ключ внешнего API",
			"value":       "super-secret-value-123",
		}, token)

		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("ожидали 201, получили %d", resp.StatusCode)
		}

		var s map[string]any
		DecodeJSON(t, resp, &s)
		secretID := s["id"].(string)

		if s["name"] != "API_KEY" {
			t.Errorf("неверное имя секрета: %v", s["name"])
		}

		// Получаем значение
		valueResp := env.Get("/api/v1/secrets/"+secretID+"/value", token)
		if valueResp.StatusCode != http.StatusOK {
			t.Fatalf("ожидали 200, получили %d", valueResp.StatusCode)
		}

		var valueResult map[string]string
		DecodeJSON(t, valueResp, &valueResult)

		if valueResult["value"] != "super-secret-value-123" {
			t.Errorf("неверное значение секрета: %v", valueResult["value"])
		}
	})

	t.Run("список секретов не содержит значений", func(t *testing.T) {
		token := env.RegisterAndLogin(t, "list_secrets@example.com", "password")
		projectID := createProject(t, token, "List Project")

		env.Post("/api/v1/projects/"+projectID+"/secrets", map[string]string{
			"name": "DB_PASSWORD", "value": "db-pass-123",
		}, token).Body.Close()

		resp := env.Get("/api/v1/projects/"+projectID+"/secrets", token)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("ожидали 200, получили %d", resp.StatusCode)
		}

		var secrets []map[string]any
		DecodeJSON(t, resp, &secrets)

		if len(secrets) == 0 {
			t.Fatal("ожидали хотя бы один секрет")
		}

		// Значение не должно возвращаться в списке
		for _, sec := range secrets {
			if _, hasValue := sec["value"]; hasValue {
				t.Error("список секретов не должен содержать значения")
			}
		}
	})

	t.Run("ротация секрета", func(t *testing.T) {
		token := env.RegisterAndLogin(t, "rotate_user@example.com", "password")
		projectID := createProject(t, token, "Rotate Project")

		// Создаём секрет
		resp := env.Post("/api/v1/projects/"+projectID+"/secrets", map[string]string{
			"name": "ROTATE_KEY", "value": "old-value",
		}, token)
		var s map[string]any
		DecodeJSON(t, resp, &s)
		secretID := s["id"].(string)

		// Ротируем
		rotateResp := env.Post("/api/v1/secrets/"+secretID+"/rotate", map[string]string{
			"value": "new-value-after-rotation",
		}, token)
		defer rotateResp.Body.Close()

		if rotateResp.StatusCode != http.StatusNoContent {
			t.Fatalf("ожидали 204, получили %d", rotateResp.StatusCode)
		}

		// Проверяем новое значение
		valueResp := env.Get("/api/v1/secrets/"+secretID+"/value", token)
		var valueResult map[string]string
		DecodeJSON(t, valueResp, &valueResult)

		if valueResult["value"] != "new-value-after-rotation" {
			t.Errorf("после ротации ожидали новое значение, получили: %v", valueResult["value"])
		}
	})

	t.Run("отзыв секрета блокирует доступ к значению", func(t *testing.T) {
		token := env.RegisterAndLogin(t, "revoke_user@example.com", "password")
		projectID := createProject(t, token, "Revoke Project")

		resp := env.Post("/api/v1/projects/"+projectID+"/secrets", map[string]string{
			"name": "REVOKE_KEY", "value": "value-to-revoke",
		}, token)
		var s map[string]any
		DecodeJSON(t, resp, &s)
		secretID := s["id"].(string)

		// Отзываем
		revokeResp := env.Post("/api/v1/secrets/"+secretID+"/revoke", nil, token)
		defer revokeResp.Body.Close()

		if revokeResp.StatusCode != http.StatusNoContent {
			t.Fatalf("ожидали 204, получили %d", revokeResp.StatusCode)
		}

		// Попытка получить значение отозванного секрета
		valueResp := env.Get("/api/v1/secrets/"+secretID+"/value", token)
		defer valueResp.Body.Close()

		if valueResp.StatusCode != http.StatusGone {
			t.Errorf("ожидали 410 (Gone) для отозванного секрета, получили %d", valueResp.StatusCode)
		}
	})

	t.Run("developer не может создавать секреты", func(t *testing.T) {
		ownerToken := env.RegisterAndLogin(t, "owner_rbac@example.com", "password")
		projectID := createProject(t, ownerToken, "RBAC Project")

		// Регистрируем разработчика и получаем токен
		devToken := env.RegisterAndLogin(t, "dev_rbac_unique@example.com", "password")
		devID := userIDFromToken(t, devToken)

		// Добавляем как developer
		env.Post("/api/v1/projects/"+projectID+"/members", map[string]string{
			"user_id": devID, "role": "developer",
		}, ownerToken).Body.Close()

		// Developer пытается создать секрет — должен получить 403
		resp := env.Post("/api/v1/projects/"+projectID+"/secrets", map[string]string{
			"name": "FORBIDDEN_KEY", "value": "value",
		}, devToken)
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("ожидали 403, получили %d", resp.StatusCode)
		}
	})

	t.Run("выдача временного доступа другому пользователю", func(t *testing.T) {
		ownerToken := env.RegisterAndLogin(t, "grant_owner@example.com", "password")
		projectID := createProject(t, ownerToken, "Grant Project")

		// Создаём секрет
		resp := env.Post("/api/v1/projects/"+projectID+"/secrets", map[string]string{
			"name": "GRANT_KEY", "value": "granted-value",
		}, ownerToken)
		var s map[string]any
		DecodeJSON(t, resp, &s)
		secretID := s["id"].(string)

		// Регистрируем получателя доступа и получаем токен
		devToken := env.RegisterAndLogin(t, "grantee_unique@example.com", "password")
		devID := userIDFromToken(t, devToken)

		// Добавляем в проект как developer
		env.Post("/api/v1/projects/"+projectID+"/members", map[string]string{
			"user_id": devID, "role": "developer",
		}, ownerToken).Body.Close()

		// До выдачи доступа developer не может читать секрет
		beforeResp := env.Get("/api/v1/secrets/"+secretID+"/value", devToken)
		defer beforeResp.Body.Close()
		if beforeResp.StatusCode == http.StatusOK {
			t.Error("developer не должен читать секрет до выдачи доступа")
		}

		// Выдаём доступ
		grantResp := env.Post(
			"/api/v1/projects/"+projectID+"/secrets/"+secretID+"/grants",
			map[string]string{"user_id": devID},
			ownerToken,
		)
		defer grantResp.Body.Close()

		if grantResp.StatusCode != http.StatusNoContent {
			t.Fatalf("ожидали 204 при выдаче доступа, получили %d", grantResp.StatusCode)
		}

		// После выдачи — developer может читать
		afterResp := env.Get("/api/v1/secrets/"+secretID+"/value", devToken)
		if afterResp.StatusCode != http.StatusOK {
			t.Errorf("после выдачи доступа ожидали 200, получили %d", afterResp.StatusCode)
		}
		var result map[string]string
		DecodeJSON(t, afterResp, &result)
		if result["value"] != "granted-value" {
			t.Errorf("неверное значение: %v", result["value"])
		}
	})
}
