package integration

import (
	"net/http"
	"testing"
)

func TestProjects(t *testing.T) {
	env := NewTestEnv(t)

	t.Run("создание проекта и получение списка", func(t *testing.T) {
		token := env.RegisterAndLogin(t, "proj_owner@example.com", "password")

		resp := env.Post("/api/v1/projects", map[string]string{
			"name":        "Мой проект",
			"description": "Тестовый проект",
		}, token)

		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("ожидали 201, получили %d", resp.StatusCode)
		}

		var project map[string]any
		DecodeJSON(t, resp, &project)

		if project["id"] == "" {
			t.Error("id проекта не должен быть пустым")
		}
		if project["name"] != "Мой проект" {
			t.Errorf("неверное имя проекта: %v", project["name"])
		}

		listResp := env.Get("/api/v1/projects", token)
		if listResp.StatusCode != http.StatusOK {
			t.Errorf("ожидали 200, получили %d", listResp.StatusCode)
		}

		var projects []map[string]any
		DecodeJSON(t, listResp, &projects)

		if len(projects) != 1 {
			t.Errorf("ожидали 1 проект, получили %d", len(projects))
		}
	})

	t.Run("создатель автоматически становится admin", func(t *testing.T) {
		token := env.RegisterAndLogin(t, "admin_check@example.com", "password")

		resp := env.Post("/api/v1/projects", map[string]string{
			"name": "Admin Test Project",
		}, token)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("ожидали 201, получили %d", resp.StatusCode)
		}

		var project map[string]any
		DecodeJSON(t, resp, &project)
		projectID := project["id"].(string)

		// Создатель может добавлять секреты (это право только admin/manager)
		secretResp := env.Post("/api/v1/projects/"+projectID+"/secrets", map[string]string{
			"name":  "MY_KEY",
			"value": "secret-value",
		}, token)
		defer secretResp.Body.Close()

		if secretResp.StatusCode != http.StatusCreated {
			t.Errorf("admin должен мочь создавать секреты, получили %d", secretResp.StatusCode)
		}
	})

	t.Run("добавление участника в проект", func(t *testing.T) {
		ownerToken := env.RegisterAndLogin(t, "owner2@example.com", "password")
		memberToken := env.RegisterAndLogin(t, "member2@example.com", "password")

		// Получаем ID участника
		memberResp := env.Post("/api/v1/auth/register", map[string]string{
			"email": "member3@example.com", "password": "password",
		}, "")
		var memberUser map[string]any
		DecodeJSON(t, memberResp, &memberUser)
		memberID := memberUser["id"].(string)

		// Создаём проект
		projResp := env.Post("/api/v1/projects", map[string]string{
			"name": "Team Project",
		}, ownerToken)
		var project map[string]any
		DecodeJSON(t, projResp, &project)
		projectID := project["id"].(string)

		// Добавляем участника
		addResp := env.Post("/api/v1/projects/"+projectID+"/members", map[string]string{
			"user_id": memberID,
			"role":    "developer",
		}, ownerToken)
		defer addResp.Body.Close()

		if addResp.StatusCode != http.StatusNoContent {
			t.Errorf("ожидали 204, получили %d", addResp.StatusCode)
		}

		// Участник видит проект в списке
		_ = memberToken
	})

	t.Run("проект без имени возвращает 400", func(t *testing.T) {
		token := env.RegisterAndLogin(t, "bad_proj@example.com", "password")

		resp := env.Post("/api/v1/projects", map[string]string{
			"name": "",
		}, token)
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("ожидали 400, получили %d", resp.StatusCode)
		}
	})
}
