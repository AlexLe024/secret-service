package commands

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/spf13/cobra"
)

func newSecretsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secrets",
		Short: "Управление секретами",
	}

	cmd.AddCommand(
		newSecretsListCmd(),
		newSecretsGetCmd(),
		newSecretsCreateCmd(),
		newSecretsRevokeCmd(),
		newSecretsRotateCmd(),
		newSecretsRollbackCmd(),
		newSecretsVersionsCmd(),
		newSecretsGrantCmd(),
	)

	return cmd
}

func newSecretsListCmd() *cobra.Command {
	var projectID string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "Список секретов проекта (без значений)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if projectID == "" {
				return fmt.Errorf("укажите проект: --project <id>")
			}

			session, err := requireSession()
			if err != nil {
				return err
			}

			client := newClient(session.BaseURL, session.Token)
			data, status, err := client.get("/api/v1/projects/" + projectID + "/secrets")
			if err != nil {
				return err
			}
			if status != http.StatusOK {
				return parseError(data, status)
			}

			var secrets []struct {
				ID          string `json:"id"`
				Name        string `json:"name"`
				Description string `json:"description"`
				Status      string `json:"status"`
			}
			if err := json.Unmarshal(data, &secrets); err != nil {
				return err
			}

			if len(secrets) == 0 {
				fmt.Println("Секретов нет.")
				return nil
			}

			fmt.Printf("%-36s  %-25s  %-8s  %s\n", "ID", "Название", "Статус", "Описание")
			fmt.Println("-------------------------------------------------------------------------------------")
			for _, s := range secrets {
				status := "✓ active"
				if s.Status == "revoked" {
					status = "⛔ revoked"
				}
				desc := s.Description
				if len(desc) > 25 {
					desc = desc[:22] + "..."
				}
				fmt.Printf("%-36s  %-25s  %-8s  %s\n", s.ID, s.Name, status, desc)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&projectID, "project", "", "ID проекта")
	return cmd
}

func newSecretsGetCmd() *cobra.Command {
	var projectID, secretID, secretName string

	cmd := &cobra.Command{
		Use:   "get",
		Short: "Получить значение секрета",
		Long: `Получить значение секрета. Доступ фиксируется в журнале аудита.
Значение выводится только в stdout и не сохраняется на диск.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			session, err := requireSession()
			if err != nil {
				return err
			}

			client := newClient(session.BaseURL, session.Token)

			// Если указан ID напрямую
			if secretID != "" {
				return printSecretValue(client, secretID)
			}

			// Поиск по имени в проекте
			if projectID == "" || secretName == "" {
				return fmt.Errorf("укажите --secret <id> или --project <id> --name <название>")
			}

			// Получаем список секретов и ищем по имени
			data, status, err := client.get("/api/v1/projects/" + projectID + "/secrets")
			if err != nil {
				return err
			}
			if status != http.StatusOK {
				return parseError(data, status)
			}

			var secrets []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			}
			if err := json.Unmarshal(data, &secrets); err != nil {
				return err
			}

			for _, s := range secrets {
				if s.Name == secretName {
					return printSecretValue(client, s.ID)
				}
			}

			return fmt.Errorf("секрет '%s' не найден в проекте", secretName)
		},
	}

	cmd.Flags().StringVar(&secretID, "secret", "", "ID секрета")
	cmd.Flags().StringVar(&projectID, "project", "", "ID проекта")
	cmd.Flags().StringVar(&secretName, "name", "", "Название секрета")
	return cmd
}

func printSecretValue(client *apiClient, secretID string) error {
	data, status, err := client.get("/api/v1/secrets/" + secretID + "/value")
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return parseError(data, status)
	}

	var resp struct {
		SecretID string `json:"secret_id"`
		Value    string `json:"value"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return err
	}

	// Выводим только значение — без лишних символов
	// чтобы можно было использовать в скриптах: VALUE=$(ss secrets get --secret <id>)
	fmt.Print(resp.Value)
	return nil
}

func newSecretsCreateCmd() *cobra.Command {
	var projectID, name, description, value, environment string
	var tags []string

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Создать новый секрет",
		RunE: func(cmd *cobra.Command, args []string) error {
			if projectID == "" || name == "" {
				return fmt.Errorf("укажите --project <id> и --name <название>")
			}

			if value == "" {
				fmt.Print("Значение секрета: ")
				var readErr error
				value, readErr = readPassword()
				if readErr != nil {
					return fmt.Errorf("ошибка чтения значения: %w", readErr)
				}
				fmt.Println()
			}

			session, err := requireSession()
			if err != nil {
				return err
			}

			body := map[string]any{
				"name":        name,
				"description": description,
				"value":       value,
			}
			if environment != "" {
				body["environment"] = environment
			}
			if len(tags) > 0 {
				body["tags"] = tags
			}

			client := newClient(session.BaseURL, session.Token)
			data, status, err := client.post("/api/v1/projects/"+projectID+"/secrets", body)
			if err != nil {
				return err
			}
			if status != http.StatusCreated {
				return parseError(data, status)
			}

			var secret struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			}
			if err := json.Unmarshal(data, &secret); err != nil {
				return err
			}

			fmt.Printf("✓ Секрет создан\n")
			fmt.Printf("  ID:       %s\n", secret.ID)
			fmt.Printf("  Название: %s\n", secret.Name)
			return nil
		},
	}

	cmd.Flags().StringVar(&projectID, "project", "", "ID проекта")
	cmd.Flags().StringVar(&name, "name", "", "Название секрета")
	cmd.Flags().StringVar(&description, "description", "", "Описание")
	cmd.Flags().StringVar(&value, "value", "", "Значение (если не указано — запросит интерактивно)")
	cmd.Flags().StringVar(&environment, "environment", "", "Окружение (production/staging/development)")
	cmd.Flags().StringSliceVar(&tags, "tags", nil, "Теги через запятую, например: --tags payment,external")
	return cmd
}

func newSecretsRevokeCmd() *cobra.Command {
	var secretID string

	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Отозвать секрет",
		RunE: func(cmd *cobra.Command, args []string) error {
			if secretID == "" {
				return fmt.Errorf("укажите --secret <id>")
			}

			session, err := requireSession()
			if err != nil {
				return err
			}

			client := newClient(session.BaseURL, session.Token)
			data, status, err := client.post("/api/v1/secrets/"+secretID+"/revoke", nil)
			if err != nil {
				return err
			}
			if status != http.StatusNoContent {
				return parseError(data, status)
			}

			fmt.Printf("✓ Секрет %s отозван\n", secretID)
			return nil
		},
	}

	cmd.Flags().StringVar(&secretID, "secret", "", "ID секрета")
	return cmd
}

func newSecretsRotateCmd() *cobra.Command {
	var secretID, newValue string

	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "Ротировать секрет (задать новое значение)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if secretID == "" {
				return fmt.Errorf("укажите --secret <id>")
			}

			if newValue == "" {
				fmt.Print("Новое значение: ")
				var readErr error
				newValue, readErr = readPassword()
				if readErr != nil {
					return fmt.Errorf("ошибка чтения значения: %w", readErr)
				}
				fmt.Println()
			}

			session, err := requireSession()
			if err != nil {
				return err
			}

			client := newClient(session.BaseURL, session.Token)
			data, status, err := client.post("/api/v1/secrets/"+secretID+"/rotate", map[string]string{
				"value": newValue,
			})
			if err != nil {
				return err
			}
			if status != http.StatusNoContent {
				return parseError(data, status)
			}

			fmt.Printf("✓ Секрет %s ротирован\n", secretID)
			return nil
		},
	}

	cmd.Flags().StringVar(&secretID, "secret", "", "ID секрета")
	cmd.Flags().StringVar(&newValue, "value", "", "Новое значение")
	return cmd
}

func newSecretsVersionsCmd() *cobra.Command {
	var secretID string

	cmd := &cobra.Command{
		Use:   "versions",
		Short: "История версий секрета",
		RunE: func(cmd *cobra.Command, args []string) error {
			if secretID == "" {
				return fmt.Errorf("укажите --secret <id>")
			}

			session, err := requireSession()
			if err != nil {
				return err
			}

			client := newClient(session.BaseURL, session.Token)
			data, status, err := client.get("/api/v1/secrets/" + secretID + "/versions")
			if err != nil {
				return err
			}
			if status != http.StatusOK {
				return parseError(data, status)
			}

			var versions []struct {
				Version   int    `json:"version"`
				IsCurrent bool   `json:"is_current"`
				CreatedBy string `json:"created_by"`
				CreatedAt string `json:"created_at"`
			}
			if err := json.Unmarshal(data, &versions); err != nil {
				return err
			}

			fmt.Printf("%-8s  %-10s  %-36s  %s\n", "VERSION", "CURRENT", "CREATED_BY", "CREATED_AT")
			fmt.Println("---------------------------------------------------------------------------------")
			for _, v := range versions {
				current := ""
				if v.IsCurrent {
					current = "✓"
				}
				fmt.Printf("v%-7d  %-10s  %-36s  %s\n", v.Version, current, v.CreatedBy, v.CreatedAt)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&secretID, "secret", "", "ID секрета")
	return cmd
}

func newSecretsRollbackCmd() *cobra.Command {
	var secretID string
	var version int

	cmd := &cobra.Command{
		Use:   "rollback",
		Short: "Откатить секрет к предыдущей версии",
		RunE: func(cmd *cobra.Command, args []string) error {
			if secretID == "" || version < 1 {
				return fmt.Errorf("укажите --secret <id> и --version <N>")
			}

			session, err := requireSession()
			if err != nil {
				return err
			}

			client := newClient(session.BaseURL, session.Token)
			data, status, err := client.post(
				"/api/v1/secrets/"+secretID+"/rollback",
				map[string]int{"version": version},
			)
			if err != nil {
				return err
			}
			if status != http.StatusNoContent {
				return parseError(data, status)
			}

			fmt.Printf("✓ Секрет %s откачен к версии %d\n", secretID, version)
			return nil
		},
	}

	cmd.Flags().StringVar(&secretID, "secret", "", "ID секрета")
	cmd.Flags().IntVar(&version, "version", 0, "Номер версии для отката")
	return cmd
}

func newSecretsGrantCmd() *cobra.Command {
	var projectID, secretID, userID, expiresIn string

	cmd := &cobra.Command{
		Use:   "grant",
		Short: "Выдать пользователю грант на чтение секрета",
		Long: `Выдает разработчику доступ к конкретному секрету.
Срок действия задается через --expires-in (например, 168h, 24h, 30m).
Без --expires-in грант бессрочный.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if projectID == "" || secretID == "" || userID == "" {
				return fmt.Errorf("укажите --project, --secret и --user")
			}

			body := map[string]any{"user_id": userID}
			if expiresIn != "" {
				dur, err := time.ParseDuration(expiresIn)
				if err != nil {
					return fmt.Errorf("неверный формат --expires-in: %w (примеры: 168h, 24h, 30m)", err)
				}
				body["expires_at"] = time.Now().UTC().Add(dur).Format(time.RFC3339)
			}

			session, err := requireSession()
			if err != nil {
				return err
			}

			client := newClient(session.BaseURL, session.Token)
			data, status, err := client.post(
				"/api/v1/projects/"+projectID+"/secrets/"+secretID+"/grants",
				body,
			)
			if err != nil {
				return err
			}
			if status != http.StatusNoContent {
				return parseError(data, status)
			}

			if expiresIn != "" {
				fmt.Printf("✓ Грант выдан пользователю %s на %s (срок: %s)\n", userID, secretID, expiresIn)
			} else {
				fmt.Printf("✓ Грант выдан пользователю %s на %s (бессрочно)\n", userID, secretID)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&projectID, "project", "", "ID проекта")
	cmd.Flags().StringVar(&secretID, "secret", "", "ID секрета")
	cmd.Flags().StringVar(&userID, "user", "", "ID пользователя, которому выдается грант")
	cmd.Flags().StringVar(&expiresIn, "expires-in", "", "Срок действия (например, 168h, 24h, 30m)")
	return cmd
}
