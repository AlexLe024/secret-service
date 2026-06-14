package commands

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

func newRunCmd() *cobra.Command {
	var projectID string
	var withSecrets bool

	cmd := &cobra.Command{
		Use:   "run -- <команда> [аргументы...]",
		Short: "Запустить команду с секретами в окружении",
		Long: `Запускает команду, подставляя секреты проекта в переменные окружения процесса.
Секреты существуют только в памяти и передаются дочернему процессу — на диск не пишутся.

Примеры:
  ss run --project <id> -- python app.py
  ss run --project <id> -- ./start.sh
  ss run --project <id> -- env | grep API`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if projectID == "" {
				return fmt.Errorf("укажите --project <id>")
			}

			session, err := requireSession()
			if err != nil {
				return err
			}

			client := newClient(session.BaseURL, session.Token)

			// Получаем список секретов (метаданные)
			listData, status, err := client.get("/api/v1/projects/" + projectID + "/secrets")
			if err != nil {
				return err
			}
			if status != http.StatusOK {
				return parseError(listData, status)
			}

			var secrets []struct {
				ID     string `json:"id"`
				Name   string `json:"name"`
				Status string `json:"status"`
			}
			if err := json.Unmarshal(listData, &secrets); err != nil {
				return err
			}

			// Фильтруем только активные
			var activeSecrets []struct {
				ID   string
				Name string
			}
			for _, s := range secrets {
				if s.Status == "active" {
					activeSecrets = append(activeSecrets, struct {
						ID   string
						Name string
					}{s.ID, s.Name})
				}
			}

			if len(activeSecrets) == 0 {
				fmt.Fprintln(os.Stderr, "⚠ В проекте нет активных секретов — запускаем без дополнительных переменных")
			}

			// Получаем значения секретов — всё в памяти
			secretEnv := make(map[string]string, len(activeSecrets))
			for _, s := range activeSecrets {
				valData, valStatus, err := client.get("/api/v1/secrets/" + s.ID + "/value")
				if err != nil {
					fmt.Fprintf(os.Stderr, "⚠ Не удалось получить %s: %v\n", s.Name, err)
					continue
				}
				if valStatus != http.StatusOK {
					fmt.Fprintf(os.Stderr, "⚠ Нет доступа к %s (статус %d)\n", s.Name, valStatus)
					continue
				}

				var resp struct {
					Value string `json:"value"`
				}
				if err := json.Unmarshal(valData, &resp); err != nil {
					continue
				}

				// Имя секрета используем как имя переменной окружения
				secretEnv[strings.ToUpper(s.Name)] = resp.Value
			}

			fmt.Fprintf(os.Stderr, "→ Загружено секретов: %d\n", len(secretEnv))

			// Запускаем команду
			command := exec.Command(args[0], args[1:]...)

			// Передаём текущее окружение + секреты
			// Секреты перезаписывают одноимённые переменные если они уже есть
			env := os.Environ()
			for k, v := range secretEnv {
				env = append(env, k+"="+v)
			}
			command.Env = env

			command.Stdin = os.Stdin
			command.Stdout = os.Stdout
			command.Stderr = os.Stderr

			if err := command.Run(); err != nil {
				// Передаём exit code дочернего процесса
				if exitErr, ok := err.(*exec.ExitError); ok {
					os.Exit(exitErr.ExitCode())
				}
				return err
			}

			// Явно зануляем секреты в памяти после использования
			for k := range secretEnv {
				secretEnv[k] = strings.Repeat("0", len(secretEnv[k]))
				delete(secretEnv, k)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&projectID, "project", "", "ID проекта")
	cmd.Flags().BoolVar(&withSecrets, "with-secrets", true, "Подставить секреты в окружение (по умолчанию: true)")
	return cmd
}
