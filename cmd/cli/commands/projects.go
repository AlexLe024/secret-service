package commands

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/spf13/cobra"
)

func newProjectsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "projects",
		Short: "Управление проектами",
	}

	cmd.AddCommand(
		newProjectsListCmd(),
		newProjectsCreateCmd(),
		newProjectsAddMemberCmd(),
	)

	return cmd
}

func newProjectsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Список доступных проектов",
		RunE: func(cmd *cobra.Command, args []string) error {
			session, err := requireSession()
			if err != nil {
				return err
			}

			client := newClient(session.BaseURL, session.Token)
			data, status, err := client.get("/api/v1/projects")
			if err != nil {
				return err
			}
			if status != http.StatusOK {
				return parseError(data, status)
			}

			var projects []struct {
				ID          string `json:"id"`
				Name        string `json:"name"`
				Description string `json:"description"`
			}
			if err := json.Unmarshal(data, &projects); err != nil {
				return err
			}

			if len(projects) == 0 {
				fmt.Println("Проектов нет. Создайте первый: ss projects create --name <название>")
				return nil
			}

			fmt.Printf("%-36s  %-20s  %s\n", "ID", "Название", "Описание")
			fmt.Println("--------------------------------------------------------------------------------")
			for _, p := range projects {
				desc := p.Description
				if len(desc) > 30 {
					desc = desc[:27] + "..."
				}
				fmt.Printf("%-36s  %-20s  %s\n", p.ID, p.Name, desc)
			}
			return nil
		},
	}
}

func newProjectsCreateCmd() *cobra.Command {
	var name, description string

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Создать новый проект",
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" {
				return fmt.Errorf("укажите название: --name <название>")
			}

			session, err := requireSession()
			if err != nil {
				return err
			}

			client := newClient(session.BaseURL, session.Token)
			data, status, err := client.post("/api/v1/projects", map[string]string{
				"name":        name,
				"description": description,
			})
			if err != nil {
				return err
			}
			if status != http.StatusCreated {
				return parseError(data, status)
			}

			var project struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			}
			if err := json.Unmarshal(data, &project); err != nil {
				return err
			}

			fmt.Printf("✓ Проект создан\n")
			fmt.Printf("  ID:       %s\n", project.ID)
			fmt.Printf("  Название: %s\n", project.Name)
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Название проекта")
	cmd.Flags().StringVar(&description, "description", "", "Описание проекта")
	return cmd
}

func newProjectsAddMemberCmd() *cobra.Command {
	var projectID, userID, role string

	cmd := &cobra.Command{
		Use:   "add-member",
		Short: "Добавить участника в проект",
		Long:  `Добавляет пользователя в проект с ролью admin/manager/developer.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if projectID == "" || userID == "" || role == "" {
				return fmt.Errorf("укажите --project, --user и --role (admin/manager/developer)")
			}

			session, err := requireSession()
			if err != nil {
				return err
			}

			client := newClient(session.BaseURL, session.Token)
			data, status, err := client.post("/api/v1/projects/"+projectID+"/members", map[string]string{
				"user_id": userID,
				"role":    role,
			})
			if err != nil {
				return err
			}
			if status != http.StatusNoContent {
				return parseError(data, status)
			}

			fmt.Printf("✓ Пользователь %s добавлен в проект с ролью %s\n", userID, role)
			return nil
		},
	}

	cmd.Flags().StringVar(&projectID, "project", "", "ID проекта")
	cmd.Flags().StringVar(&userID, "user", "", "ID пользователя")
	cmd.Flags().StringVar(&role, "role", "developer", "Роль: admin / manager / developer")
	return cmd
}
