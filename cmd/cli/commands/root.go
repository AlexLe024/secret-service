package commands

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var defaultBaseURL = "http://localhost:8080"

func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "ss",
		Short: "Secret Service CLI — управление API-ключами команды",
		Long: `ss — CLI-клиент для сервиса централизованного хранения секретов.

Примеры:
  ss login
  ss projects list
  ss secrets list --project <id>
  ss secrets get --project <id> --name MY_KEY
  ss run --project <id> -- ./start.sh`,
	}

	root.AddCommand(
		newRegisterCmd(),
		newLoginCmd(),
		newLogoutCmd(),
		newWhoamiCmd(),
		newProjectsCmd(),
		newSecretsCmd(),
		newRunCmd(),
	)

	return root
}

func newRegisterCmd() *cobra.Command {
	var serverURL, email, password string
	var autoLogin bool

	cmd := &cobra.Command{
		Use:   "register",
		Short: "Зарегистрировать нового пользователя",
		RunE: func(cmd *cobra.Command, args []string) error {
			if email == "" {
				fmt.Print("Email: ")
				fmt.Scanln(&email)
			}
			if password == "" {
				fmt.Print("Пароль: ")
				p, err := readPassword()
				if err != nil {
					return err
				}
				password = p
				fmt.Println()
			}

			client := newClient(serverURL, "")
			data, status, err := client.post("/api/v1/auth/register", map[string]string{
				"email":    email,
				"password": password,
			})
			if err != nil {
				return err
			}
			if status != http.StatusCreated {
				return parseError(data, status)
			}

			var user struct {
				ID    string `json:"id"`
				Email string `json:"email"`
			}
			if err := json.Unmarshal(data, &user); err != nil {
				return err
			}

			fmt.Println("✓ Пользователь зарегистрирован")
			fmt.Printf("  ID:    %s\n", user.ID)
			fmt.Printf("  Email: %s\n", user.Email)

			if !autoLogin {
				return nil
			}

			loginData, loginStatus, err := client.post("/api/v1/auth/login", map[string]string{
				"email":    email,
				"password": password,
			})
			if err != nil {
				return err
			}
			if loginStatus != http.StatusOK {
				return parseError(loginData, loginStatus)
			}
			var resp struct {
				AccessToken string `json:"access_token"`
			}
			if err := json.Unmarshal(loginData, &resp); err != nil {
				return err
			}
			if err := saveSession(Session{Token: resp.AccessToken, BaseURL: serverURL}); err != nil {
				return fmt.Errorf("не удалось сохранить сессию: %w", err)
			}
			fmt.Println("✓ Вход выполнен — JWT-токен сохранён")
			return nil
		},
	}

	cmd.Flags().StringVar(&serverURL, "server", defaultBaseURL, "URL сервера")
	cmd.Flags().StringVar(&email, "email", "", "Email (если не указан — спросит интерактивно)")
	cmd.Flags().StringVar(&password, "password", "", "Пароль (если не указан — спросит интерактивно)")
	cmd.Flags().BoolVar(&autoLogin, "login", true, "Автоматически войти после регистрации")
	return cmd
}

func newLoginCmd() *cobra.Command {
	var serverURL string

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Войти в систему",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Print("Email: ")
			var email string
			fmt.Scanln(&email)

			fmt.Print("Пароль: ")
			// Читаем пароль без вывода на экран
			password, err := readPassword()
			if err != nil {
				return err
			}
			fmt.Println()

			client := newClient(serverURL, "")
			data, status, err := client.post("/api/v1/auth/login", map[string]string{
				"email":    email,
				"password": password,
			})
			if err != nil {
				return err
			}
			if status != http.StatusOK {
				return parseError(data, status)
			}

			var resp struct {
				AccessToken string `json:"access_token"`
			}
			if err := json.Unmarshal(data, &resp); err != nil {
				return err
			}

			if err := saveSession(Session{
				Token:   resp.AccessToken,
				BaseURL: serverURL,
			}); err != nil {
				return fmt.Errorf("не удалось сохранить сессию: %w", err)
			}

			fmt.Println("✓ Вход выполнен успешно")
			return nil
		},
	}

	cmd.Flags().StringVar(&serverURL, "server", defaultBaseURL, "URL сервера")
	return cmd
}

func newLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Выйти из системы",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := deleteSession(); err != nil {
				return err
			}
			fmt.Println("✓ Сессия завершена")
			return nil
		},
	}
}

func newWhoamiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Показать текущего пользователя",
		RunE: func(cmd *cobra.Command, args []string) error {
			session, err := requireSession()
			if err != nil {
				return err
			}

			client := newClient(session.BaseURL, session.Token)
			data, status, err := client.get("/api/v1/auth/me")
			if err != nil {
				return err
			}
			if status != http.StatusOK {
				return parseError(data, status)
			}

			var user struct {
				ID          string `json:"id"`
				Email       string `json:"email"`
				DisplayName string `json:"display_name"`
				IsBlocked   bool   `json:"is_blocked"`
			}
			if err := json.Unmarshal(data, &user); err != nil {
				return err
			}

			fmt.Printf("ID:    %s\n", user.ID)
			fmt.Printf("Email: %s\n", user.Email)
			if user.DisplayName != "" && user.DisplayName != user.Email {
				fmt.Printf("Имя:   %s\n", user.DisplayName)
			}
			if user.IsBlocked {
				fmt.Println("Статус: ⛔ заблокирован")
			} else {
				fmt.Println("Статус: ✓ активен")
			}
			return nil
		},
	}
}

// readPassword reads a password from stdin without echoing characters.
func readPassword() (string, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		bytes, err := term.ReadPassword(fd)
		if err != nil {
			return "", err
		}
		return string(bytes), nil
	}
	// Fallback for non-terminal input (pipes, tests)
	var password string
	fmt.Scanln(&password)
	return password, nil
}

// printJSON выводит JSON в читаемом виде
func printJSON(data []byte) {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		fmt.Println(string(data))
		return
	}
	pretty, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Println(string(data))
		return
	}
	fmt.Println(string(pretty))
}

// tableRow выводит строку таблицы
func tableRow(cols ...string) {
	for i, c := range cols {
		if i > 0 {
			fmt.Print("  ")
		}
		fmt.Printf("%-40s", c)
	}
	fmt.Println()
}

func exitWithError(msg string) {
	fmt.Fprintln(os.Stderr, "Ошибка: "+msg)
	os.Exit(1)
}
