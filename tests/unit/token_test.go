package crypto_test

import (
	"testing"

	"secret-service/internal/token"
)

func TestJWTProvider(t *testing.T) {
	provider := token.NewJWTProvider("test-secret-key-for-unit-tests!!")

	t.Run("генерация и парсинг токена", func(t *testing.T) {
		userID := "user-123"

		tok, err := provider.Generate(userID)
		if err != nil {
			t.Fatalf("генерация токена: %v", err)
		}
		if tok == "" {
			t.Fatal("токен не должен быть пустым")
		}

		parsedID, err := provider.Parse(tok)
		if err != nil {
			t.Fatalf("парсинг токена: %v", err)
		}
		if parsedID != userID {
			t.Errorf("ожидали userID %q, получили %q", userID, parsedID)
		}
	})

	t.Run("неверная подпись", func(t *testing.T) {
		otherProvider := token.NewJWTProvider("other-secret-key-!!!!!!!!!!!!!")

		tok, _ := otherProvider.Generate("user-456")

		_, err := provider.Parse(tok)
		if err == nil {
			t.Error("токен с другой подписью должен отклоняться")
		}
	})

	t.Run("повреждённый токен", func(t *testing.T) {
		_, err := provider.Parse("this.is.not.a.valid.jwt")
		if err == nil {
			t.Error("невалидный токен должен возвращать ошибку")
		}
	})

	t.Run("пустой токен", func(t *testing.T) {
		_, err := provider.Parse("")
		if err == nil {
			t.Error("пустой токен должен возвращать ошибку")
		}
	})
}
