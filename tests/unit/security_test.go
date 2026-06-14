package crypto_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/time/rate"

	"secret-service/internal/auth"
	"secret-service/internal/domain"
	"secret-service/internal/dto"
	"secret-service/internal/middleware"
	"secret-service/internal/token"
)

const testSecret = "test-secret-key-for-unit-tests!!"

// --- #11: JWT must require exp and validate issuer/audience -------------------

func signClaims(t *testing.T, c token.Claims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString([]byte(testSecret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func TestJWT_RequiresExpAndIssuerAudience(t *testing.T) {
	provider := token.NewJWTProvider(testSecret)

	t.Run("SA-токен несёт тип и проект", func(t *testing.T) {
		tok, err := provider.GenerateForSA("sa-1", "proj-1")
		if err != nil {
			t.Fatal(err)
		}
		claims, err := provider.ParseClaims(tok)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if claims.Subject != token.SubjectServiceAccount {
			t.Errorf("ожидали subject service_account, получили %q", claims.Subject)
		}
		if claims.ProjectID != "proj-1" {
			t.Errorf("ожидали project proj-1, получили %q", claims.ProjectID)
		}
	})

	t.Run("токен без exp отклоняется", func(t *testing.T) {
		tok := signClaims(t, token.Claims{
			UserID:  "u",
			Subject: token.SubjectUser,
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:   "secret-service",
				Audience: jwt.ClaimStrings{"secret-service"},
			},
		})
		if _, err := provider.ParseClaims(tok); err == nil {
			t.Error("токен без exp должен отклоняться")
		}
	})

	t.Run("чужой issuer отклоняется", func(t *testing.T) {
		tok := signClaims(t, token.Claims{
			UserID: "u",
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "evil",
				Audience:  jwt.ClaimStrings{"secret-service"},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
		})
		if _, err := provider.ParseClaims(tok); err == nil {
			t.Error("токен с чужим issuer должен отклоняться")
		}
	})

	t.Run("чужой audience отклоняется", func(t *testing.T) {
		tok := signClaims(t, token.Claims{
			UserID: "u",
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "secret-service",
				Audience:  jwt.ClaimStrings{"someone-else"},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
		})
		if _, err := provider.ParseClaims(tok); err == nil {
			t.Error("токен с чужим audience должен отклоняться")
		}
	})
}

// --- #4: password length validation -----------------------------------------

func TestValidatePassword(t *testing.T) {
	cases := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"слишком короткий", "short", true},
		{"минимально допустимый", "12345678", false},
		{"нормальный", "correct horse battery", false},
		{"слишком длинный (>72)", strings.Repeat("a", 73), true},
		{"пустой", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := auth.ValidatePassword(c.password)
			if (err != nil) != c.wantErr {
				t.Errorf("ValidatePassword(%q) err=%v, ожидали ошибку=%v", c.password, err, c.wantErr)
			}
		})
	}
}

// --- #6: pagination caps limit and offset -----------------------------------

func TestParsePage_Caps(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/?limit=99999&offset=99999999", nil)
	p := dto.ParsePage(r)
	if p.Limit != 200 {
		t.Errorf("ожидали limit=200 (cap), получили %d", p.Limit)
	}
	if p.Offset != 100000 {
		t.Errorf("ожидали offset=100000 (cap), получили %d", p.Offset)
	}
}

// --- #2: middleware distinguishes user vs service-account principals ----------

type fakeParser struct{ claims *token.Claims }

func (f fakeParser) ParseClaims(string) (*token.Claims, error) { return f.claims, nil }

func runAuth(claims *token.Claims) (gotUserOK, gotPrincipalOK bool, gotType domain.PrincipalType) {
	h := middleware.Auth(fakeParser{claims: claims}, nil)(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_, gotUserOK = middleware.GetUserID(r)
			var p domain.Principal
			p, gotPrincipalOK = middleware.GetPrincipal(r)
			gotType = p.Type
		}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer x")
	h.ServeHTTP(httptest.NewRecorder(), req)
	return
}

func TestAuthMiddleware_PrincipalType(t *testing.T) {
	t.Run("пользовательский токен — GetUserID работает", func(t *testing.T) {
		userOK, princOK, typ := runAuth(&token.Claims{UserID: "u1", Subject: token.SubjectUser})
		if !userOK {
			t.Error("для пользователя GetUserID должен возвращать ok=true")
		}
		if !princOK || typ != domain.PrincipalUser {
			t.Errorf("ожидали principal user, получили ok=%v type=%v", princOK, typ)
		}
	})

	t.Run("SA-токен НЕ принимается как пользователь", func(t *testing.T) {
		userOK, princOK, typ := runAuth(&token.Claims{UserID: "sa1", Subject: token.SubjectServiceAccount, ProjectID: "p1"})
		if userOK {
			t.Error("SA-токен не должен проходить как пользователь (GetUserID ok=false)")
		}
		if !princOK || typ != domain.PrincipalServiceAccount {
			t.Errorf("ожидали principal service_account, получили ok=%v type=%v", princOK, typ)
		}
	})
}

// --- #8: rate limiter keys on the right client identity ----------------------

func sendRL(h http.Handler, remoteAddr, xff string) int {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteAddr
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestRateLimiter_TrustProxy(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	t.Run("trustProxy=true: бакеты по X-Forwarded-For", func(t *testing.T) {
		h := middleware.NewRateLimiter(rate.Limit(0.0001), 1, true).Limit(ok)
		if code := sendRL(h, "10.0.0.1:1111", "1.1.1.1"); code != http.StatusOK {
			t.Fatalf("первый запрос клиента 1.1.1.1 должен пройти, got %d", code)
		}
		if code := sendRL(h, "10.0.0.1:2222", "2.2.2.2"); code != http.StatusOK {
			t.Fatalf("другой клиент 2.2.2.2 должен пройти (отдельный бакет), got %d", code)
		}
		if code := sendRL(h, "10.0.0.1:3333", "1.1.1.1"); code != http.StatusTooManyRequests {
			t.Fatalf("повторный запрос 1.1.1.1 должен быть ограничен (429), got %d", code)
		}
	})

	t.Run("trustProxy=false: X-Forwarded-For игнорируется", func(t *testing.T) {
		h := middleware.NewRateLimiter(rate.Limit(0.0001), 1, false).Limit(ok)
		if code := sendRL(h, "10.0.0.9:1111", "1.1.1.1"); code != http.StatusOK {
			t.Fatalf("первый запрос должен пройти, got %d", code)
		}
		// Тот же RemoteAddr, другой XFF — XFF не должен давать новый бакет.
		if code := sendRL(h, "10.0.0.9:2222", "2.2.2.2"); code != http.StatusTooManyRequests {
			t.Fatalf("спуфинг X-Forwarded-For не должен обходить лимит (ожидали 429), got %d", code)
		}
	})
}
