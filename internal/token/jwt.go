package token

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	tokenTTL   = 24 * time.Hour
	saTokenTTL = 1 * time.Hour

	SubjectUser           = "user"
	SubjectServiceAccount = "service_account"

	// tokenIssuer/tokenAudience scope tokens to this service so a token minted
	// for/by a different system is not accepted here.
	tokenIssuer   = "secret-service"
	tokenAudience = "secret-service"
)

type Claims struct {
	UserID    string `json:"user_id"`
	Subject   string `json:"sub_type"`
	IsAdmin   bool   `json:"is_admin,omitempty"`
	ProjectID string `json:"project_id,omitempty"`
	jwt.RegisteredClaims
}

type JWTProvider struct {
	secret []byte
}

func NewJWTProvider(secret string) *JWTProvider {
	return &JWTProvider{secret: []byte(secret)}
}

// Generate — токен для обычного пользователя
func (p *JWTProvider) Generate(userID string) (string, error) {
	return p.GenerateWithClaims(userID, false)
}

// GenerateWithClaims — токен с флагом is_admin
func (p *JWTProvider) GenerateWithClaims(userID string, isAdmin bool) (string, error) {
	claims := Claims{
		UserID:  userID,
		Subject: SubjectUser,
		IsAdmin: isAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    tokenIssuer,
			Audience:  jwt.ClaimStrings{tokenAudience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tokenTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(p.secret)
}

// GenerateForSA — токен для сервисного аккаунта (короткий TTL, привязан к проекту)
func (p *JWTProvider) GenerateForSA(saID, projectID string) (string, error) {
	claims := Claims{
		UserID:    saID,
		Subject:   SubjectServiceAccount,
		ProjectID: projectID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    tokenIssuer,
			Audience:  jwt.ClaimStrings{tokenAudience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(saTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(p.secret)
}

// Parse — парсит токен и возвращает userID
func (p *JWTProvider) Parse(tokenStr string) (string, error) {
	claims, err := p.parseClaims(tokenStr)
	if err != nil {
		return "", err
	}
	return claims.UserID, nil
}

// ParseClaims — полный парсинг с доступом ко всем полям
func (p *JWTProvider) ParseClaims(tokenStr string) (*Claims, error) {
	return p.parseClaims(tokenStr)
}

func (p *JWTProvider) parseClaims(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("token: unexpected signing method")
		}
		return p.secret, nil
	},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuer(tokenIssuer),
		jwt.WithAudience(tokenAudience),
	)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("token: invalid token")
	}

	return claims, nil
}
