package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"

	"marketplace/internal/api"
)

const (
	ctxUserIDKey    = "user_id"
	ctxRoleKey      = "role"
	ctxRequestIDKey = "request_id"
)

var promoCodePattern = regexp.MustCompile(`^[A-Z0-9_]{4,20}$`)

type Config struct {
	Port                  string
	DatabaseDSN           string
	AccessTokenSecret     string
	RefreshTokenSecret    string
	AccessTokenTTLMinutes int
	RefreshTokenTTLDays   int
	OrderRateLimitMinutes int
}

type Server struct {
	db  *sql.DB
	cfg Config
}

type Claims struct {
	Role api.Role `json:"role"`
	jwt.RegisteredClaims
	UserID int64 `json:"user_id"`
}

type fieldViolation struct {
	Field     string `json:"field"`
	Violation string `json:"violation"`
}

type logRecord struct {
	DurationMs int64  `json:"duration_ms"`
	Endpoint   string `json:"endpoint"`
	Method     string `json:"method"`
	RequestID  string `json:"request_id"`
	StatusCode int    `json:"status_code"`
	Timestamp  string `json:"timestamp"`
	UserID     *int64 `json:"user_id"`
	Body       any    `json:"request_body,omitempty"`
}

func LoadConfig() Config {
	cfg := Config{
		Port:                  getEnv("PORT", "8000"),
		DatabaseDSN:           getEnv("DB_DSN", "postgres://postgres:postgres@localhost:5432/marketplace?sslmode=disable"),
		AccessTokenSecret:     getEnv("JWT_ACCESS_SECRET", "change-me-access"),
		RefreshTokenSecret:    getEnv("JWT_REFRESH_SECRET", "change-me-refresh"),
		AccessTokenTTLMinutes: getEnvAsInt("JWT_ACCESS_TTL_MINUTES", 20),
		RefreshTokenTTLDays:   getEnvAsInt("JWT_REFRESH_TTL_DAYS", 14),
		OrderRateLimitMinutes: getEnvAsInt("ORDER_RATE_LIMIT_MINUTES", 5),
	}
	return cfg
}

func ConnectDB(ctx context.Context, dsn string) (*sql.DB, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if err = db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping db: %w", err)
	}
	return db, nil
}

func NewServer(db *sql.DB, cfg Config) *Server {
	return &Server{db: db, cfg: cfg}
}

func (s *Server) Router() *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(s.requestIDMiddleware())
	r.Use(s.loggingMiddleware())
	r.Use(s.authMiddleware())

	api.RegisterHandlers(r, s)
	return r
}

func (s *Server) requestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-Id")
		if requestID == "" {
			requestID = uuid.NewString()
		}
		c.Set(ctxRequestIDKey, requestID)
		c.Header("X-Request-Id", requestID)
		c.Next()
	}
}

func (s *Server) loggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		startedAt := time.Now().UTC()
		var requestBody any

		if methodNeedsBodyLog(c.Request.Method) {
			raw, _ := io.ReadAll(c.Request.Body)
			_ = c.Request.Body.Close()
			c.Request.Body = io.NopCloser(bytes.NewReader(raw))
			requestBody = sanitizeRequestBody(raw)
		}

		c.Next()

		requestID, _ := c.Get(ctxRequestIDKey)
		var userID *int64
		if id, ok := c.Get(ctxUserIDKey); ok {
			if parsed, okCast := id.(int64); okCast {
				userID = &parsed
			}
		}

		record := logRecord{
			RequestID:  fmt.Sprintf("%v", requestID),
			Method:     c.Request.Method,
			Endpoint:   c.Request.URL.Path,
			StatusCode: c.Writer.Status(),
			DurationMs: time.Since(startedAt).Milliseconds(),
			UserID:     userID,
			Timestamp:  startedAt.Format(time.RFC3339),
			Body:       requestBody,
		}
		payload, _ := json.Marshal(record)
		log.Println(string(payload))
	}
}

func (s *Server) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if isPublicRoute(c.Request.Method, c.Request.URL.Path) {
			c.Next()
			return
		}

		header := strings.TrimSpace(c.GetHeader("Authorization"))
		if header == "" || !strings.HasPrefix(strings.ToLower(header), "bearer ") {
			s.writeError(c, http.StatusUnauthorized, api.ErrorCodeTOKENINVALID, "Access token is required", nil)
			c.Abort()
			return
		}

		parts := strings.SplitN(header, " ", 2)
		tokenString := ""
		if len(parts) == 2 {
			tokenString = strings.TrimSpace(parts[1])
		}
		if tokenString == "" {
			s.writeError(c, http.StatusUnauthorized, api.ErrorCodeTOKENINVALID, "Access token is required", nil)
			c.Abort()
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return []byte(s.cfg.AccessTokenSecret), nil
		})
		if err != nil {
			if errors.Is(err, jwt.ErrTokenExpired) {
				s.writeError(c, http.StatusUnauthorized, api.ErrorCodeTOKENEXPIRED, "Access token expired", nil)
			} else {
				s.writeError(c, http.StatusUnauthorized, api.ErrorCodeTOKENINVALID, "Access token invalid", nil)
			}
			c.Abort()
			return
		}
		if !token.Valid || claims.UserID == 0 || claims.Role == "" {
			s.writeError(c, http.StatusUnauthorized, api.ErrorCodeTOKENINVALID, "Access token invalid", nil)
			c.Abort()
			return
		}

		c.Set(ctxUserIDKey, claims.UserID)
		c.Set(ctxRoleKey, claims.Role)
		c.Next()
	}
}

func sanitizeRequestBody(raw []byte) any {
	if len(raw) == 0 {
		return nil
	}
	var payload any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return string(raw)
	}
	maskSecrets(payload)
	return payload
}

func maskSecrets(v any) {
	switch typed := v.(type) {
	case map[string]any:
		for key, value := range typed {
			lower := strings.ToLower(key)
			if strings.Contains(lower, "password") || strings.Contains(lower, "secret") {
				typed[key] = "***"
				continue
			}
			maskSecrets(value)
		}
	case []any:
		for _, item := range typed {
			maskSecrets(item)
		}
	}
}

func methodNeedsBodyLog(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodDelete:
		return true
	default:
		return false
	}
}

func isPublicRoute(method, path string) bool {
	if method == http.MethodGet && path == "/health" {
		return true
	}
	return strings.HasPrefix(path, "/auth/")
}

func (s *Server) currentUser(c *gin.Context) (int64, api.Role, bool) {
	rawID, okID := c.Get(ctxUserIDKey)
	rawRole, okRole := c.Get(ctxRoleKey)
	if !okID || !okRole {
		return 0, "", false
	}
	id, ok := rawID.(int64)
	if !ok {
		return 0, "", false
	}
	role, ok := rawRole.(api.Role)
	if !ok {
		roleStr, okStr := rawRole.(string)
		if !okStr {
			return 0, "", false
		}
		role = api.Role(roleStr)
	}
	return id, role, true
}

func (s *Server) requireRole(c *gin.Context, allowed ...api.Role) bool {
	_, role, ok := s.currentUser(c)
	if !ok {
		s.writeError(c, http.StatusUnauthorized, api.ErrorCodeTOKENINVALID, "Access token invalid", nil)
		return false
	}
	for _, candidate := range allowed {
		if role == candidate {
			return true
		}
	}
	s.writeError(c, http.StatusForbidden, api.ErrorCodeACCESSDENIED, "Access denied", nil)
	return false
}

func (s *Server) writeError(c *gin.Context, status int, code api.ErrorCode, message string, details map[string]any) {
	resp := api.ErrorResponse{
		ErrorCode: code,
		Message:   message,
		Details:   details,
	}
	if len(details) == 0 {
		resp.Details = nil
	}
	c.JSON(status, resp)
}

func (s *Server) writeValidationError(c *gin.Context, violations []fieldViolation) {
	fields := make([]map[string]string, 0, len(violations))
	for _, v := range violations {
		fields = append(fields, map[string]string{
			"field":     v.Field,
			"violation": v.Violation,
		})
	}
	s.writeError(c, http.StatusBadRequest, api.ErrorCodeVALIDATIONERROR, "Validation failed", map[string]any{"fields": fields})
}

func getEnv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func getEnvAsInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func hashPassword(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}

func comparePassword(hash string, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func hashToken(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

func (s *Server) generateTokens(userID int64, role api.Role) (api.AuthTokensResponse, error) {
	now := time.Now().UTC()
	accessExpires := now.Add(time.Duration(s.cfg.AccessTokenTTLMinutes) * time.Minute)
	refreshExpires := now.Add(time.Duration(s.cfg.RefreshTokenTTLDays) * 24 * time.Hour)

	accessClaims := Claims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   fmt.Sprintf("%d", userID),
			ExpiresAt: jwt.NewNumericDate(accessExpires),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
	}
	access := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessToken, err := access.SignedString([]byte(s.cfg.AccessTokenSecret))
	if err != nil {
		return api.AuthTokensResponse{}, fmt.Errorf("sign access token: %w", err)
	}

	refreshClaims := Claims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   fmt.Sprintf("%d", userID),
			ExpiresAt: jwt.NewNumericDate(refreshExpires),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
	}
	refresh := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshToken, err := refresh.SignedString([]byte(s.cfg.RefreshTokenSecret))
	if err != nil {
		return api.AuthTokensResponse{}, fmt.Errorf("sign refresh token: %w", err)
	}

	return api.AuthTokensResponse{
		TokenType:        "Bearer",
		AccessToken:      accessToken,
		RefreshToken:     refreshToken,
		AccessExpiresAt:  accessExpires,
		RefreshExpiresAt: refreshExpires,
	}, nil
}

func validateRole(value api.Role) bool {
	switch value {
	case api.RoleUSER, api.RoleSELLER, api.RoleADMIN:
		return true
	default:
		return false
	}
}

func validateProductStatus(value api.ProductStatus) bool {
	switch value {
	case api.ProductStatusACTIVE, api.ProductStatusINACTIVE, api.ProductStatusARCHIVED:
		return true
	default:
		return false
	}
}

func validateOrderStatus(value api.OrderStatus) bool {
	switch value {
	case api.OrderStatusCREATED, api.OrderStatusPAYMENTPENDING, api.OrderStatusPAID, api.OrderStatusSHIPPED, api.OrderStatusCOMPLETED, api.OrderStatusCANCELED:
		return true
	default:
		return false
	}
}

func validateDiscountType(value api.DiscountType) bool {
	switch value {
	case api.DiscountTypePERCENTAGE, api.DiscountTypeFIXEDAMOUNT:
		return true
	default:
		return false
	}
}

func jwtParse(tokenString, secret string, claims *Claims) (*jwt.Token, error) {
	return jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(secret), nil
	})
}
