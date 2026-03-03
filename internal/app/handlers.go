package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lib/pq"

	"marketplace/internal/api"
)

func (s *Server) HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, api.HealthResponse{
		Status:    "ok",
		Service:   "marketplace-service",
		Timestamp: time.Now().UTC(),
	})
}

func (s *Server) RegisterUser(c *gin.Context) {
	var req api.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		s.writeValidationError(c, []fieldViolation{{Field: "body", Violation: "invalid JSON"}})
		return
	}

	violations := validateRegisterRequest(req)
	if len(violations) > 0 {
		s.writeValidationError(c, violations)
		return
	}

	passwordHash, err := hashPassword(req.Password)
	if err != nil {
		s.writeError(c, http.StatusInternalServerError, api.TOKENINVALID, "Failed to process password", nil)
		return
	}

	const query = `
		INSERT INTO users (email, password_hash, role)
		VALUES ($1, $2, $3)
		RETURNING id, email, role, created_at, updated_at`

	var resp api.UserResponse
	err = s.db.QueryRowContext(c.Request.Context(), query, strings.ToLower(string(req.Email)), passwordHash, req.Role).
		Scan(&resp.Id, &resp.Email, &resp.Role, &resp.CreatedAt, &resp.UpdatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			s.writeValidationError(c, []fieldViolation{{Field: "email", Violation: "already exists"}})
			return
		}
		s.writeError(c, http.StatusInternalServerError, api.TOKENINVALID, "Failed to register user", nil)
		return
	}

	c.JSON(http.StatusCreated, resp)
}

func (s *Server) LoginUser(c *gin.Context) {
	var req api.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		s.writeValidationError(c, []fieldViolation{{Field: "body", Violation: "invalid JSON"}})
		return
	}

	violations := validateLoginRequest(req)
	if len(violations) > 0 {
		s.writeValidationError(c, violations)
		return
	}

	const query = `SELECT id, password_hash, role FROM users WHERE email = $1`
	var (
		userID       int64
		passwordHash string
		role         api.Role
	)
	if err := s.db.QueryRowContext(c.Request.Context(), query, strings.ToLower(string(req.Email))).Scan(&userID, &passwordHash, &role); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.writeError(c, http.StatusUnauthorized, api.TOKENINVALID, "Invalid credentials", nil)
			return
		}
		s.writeError(c, http.StatusInternalServerError, api.TOKENINVALID, "Failed to login", nil)
		return
	}

	if err := comparePassword(passwordHash, req.Password); err != nil {
		s.writeError(c, http.StatusUnauthorized, api.TOKENINVALID, "Invalid credentials", nil)
		return
	}

	tokens, err := s.generateTokens(userID, role)
	if err != nil {
		s.writeError(c, http.StatusInternalServerError, api.TOKENINVALID, "Failed to generate token", nil)
		return
	}

	if err := s.saveRefreshToken(c, userID, tokens.RefreshToken, tokens.RefreshExpiresAt); err != nil {
		s.writeError(c, http.StatusInternalServerError, api.TOKENINVALID, "Failed to save refresh token", nil)
		return
	}

	c.JSON(http.StatusOK, tokens)
}

func (s *Server) RefreshToken(c *gin.Context) {
	var req api.RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		s.writeValidationError(c, []fieldViolation{{Field: "body", Violation: "invalid JSON"}})
		return
	}

	violations := validateRefreshRequest(req)
	if len(violations) > 0 {
		s.writeValidationError(c, violations)
		return
	}

	claims := &Claims{}
	token, err := jwtParse(req.RefreshToken, s.cfg.RefreshTokenSecret, claims)
	if err != nil || !token.Valid {
		s.writeError(c, http.StatusUnauthorized, api.REFRESHTOKENINVALID, "Refresh token invalid", nil)
		return
	}

	const findToken = `
		SELECT user_id, expires_at, revoked
		FROM refresh_tokens
		WHERE token_hash = $1`
	var (
		userID    int64
		expiresAt time.Time
		revoked   bool
	)
	err = s.db.QueryRowContext(c.Request.Context(), findToken, hashToken(req.RefreshToken)).Scan(&userID, &expiresAt, &revoked)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.writeError(c, http.StatusUnauthorized, api.REFRESHTOKENINVALID, "Refresh token invalid", nil)
			return
		}
		s.writeError(c, http.StatusInternalServerError, api.REFRESHTOKENINVALID, "Failed to refresh token", nil)
		return
	}
	if revoked || expiresAt.Before(time.Now().UTC()) || userID != claims.UserID {
		s.writeError(c, http.StatusUnauthorized, api.REFRESHTOKENINVALID, "Refresh token invalid", nil)
		return
	}

	var role api.Role
	if err = s.db.QueryRowContext(c.Request.Context(), `SELECT role FROM users WHERE id = $1`, userID).Scan(&role); err != nil {
		s.writeError(c, http.StatusUnauthorized, api.REFRESHTOKENINVALID, "Refresh token invalid", nil)
		return
	}

	tokens, err := s.generateTokens(userID, role)
	if err != nil {
		s.writeError(c, http.StatusInternalServerError, api.REFRESHTOKENINVALID, "Failed to generate token", nil)
		return
	}

	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		s.writeError(c, http.StatusInternalServerError, api.REFRESHTOKENINVALID, "Failed to refresh token", nil)
		return
	}
	defer func() { _ = tx.Rollback() }()

	if _, err = tx.ExecContext(c.Request.Context(), `UPDATE refresh_tokens SET revoked = TRUE WHERE token_hash = $1`, hashToken(req.RefreshToken)); err != nil {
		s.writeError(c, http.StatusInternalServerError, api.REFRESHTOKENINVALID, "Failed to refresh token", nil)
		return
	}

	if _, err = tx.ExecContext(c.Request.Context(), `INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`, userID, hashToken(tokens.RefreshToken), tokens.RefreshExpiresAt); err != nil {
		s.writeError(c, http.StatusInternalServerError, api.REFRESHTOKENINVALID, "Failed to refresh token", nil)
		return
	}

	if err = tx.Commit(); err != nil {
		s.writeError(c, http.StatusInternalServerError, api.REFRESHTOKENINVALID, "Failed to refresh token", nil)
		return
	}

	c.JSON(http.StatusOK, tokens)
}

func (s *Server) ListProducts(c *gin.Context, params api.ListProductsParams) {
	if !s.requireRole(c, api.USER, api.SELLER, api.ADMIN) {
		return
	}

	page := 0
	size := 20
	if params.Page != nil {
		page = *params.Page
	}
	if params.Size != nil {
		size = *params.Size
	}

	violations := make([]fieldViolation, 0)
	if page < 0 {
		violations = append(violations, fieldViolation{Field: "page", Violation: "must be >= 0"})
	}
	if size < 1 || size > 100 {
		violations = append(violations, fieldViolation{Field: "size", Violation: "must be between 1 and 100"})
	}
	if params.Category != nil {
		if len(strings.TrimSpace(*params.Category)) < 1 || len(strings.TrimSpace(*params.Category)) > 100 {
			violations = append(violations, fieldViolation{Field: "category", Violation: "length must be between 1 and 100"})
		}
	}
	if params.Status != nil && !validateProductStatus(*params.Status) {
		violations = append(violations, fieldViolation{Field: "status", Violation: "invalid enum value"})
	}
	if len(violations) > 0 {
		s.writeValidationError(c, violations)
		return
	}

	filters := []string{"1=1"}
	args := []any{}

	if params.Status != nil {
		args = append(args, string(*params.Status))
		filters = append(filters, fmt.Sprintf("status = $%d", len(args)))
	}
	if params.Category != nil {
		args = append(args, strings.TrimSpace(*params.Category))
		filters = append(filters, fmt.Sprintf("category = $%d", len(args)))
	}

	whereClause := strings.Join(filters, " AND ")
	countQuery := "SELECT COUNT(*) FROM products WHERE " + whereClause
	var total int64
	if err := s.db.QueryRowContext(c.Request.Context(), countQuery, args...).Scan(&total); err != nil {
		s.writeError(c, http.StatusInternalServerError, api.PRODUCTNOTFOUND, "Failed to list products", nil)
		return
	}

	args = append(args, size, page*size)
	selectQuery := fmt.Sprintf(`
		SELECT id, name, description, price, stock, category, status, seller_id, created_at, updated_at
		FROM products
		WHERE %s
		ORDER BY id
		LIMIT $%d OFFSET $%d`, whereClause, len(args)-1, len(args))

	rows, err := s.db.QueryContext(c.Request.Context(), selectQuery, args...)
	if err != nil {
		s.writeError(c, http.StatusInternalServerError, api.PRODUCTNOTFOUND, "Failed to list products", nil)
		return
	}
	defer rows.Close()

	items := make([]api.ProductResponse, 0)
	for rows.Next() {
		product, scanErr := scanProduct(rows)
		if scanErr != nil {
			s.writeError(c, http.StatusInternalServerError, api.PRODUCTNOTFOUND, "Failed to list products", nil)
			return
		}
		items = append(items, product)
	}

	c.JSON(http.StatusOK, api.ProductListResponse{
		Items:         items,
		TotalElements: total,
		Page:          page,
		Size:          size,
	})
}

func (s *Server) CreateProduct(c *gin.Context) {
	if !s.requireRole(c, api.SELLER, api.ADMIN) {
		return
	}

	var req api.ProductCreate
	if err := c.ShouldBindJSON(&req); err != nil {
		s.writeValidationError(c, []fieldViolation{{Field: "body", Violation: "invalid JSON"}})
		return
	}
	if violations := validateProductCreate(req); len(violations) > 0 {
		s.writeValidationError(c, violations)
		return
	}

	userID, role, ok := s.currentUser(c)
	if !ok {
		s.writeError(c, http.StatusUnauthorized, api.TOKENINVALID, "Access token invalid", nil)
		return
	}

	sellerID := userID
	if role == api.SELLER {
		if req.SellerId != nil && *req.SellerId != userID {
			s.writeError(c, http.StatusForbidden, api.ACCESSDENIED, "Seller can create only own products", nil)
			return
		}
	} else if req.SellerId != nil {
		sellerID = *req.SellerId
	}

	const query = `
		INSERT INTO products (name, description, price, stock, category, status, seller_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, name, description, price, stock, category, status, seller_id, created_at, updated_at`
	var desc any
	if req.Description != nil {
		desc = strings.TrimSpace(*req.Description)
	}
	var resp api.ProductResponse
	err := s.db.QueryRowContext(
		c.Request.Context(),
		query,
		strings.TrimSpace(req.Name),
		desc,
		req.Price,
		req.Stock,
		strings.TrimSpace(req.Category),
		string(req.Status),
		sellerID,
	).Scan(
		&resp.Id,
		&resp.Name,
		&resp.Description,
		&resp.Price,
		&resp.Stock,
		&resp.Category,
		&resp.Status,
		&resp.SellerId,
		&resp.CreatedAt,
		&resp.UpdatedAt,
	)
	if err != nil {
		s.writeError(c, http.StatusInternalServerError, api.PRODUCTNOTFOUND, "Failed to create product", nil)
		return
	}

	c.JSON(http.StatusCreated, resp)
}

func (s *Server) GetProductById(c *gin.Context, id int64) {
	if !s.requireRole(c, api.USER, api.SELLER, api.ADMIN) {
		return
	}
	product, err := s.getProduct(c, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.writeError(c, http.StatusNotFound, api.PRODUCTNOTFOUND, "Product not found", nil)
			return
		}
		s.writeError(c, http.StatusInternalServerError, api.PRODUCTNOTFOUND, "Failed to get product", nil)
		return
	}
	c.JSON(http.StatusOK, product)
}

func (s *Server) UpdateProductById(c *gin.Context, id int64) {
	if !s.requireRole(c, api.SELLER, api.ADMIN) {
		return
	}

	var req api.ProductUpdate
	if err := c.ShouldBindJSON(&req); err != nil {
		s.writeValidationError(c, []fieldViolation{{Field: "body", Violation: "invalid JSON"}})
		return
	}
	if violations := validateProductUpdate(req); len(violations) > 0 {
		s.writeValidationError(c, violations)
		return
	}

	userID, role, _ := s.currentUser(c)
	current, err := s.getProduct(c, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.writeError(c, http.StatusNotFound, api.PRODUCTNOTFOUND, "Product not found", nil)
			return
		}
		s.writeError(c, http.StatusInternalServerError, api.PRODUCTNOTFOUND, "Failed to update product", nil)
		return
	}
	if role == api.SELLER && current.SellerId != userID {
		s.writeError(c, http.StatusForbidden, api.ACCESSDENIED, "Seller can update only own products", nil)
		return
	}

	setParts := make([]string, 0)
	args := make([]any, 0)

	if req.Name != nil {
		args = append(args, strings.TrimSpace(*req.Name))
		setParts = append(setParts, fmt.Sprintf("name = $%d", len(args)))
	}
	if req.Description != nil {
		args = append(args, strings.TrimSpace(*req.Description))
		setParts = append(setParts, fmt.Sprintf("description = $%d", len(args)))
	}
	if req.Price != nil {
		args = append(args, *req.Price)
		setParts = append(setParts, fmt.Sprintf("price = $%d", len(args)))
	}
	if req.Stock != nil {
		args = append(args, *req.Stock)
		setParts = append(setParts, fmt.Sprintf("stock = $%d", len(args)))
	}
	if req.Category != nil {
		args = append(args, strings.TrimSpace(*req.Category))
		setParts = append(setParts, fmt.Sprintf("category = $%d", len(args)))
	}
	if req.Status != nil {
		args = append(args, string(*req.Status))
		setParts = append(setParts, fmt.Sprintf("status = $%d", len(args)))
	}
	if len(setParts) == 0 {
		s.writeValidationError(c, []fieldViolation{{Field: "body", Violation: "at least one field must be provided"}})
		return
	}

	args = append(args, id)
	query := fmt.Sprintf(`
		UPDATE products
		SET %s
		WHERE id = $%d
		RETURNING id, name, description, price, stock, category, status, seller_id, created_at, updated_at`, strings.Join(setParts, ", "), len(args))

	var resp api.ProductResponse
	err = s.db.QueryRowContext(c.Request.Context(), query, args...).Scan(
		&resp.Id,
		&resp.Name,
		&resp.Description,
		&resp.Price,
		&resp.Stock,
		&resp.Category,
		&resp.Status,
		&resp.SellerId,
		&resp.CreatedAt,
		&resp.UpdatedAt,
	)
	if err != nil {
		s.writeError(c, http.StatusInternalServerError, api.PRODUCTNOTFOUND, "Failed to update product", nil)
		return
	}

	c.JSON(http.StatusOK, resp)
}

func (s *Server) ArchiveProductById(c *gin.Context, id int64) {
	if !s.requireRole(c, api.SELLER, api.ADMIN) {
		return
	}

	userID, role, _ := s.currentUser(c)
	current, err := s.getProduct(c, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.writeError(c, http.StatusNotFound, api.PRODUCTNOTFOUND, "Product not found", nil)
			return
		}
		s.writeError(c, http.StatusInternalServerError, api.PRODUCTNOTFOUND, "Failed to archive product", nil)
		return
	}
	if role == api.SELLER && current.SellerId != userID {
		s.writeError(c, http.StatusForbidden, api.ACCESSDENIED, "Seller can archive only own products", nil)
		return
	}

	const query = `
		UPDATE products
		SET status = 'ARCHIVED'
		WHERE id = $1
		RETURNING id, name, description, price, stock, category, status, seller_id, created_at, updated_at`

	var resp api.ProductResponse
	err = s.db.QueryRowContext(c.Request.Context(), query, id).Scan(
		&resp.Id,
		&resp.Name,
		&resp.Description,
		&resp.Price,
		&resp.Stock,
		&resp.Category,
		&resp.Status,
		&resp.SellerId,
		&resp.CreatedAt,
		&resp.UpdatedAt,
	)
	if err != nil {
		s.writeError(c, http.StatusInternalServerError, api.PRODUCTNOTFOUND, "Failed to archive product", nil)
		return
	}

	c.JSON(http.StatusOK, resp)
}

func (s *Server) CreateOrder(c *gin.Context) {
	if !s.requireRole(c, api.USER, api.ADMIN) {
		return
	}

	userID, role, _ := s.currentUser(c)
	if role == api.SELLER {
		s.writeError(c, http.StatusForbidden, api.ACCESSDENIED, "SELLER cannot create orders", nil)
		return
	}

	var req api.OrderCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		s.writeValidationError(c, []fieldViolation{{Field: "body", Violation: "invalid JSON"}})
		return
	}
	if violations := validateOrderCreate(req); len(violations) > 0 {
		s.writeValidationError(c, violations)
		return
	}

	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to create order", nil)
		return
	}
	defer func() { _ = tx.Rollback() }()

	if err = s.checkUserOperationRateLimit(c, tx, userID, "CREATE_ORDER"); err != nil {
		return
	}
	if hasActive, checkErr := s.hasActiveOrder(c, tx, userID); checkErr != nil {
		s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to create order", nil)
		return
	} else if hasActive {
		s.writeError(c, http.StatusConflict, api.ORDERHASACTIVE, "User already has active order", nil)
		return
	}

	normalized := normalizeOrderItems(req.Items)
	productIDs := sortedProductIDs(normalized)
	products, err := s.lockProducts(c, tx, productIDs)
	if err != nil {
		s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to create order", nil)
		return
	}

	if missingID, ok := findMissingProductID(products, productIDs); ok {
		s.writeError(c, http.StatusNotFound, api.PRODUCTNOTFOUND, fmt.Sprintf("Product %d not found", missingID), nil)
		return
	}
	if inactiveID, ok := findInactiveProductID(products, productIDs); ok {
		s.writeError(c, http.StatusConflict, api.PRODUCTINACTIVE, fmt.Sprintf("Product %d is inactive", inactiveID), nil)
		return
	}

	if details, insufficient := findInsufficientStock(products, normalized); insufficient {
		s.writeError(c, http.StatusConflict, api.INSUFFICIENTSTOCK, "Insufficient stock for one or more products", map[string]any{"products": details})
		return
	}

	subtotal := calculateSubtotal(products, normalized)
	promoID, discount, total, promoErr := s.applyPromoCodeOnCreate(c, tx, req.PromoCode, subtotal)
	if promoErr != nil {
		return
	}
	if promoID == nil {
		total = subtotal
	}

	const insertOrder = `
		INSERT INTO orders (user_id, status, promo_code_id, total_amount, discount_amount)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id`
	var orderID int64
	err = tx.QueryRowContext(c.Request.Context(), insertOrder, userID, string(api.CREATED), promoID, total, discount).Scan(&orderID)
	if err != nil {
		s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to create order", nil)
		return
	}

	for productID, quantity := range normalized {
		product := products[productID]
		if _, execErr := tx.ExecContext(
			c.Request.Context(),
			`INSERT INTO order_items (order_id, product_id, quantity, price_at_order) VALUES ($1, $2, $3, $4)`,
			orderID,
			productID,
			quantity,
			product.Price,
		); execErr != nil {
			s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to create order", nil)
			return
		}

		if _, execErr := tx.ExecContext(c.Request.Context(), `UPDATE products SET stock = stock - $1 WHERE id = $2`, quantity, productID); execErr != nil {
			s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to create order", nil)
			return
		}
	}

	if _, err = tx.ExecContext(c.Request.Context(), `INSERT INTO user_operations (user_id, operation_type) VALUES ($1, 'CREATE_ORDER')`, userID); err != nil {
		s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to create order", nil)
		return
	}

	if err = tx.Commit(); err != nil {
		s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to create order", nil)
		return
	}

	order, err := s.loadOrderResponse(c.Request.Context(), s.db, orderID)
	if err != nil {
		s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to create order", nil)
		return
	}
	c.JSON(http.StatusCreated, order)
}

func (s *Server) GetOrderById(c *gin.Context, id int64) {
	if !s.requireRole(c, api.USER, api.ADMIN) {
		return
	}

	userID, role, _ := s.currentUser(c)
	if role == api.SELLER {
		s.writeError(c, http.StatusForbidden, api.ACCESSDENIED, "SELLER cannot access orders", nil)
		return
	}

	order, err := s.loadOrderResponse(c.Request.Context(), s.db, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.writeError(c, http.StatusNotFound, api.ORDERNOTFOUND, "Order not found", nil)
			return
		}
		s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to load order", nil)
		return
	}

	if role == api.USER && order.UserId != userID {
		s.writeError(c, http.StatusForbidden, api.ORDEROWNERSHIPVIOLATION, "Order belongs to another user", nil)
		return
	}

	c.JSON(http.StatusOK, order)
}

func (s *Server) UpdateOrderById(c *gin.Context, id int64) {
	if !s.requireRole(c, api.USER, api.ADMIN) {
		return
	}

	userID, role, _ := s.currentUser(c)
	if role == api.SELLER {
		s.writeError(c, http.StatusForbidden, api.ACCESSDENIED, "SELLER cannot update orders", nil)
		return
	}

	var req api.OrderUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		s.writeValidationError(c, []fieldViolation{{Field: "body", Violation: "invalid JSON"}})
		return
	}
	if violations := validateOrderUpdate(req); len(violations) > 0 {
		s.writeValidationError(c, violations)
		return
	}

	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to update order", nil)
		return
	}
	defer func() { _ = tx.Rollback() }()

	order, err := s.lockOrder(tx, c, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.writeError(c, http.StatusNotFound, api.ORDERNOTFOUND, "Order not found", nil)
			return
		}
		s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to update order", nil)
		return
	}

	if role == api.USER && order.UserID != userID {
		s.writeError(c, http.StatusForbidden, api.ORDEROWNERSHIPVIOLATION, "Order belongs to another user", nil)
		return
	}
	if order.Status != api.CREATED {
		s.writeError(c, http.StatusConflict, api.INVALIDSTATETRANSITION, "Order can be updated only in CREATED status", nil)
		return
	}

	if err = s.checkUserOperationRateLimit(c, tx, order.UserID, "UPDATE_ORDER"); err != nil {
		return
	}

	existingItems, err := s.loadOrderItems(c.Request.Context(), tx, id)
	if err != nil {
		s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to update order", nil)
		return
	}
	for _, item := range existingItems {
		if _, execErr := tx.ExecContext(c.Request.Context(), `UPDATE products SET stock = stock + $1 WHERE id = $2`, item.Quantity, item.ProductId); execErr != nil {
			s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to update order", nil)
			return
		}
	}

	normalized := normalizeOrderItems(req.Items)
	productIDs := sortedProductIDs(normalized)
	products, err := s.lockProducts(c, tx, productIDs)
	if err != nil {
		s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to update order", nil)
		return
	}

	if missingID, ok := findMissingProductID(products, productIDs); ok {
		s.writeError(c, http.StatusNotFound, api.PRODUCTNOTFOUND, fmt.Sprintf("Product %d not found", missingID), nil)
		return
	}
	if inactiveID, ok := findInactiveProductID(products, productIDs); ok {
		s.writeError(c, http.StatusConflict, api.PRODUCTINACTIVE, fmt.Sprintf("Product %d is inactive", inactiveID), nil)
		return
	}
	if details, insufficient := findInsufficientStock(products, normalized); insufficient {
		s.writeError(c, http.StatusConflict, api.INSUFFICIENTSTOCK, "Insufficient stock for one or more products", map[string]any{"products": details})
		return
	}

	for productID, quantity := range normalized {
		if _, execErr := tx.ExecContext(c.Request.Context(), `UPDATE products SET stock = stock - $1 WHERE id = $2`, quantity, productID); execErr != nil {
			s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to update order", nil)
			return
		}
	}

	if _, err = tx.ExecContext(c.Request.Context(), `DELETE FROM order_items WHERE order_id = $1`, id); err != nil {
		s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to update order", nil)
		return
	}

	subtotal := calculateSubtotal(products, normalized)
	discount := 0.0
	total := subtotal
	promoID := order.PromoCodeID

	if order.PromoCodeID != nil {
		promo, promoErr := s.lockPromoByID(c, tx, *order.PromoCodeID)
		if promoErr != nil {
			s.writeError(c, http.StatusUnprocessableEntity, api.PROMOCODEINVALID, "Promo code invalid", nil)
			return
		}

		now := time.Now().UTC()
		if !promo.Active || now.Before(promo.ValidFrom) || now.After(promo.ValidUntil) || promo.CurrentUses < 1 || promo.CurrentUses > promo.MaxUses {
			s.writeError(c, http.StatusUnprocessableEntity, api.PROMOCODEINVALID, "Promo code invalid", nil)
			return
		}

		if subtotal < promo.MinOrderAmount {
			promoID = nil
			if _, execErr := tx.ExecContext(c.Request.Context(), `UPDATE promo_codes SET current_uses = GREATEST(current_uses - 1, 0) WHERE id = $1`, promo.ID); execErr != nil {
				s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to update order", nil)
				return
			}
		} else {
			discount = calculateDiscount(subtotal, promo.DiscountType, promo.DiscountValue)
			total = subtotal - discount
		}
	}

	for productID, quantity := range normalized {
		product := products[productID]
		if _, execErr := tx.ExecContext(
			c.Request.Context(),
			`INSERT INTO order_items (order_id, product_id, quantity, price_at_order) VALUES ($1, $2, $3, $4)`,
			id,
			productID,
			quantity,
			product.Price,
		); execErr != nil {
			s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to update order", nil)
			return
		}
	}

	if _, err = tx.ExecContext(c.Request.Context(), `
		UPDATE orders
		SET promo_code_id = $1, total_amount = $2, discount_amount = $3
		WHERE id = $4`, promoID, total, discount, id); err != nil {
		s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to update order", nil)
		return
	}

	if _, err = tx.ExecContext(c.Request.Context(), `INSERT INTO user_operations (user_id, operation_type) VALUES ($1, 'UPDATE_ORDER')`, order.UserID); err != nil {
		s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to update order", nil)
		return
	}

	if err = tx.Commit(); err != nil {
		s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to update order", nil)
		return
	}

	resp, err := s.loadOrderResponse(c.Request.Context(), s.db, id)
	if err != nil {
		s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to update order", nil)
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (s *Server) CancelOrderById(c *gin.Context, id int64) {
	if !s.requireRole(c, api.USER, api.ADMIN) {
		return
	}

	userID, role, _ := s.currentUser(c)
	if role == api.SELLER {
		s.writeError(c, http.StatusForbidden, api.ACCESSDENIED, "SELLER cannot cancel orders", nil)
		return
	}

	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to cancel order", nil)
		return
	}
	defer func() { _ = tx.Rollback() }()

	order, err := s.lockOrder(tx, c, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.writeError(c, http.StatusNotFound, api.ORDERNOTFOUND, "Order not found", nil)
			return
		}
		s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to cancel order", nil)
		return
	}

	if role == api.USER && order.UserID != userID {
		s.writeError(c, http.StatusForbidden, api.ORDEROWNERSHIPVIOLATION, "Order belongs to another user", nil)
		return
	}
	if order.Status != api.CREATED && order.Status != api.PAYMENTPENDING {
		s.writeError(c, http.StatusConflict, api.INVALIDSTATETRANSITION, "Order cannot be canceled from current status", nil)
		return
	}

	items, err := s.loadOrderItems(c.Request.Context(), tx, id)
	if err != nil {
		s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to cancel order", nil)
		return
	}
	for _, item := range items {
		if _, execErr := tx.ExecContext(c.Request.Context(), `UPDATE products SET stock = stock + $1 WHERE id = $2`, item.Quantity, item.ProductId); execErr != nil {
			s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to cancel order", nil)
			return
		}
	}

	if order.PromoCodeID != nil {
		if _, err = tx.ExecContext(c.Request.Context(), `UPDATE promo_codes SET current_uses = GREATEST(current_uses - 1, 0) WHERE id = $1`, *order.PromoCodeID); err != nil {
			s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to cancel order", nil)
			return
		}
	}

	if _, err = tx.ExecContext(c.Request.Context(), `UPDATE orders SET status = 'CANCELED' WHERE id = $1`, id); err != nil {
		s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to cancel order", nil)
		return
	}

	if err = tx.Commit(); err != nil {
		s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to cancel order", nil)
		return
	}

	resp, err := s.loadOrderResponse(c.Request.Context(), s.db, id)
	if err != nil {
		s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to cancel order", nil)
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (s *Server) TransitionOrderStatus(c *gin.Context, id int64) {
	if !s.requireRole(c, api.ADMIN) {
		return
	}

	var req api.OrderStatusTransitionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		s.writeValidationError(c, []fieldViolation{{Field: "body", Violation: "invalid JSON"}})
		return
	}
	if !validateOrderStatus(req.Status) {
		s.writeValidationError(c, []fieldViolation{{Field: "status", Violation: "invalid enum value"}})
		return
	}

	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to transition order status", nil)
		return
	}
	defer func() { _ = tx.Rollback() }()

	order, err := s.lockOrder(tx, c, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.writeError(c, http.StatusNotFound, api.ORDERNOTFOUND, "Order not found", nil)
			return
		}
		s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to transition order status", nil)
		return
	}

	if !isValidStateTransition(order.Status, req.Status) {
		s.writeError(c, http.StatusConflict, api.INVALIDSTATETRANSITION, "Invalid state transition", nil)
		return
	}

	if _, err = tx.ExecContext(c.Request.Context(), `UPDATE orders SET status = $1 WHERE id = $2`, string(req.Status), id); err != nil {
		s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to transition order status", nil)
		return
	}

	if err = tx.Commit(); err != nil {
		s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to transition order status", nil)
		return
	}

	resp, err := s.loadOrderResponse(c.Request.Context(), s.db, id)
	if err != nil {
		s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to transition order status", nil)
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (s *Server) CreatePromoCode(c *gin.Context) {
	if !s.requireRole(c, api.SELLER, api.ADMIN) {
		return
	}

	var req api.PromoCodeCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		s.writeValidationError(c, []fieldViolation{{Field: "body", Violation: "invalid JSON"}})
		return
	}
	if violations := validatePromoCodeCreate(req); len(violations) > 0 {
		s.writeValidationError(c, violations)
		return
	}

	active := true
	if req.Active != nil {
		active = *req.Active
	}

	const query = `
		INSERT INTO promo_codes (code, discount_type, discount_value, min_order_amount, max_uses, valid_from, valid_until, active)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, code, discount_type, discount_value, min_order_amount, max_uses, current_uses, valid_from, valid_until, active, created_at, updated_at`

	var resp api.PromoCodeResponse
	err := s.db.QueryRowContext(
		c.Request.Context(),
		query,
		strings.ToUpper(strings.TrimSpace(req.Code)),
		string(req.DiscountType),
		req.DiscountValue,
		req.MinOrderAmount,
		req.MaxUses,
		req.ValidFrom,
		req.ValidUntil,
		active,
	).Scan(
		&resp.Id,
		&resp.Code,
		&resp.DiscountType,
		&resp.DiscountValue,
		&resp.MinOrderAmount,
		&resp.MaxUses,
		&resp.CurrentUses,
		&resp.ValidFrom,
		&resp.ValidUntil,
		&resp.Active,
		&resp.CreatedAt,
		&resp.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			s.writeValidationError(c, []fieldViolation{{Field: "code", Violation: "already exists"}})
			return
		}
		s.writeError(c, http.StatusInternalServerError, api.PROMOCODEINVALID, "Failed to create promo code", nil)
		return
	}

	c.JSON(http.StatusCreated, resp)
}

func (s *Server) saveRefreshToken(c *gin.Context, userID int64, refreshToken string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(
		c.Request.Context(),
		`INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`,
		userID,
		hashToken(refreshToken),
		expiresAt,
	)
	return err
}

func (s *Server) getProduct(c *gin.Context, id int64) (api.ProductResponse, error) {
	const query = `
		SELECT id, name, description, price, stock, category, status, seller_id, created_at, updated_at
		FROM products WHERE id = $1`
	var product api.ProductResponse
	err := s.db.QueryRowContext(c.Request.Context(), query, id).Scan(
		&product.Id,
		&product.Name,
		&product.Description,
		&product.Price,
		&product.Stock,
		&product.Category,
		&product.Status,
		&product.SellerId,
		&product.CreatedAt,
		&product.UpdatedAt,
	)
	return product, err
}

func scanProduct(scanner interface{ Scan(dest ...any) error }) (api.ProductResponse, error) {
	var product api.ProductResponse
	err := scanner.Scan(
		&product.Id,
		&product.Name,
		&product.Description,
		&product.Price,
		&product.Stock,
		&product.Category,
		&product.Status,
		&product.SellerId,
		&product.CreatedAt,
		&product.UpdatedAt,
	)
	return product, err
}

type productLockRow struct {
	ID     int64
	Price  float64
	Status api.ProductStatus
	Stock  int
}

type promoRow struct {
	Active         bool
	CurrentUses    int
	DiscountType   api.DiscountType
	DiscountValue  float64
	ID             int64
	MaxUses        int
	MinOrderAmount float64
	ValidFrom      time.Time
	ValidUntil     time.Time
}

type lockedOrder struct {
	ID          int64
	PromoCodeID *int64
	Status      api.OrderStatus
	UserID      int64
}

func (s *Server) lockProducts(c *gin.Context, tx *sql.Tx, productIDs []int64) (map[int64]productLockRow, error) {
	rows, err := tx.QueryContext(
		c.Request.Context(),
		`SELECT id, price, status, stock FROM products WHERE id = ANY($1) FOR UPDATE`,
		pq.Array(productIDs),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[int64]productLockRow)
	for rows.Next() {
		var row productLockRow
		if scanErr := rows.Scan(&row.ID, &row.Price, &row.Status, &row.Stock); scanErr != nil {
			return nil, scanErr
		}
		result[row.ID] = row
	}
	return result, nil
}

func (s *Server) lockPromoByCode(c *gin.Context, tx *sql.Tx, code string) (*promoRow, error) {
	const query = `
		SELECT id, discount_type, discount_value, min_order_amount, max_uses, current_uses, valid_from, valid_until, active
		FROM promo_codes WHERE code = $1 FOR UPDATE`
	var row promoRow
	err := tx.QueryRowContext(c.Request.Context(), query, strings.ToUpper(strings.TrimSpace(code))).Scan(
		&row.ID,
		&row.DiscountType,
		&row.DiscountValue,
		&row.MinOrderAmount,
		&row.MaxUses,
		&row.CurrentUses,
		&row.ValidFrom,
		&row.ValidUntil,
		&row.Active,
	)
	if err != nil {
		return nil, err
	}
	return &row, nil
}

func (s *Server) lockPromoByID(c *gin.Context, tx *sql.Tx, id int64) (*promoRow, error) {
	const query = `
		SELECT id, discount_type, discount_value, min_order_amount, max_uses, current_uses, valid_from, valid_until, active
		FROM promo_codes WHERE id = $1 FOR UPDATE`
	var row promoRow
	err := tx.QueryRowContext(c.Request.Context(), query, id).Scan(
		&row.ID,
		&row.DiscountType,
		&row.DiscountValue,
		&row.MinOrderAmount,
		&row.MaxUses,
		&row.CurrentUses,
		&row.ValidFrom,
		&row.ValidUntil,
		&row.Active,
	)
	if err != nil {
		return nil, err
	}
	return &row, nil
}

func (s *Server) hasActiveOrder(c *gin.Context, tx *sql.Tx, userID int64) (bool, error) {
	const query = `SELECT EXISTS(SELECT 1 FROM orders WHERE user_id = $1 AND status IN ('CREATED', 'PAYMENT_PENDING'))`
	var exists bool
	err := tx.QueryRowContext(c.Request.Context(), query, userID).Scan(&exists)
	return exists, err
}

func (s *Server) checkUserOperationRateLimit(c *gin.Context, tx *sql.Tx, userID int64, operationType string) error {
	const query = `
		SELECT created_at
		FROM user_operations
		WHERE user_id = $1 AND operation_type = $2
		ORDER BY created_at DESC
		LIMIT 1`
	var createdAt time.Time
	err := tx.QueryRowContext(c.Request.Context(), query, userID, operationType).Scan(&createdAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to check operation rate limit", nil)
		return err
	}

	if time.Since(createdAt) < time.Duration(s.cfg.OrderRateLimitMinutes)*time.Minute {
		s.writeError(c, http.StatusTooManyRequests, api.ORDERLIMITEXCEEDED, "Too many order operations", nil)
		return fmt.Errorf("rate limit exceeded")
	}
	return nil
}

func (s *Server) applyPromoCodeOnCreate(c *gin.Context, tx *sql.Tx, promoCode *string, subtotal float64) (*int64, float64, float64, error) {
	if promoCode == nil || strings.TrimSpace(*promoCode) == "" {
		return nil, 0, subtotal, nil
	}

	promo, err := s.lockPromoByCode(c, tx, *promoCode)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.writeError(c, http.StatusUnprocessableEntity, api.PROMOCODEINVALID, "Promo code invalid", nil)
			return nil, 0, subtotal, err
		}
		s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to apply promo code", nil)
		return nil, 0, subtotal, err
	}

	now := time.Now().UTC()
	if !promo.Active || promo.CurrentUses >= promo.MaxUses || now.Before(promo.ValidFrom) || now.After(promo.ValidUntil) {
		s.writeError(c, http.StatusUnprocessableEntity, api.PROMOCODEINVALID, "Promo code invalid", nil)
		return nil, 0, subtotal, fmt.Errorf("promo invalid")
	}

	if subtotal < promo.MinOrderAmount {
		s.writeError(c, http.StatusUnprocessableEntity, api.PROMOCODEMINAMOUNT, "Promo code minimum amount not reached", nil)
		return nil, 0, subtotal, fmt.Errorf("promo minimum amount")
	}

	discount := calculateDiscount(subtotal, promo.DiscountType, promo.DiscountValue)
	total := subtotal - discount

	if _, err = tx.ExecContext(c.Request.Context(), `UPDATE promo_codes SET current_uses = current_uses + 1 WHERE id = $1`, promo.ID); err != nil {
		s.writeError(c, http.StatusInternalServerError, api.ORDERNOTFOUND, "Failed to apply promo code", nil)
		return nil, 0, subtotal, err
	}

	return &promo.ID, discount, total, nil
}

func calculateDiscount(subtotal float64, discountType api.DiscountType, value float64) float64 {
	switch discountType {
	case api.PERCENTAGE:
		discount := subtotal * value / 100
		maxDiscount := subtotal * 0.70
		if discount > maxDiscount {
			discount = maxDiscount
		}
		return discount
	case api.FIXEDAMOUNT:
		if value > subtotal {
			return subtotal
		}
		return value
	default:
		return 0
	}
}

func normalizeOrderItems(items []api.OrderItemRequest) map[int64]int {
	result := make(map[int64]int)
	for _, item := range items {
		result[item.ProductId] += item.Quantity
	}
	return result
}

func sortedProductIDs(items map[int64]int) []int64 {
	ids := make([]int64, 0, len(items))
	for id := range items {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func findMissingProductID(products map[int64]productLockRow, requested []int64) (int64, bool) {
	for _, id := range requested {
		if _, ok := products[id]; !ok {
			return id, true
		}
	}
	return 0, false
}

func findInactiveProductID(products map[int64]productLockRow, requested []int64) (int64, bool) {
	for _, id := range requested {
		if product, ok := products[id]; ok && product.Status != api.ACTIVE {
			return id, true
		}
	}
	return 0, false
}

func findInsufficientStock(products map[int64]productLockRow, requested map[int64]int) ([]map[string]any, bool) {
	violations := make([]map[string]any, 0)
	for productID, quantity := range requested {
		if product, ok := products[productID]; ok {
			if product.Stock < quantity {
				violations = append(violations, map[string]any{
					"product_id":         productID,
					"requested_quantity": quantity,
					"available_stock":    product.Stock,
				})
			}
		}
	}
	return violations, len(violations) > 0
}

func calculateSubtotal(products map[int64]productLockRow, quantities map[int64]int) float64 {
	total := 0.0
	for id, quantity := range quantities {
		product, ok := products[id]
		if !ok {
			continue
		}
		total += product.Price * float64(quantity)
	}
	return total
}

func (s *Server) loadOrderResponse(ctx context.Context, db interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}, orderID int64) (api.OrderResponse, error) {
	const orderQuery = `
		SELECT id, user_id, status, promo_code_id, total_amount, discount_amount, created_at, updated_at
		FROM orders
		WHERE id = $1`
	var order api.OrderResponse
	err := db.QueryRowContext(ctx, orderQuery, orderID).Scan(
		&order.Id,
		&order.UserId,
		&order.Status,
		&order.PromoCodeId,
		&order.TotalAmount,
		&order.DiscountAmount,
		&order.CreatedAt,
		&order.UpdatedAt,
	)
	if err != nil {
		return api.OrderResponse{}, err
	}

	const itemQuery = `
		SELECT id, order_id, product_id, quantity, price_at_order
		FROM order_items
		WHERE order_id = $1
		ORDER BY id`
	rows, err := db.QueryContext(ctx, itemQuery, orderID)
	if err != nil {
		return api.OrderResponse{}, err
	}
	defer rows.Close()

	items := make([]api.OrderItemResponse, 0)
	for rows.Next() {
		var item api.OrderItemResponse
		if scanErr := rows.Scan(&item.Id, &item.OrderId, &item.ProductId, &item.Quantity, &item.PriceAtOrder); scanErr != nil {
			return api.OrderResponse{}, scanErr
		}
		items = append(items, item)
	}
	order.Items = items
	return order, nil
}

func (s *Server) lockOrder(tx *sql.Tx, c *gin.Context, orderID int64) (lockedOrder, error) {
	const query = `
		SELECT id, user_id, status, promo_code_id
		FROM orders
		WHERE id = $1
		FOR UPDATE`
	var row lockedOrder
	err := tx.QueryRowContext(c.Request.Context(), query, orderID).Scan(&row.ID, &row.UserID, &row.Status, &row.PromoCodeID)
	if err != nil {
		return lockedOrder{}, err
	}
	return row, nil
}

func (s *Server) loadOrderItems(ctx context.Context, tx *sql.Tx, orderID int64) ([]api.OrderItemResponse, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, order_id, product_id, quantity, price_at_order FROM order_items WHERE order_id = $1`, orderID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]api.OrderItemResponse, 0)
	for rows.Next() {
		var item api.OrderItemResponse
		if scanErr := rows.Scan(&item.Id, &item.OrderId, &item.ProductId, &item.Quantity, &item.PriceAtOrder); scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	return items, nil
}

func isValidStateTransition(from, to api.OrderStatus) bool {
	if from == to {
		return true
	}
	transitions := map[api.OrderStatus][]api.OrderStatus{
		api.CREATED:        {api.PAYMENTPENDING},
		api.PAYMENTPENDING: {api.PAID, api.CANCELED},
		api.PAID:           {api.SHIPPED},
		api.SHIPPED:        {api.COMPLETED},
	}
	allowed := transitions[from]
	for _, next := range allowed {
		if next == to {
			return true
		}
	}
	return false
}

func validateRegisterRequest(req api.RegisterRequest) []fieldViolation {
	violations := make([]fieldViolation, 0)
	if l := len(strings.TrimSpace(string(req.Email))); l < 5 || l > 255 || !strings.Contains(string(req.Email), "@") {
		violations = append(violations, fieldViolation{Field: "email", Violation: "must be a valid email with length 5..255"})
	}
	if l := len(req.Password); l < 8 || l > 128 {
		violations = append(violations, fieldViolation{Field: "password", Violation: "length must be between 8 and 128"})
	}
	if !validateRole(req.Role) {
		violations = append(violations, fieldViolation{Field: "role", Violation: "invalid enum value"})
	}
	return violations
}

func validateLoginRequest(req api.LoginRequest) []fieldViolation {
	violations := make([]fieldViolation, 0)
	if l := len(strings.TrimSpace(string(req.Email))); l < 5 || l > 255 || !strings.Contains(string(req.Email), "@") {
		violations = append(violations, fieldViolation{Field: "email", Violation: "must be a valid email with length 5..255"})
	}
	if l := len(req.Password); l < 8 || l > 128 {
		violations = append(violations, fieldViolation{Field: "password", Violation: "length must be between 8 and 128"})
	}
	return violations
}

func validateRefreshRequest(req api.RefreshRequest) []fieldViolation {
	violations := make([]fieldViolation, 0)
	if l := len(strings.TrimSpace(req.RefreshToken)); l < 16 || l > 2048 {
		violations = append(violations, fieldViolation{Field: "refresh_token", Violation: "length must be between 16 and 2048"})
	}
	return violations
}

func validateProductCreate(req api.ProductCreate) []fieldViolation {
	violations := make([]fieldViolation, 0)
	if l := len(strings.TrimSpace(req.Name)); l < 1 || l > 255 {
		violations = append(violations, fieldViolation{Field: "name", Violation: "length must be between 1 and 255"})
	}
	if req.Description != nil && len(*req.Description) > 4000 {
		violations = append(violations, fieldViolation{Field: "description", Violation: "max length is 4000"})
	}
	if req.Price < 0.01 {
		violations = append(violations, fieldViolation{Field: "price", Violation: "must be >= 0.01"})
	}
	if req.Stock < 0 {
		violations = append(violations, fieldViolation{Field: "stock", Violation: "must be >= 0"})
	}
	if l := len(strings.TrimSpace(req.Category)); l < 1 || l > 100 {
		violations = append(violations, fieldViolation{Field: "category", Violation: "length must be between 1 and 100"})
	}
	if !validateProductStatus(req.Status) {
		violations = append(violations, fieldViolation{Field: "status", Violation: "invalid enum value"})
	}
	return violations
}

func validateProductUpdate(req api.ProductUpdate) []fieldViolation {
	violations := make([]fieldViolation, 0)
	if req.Name == nil && req.Description == nil && req.Price == nil && req.Stock == nil && req.Category == nil && req.Status == nil {
		violations = append(violations, fieldViolation{Field: "body", Violation: "at least one field must be provided"})
		return violations
	}
	if req.Name != nil {
		if l := len(strings.TrimSpace(*req.Name)); l < 1 || l > 255 {
			violations = append(violations, fieldViolation{Field: "name", Violation: "length must be between 1 and 255"})
		}
	}
	if req.Description != nil && len(*req.Description) > 4000 {
		violations = append(violations, fieldViolation{Field: "description", Violation: "max length is 4000"})
	}
	if req.Price != nil && *req.Price < 0.01 {
		violations = append(violations, fieldViolation{Field: "price", Violation: "must be >= 0.01"})
	}
	if req.Stock != nil && *req.Stock < 0 {
		violations = append(violations, fieldViolation{Field: "stock", Violation: "must be >= 0"})
	}
	if req.Category != nil {
		if l := len(strings.TrimSpace(*req.Category)); l < 1 || l > 100 {
			violations = append(violations, fieldViolation{Field: "category", Violation: "length must be between 1 and 100"})
		}
	}
	if req.Status != nil && !validateProductStatus(*req.Status) {
		violations = append(violations, fieldViolation{Field: "status", Violation: "invalid enum value"})
	}
	return violations
}

func validateOrderCreate(req api.OrderCreateRequest) []fieldViolation {
	violations := make([]fieldViolation, 0)
	if len(req.Items) < 1 || len(req.Items) > 50 {
		violations = append(violations, fieldViolation{Field: "items", Violation: "size must be between 1 and 50"})
	}
	for idx, item := range req.Items {
		if item.ProductId < 1 {
			violations = append(violations, fieldViolation{Field: fmt.Sprintf("items[%d].product_id", idx), Violation: "must be >= 1"})
		}
		if item.Quantity < 1 || item.Quantity > 999 {
			violations = append(violations, fieldViolation{Field: fmt.Sprintf("items[%d].quantity", idx), Violation: "must be between 1 and 999"})
		}
	}
	if req.PromoCode != nil && strings.TrimSpace(*req.PromoCode) != "" && !promoCodePattern.MatchString(strings.TrimSpace(*req.PromoCode)) {
		violations = append(violations, fieldViolation{Field: "promo_code", Violation: "must match pattern ^[A-Z0-9_]{4,20}$"})
	}
	return violations
}

func validateOrderUpdate(req api.OrderUpdateRequest) []fieldViolation {
	violations := make([]fieldViolation, 0)
	if len(req.Items) < 1 || len(req.Items) > 50 {
		violations = append(violations, fieldViolation{Field: "items", Violation: "size must be between 1 and 50"})
	}
	for idx, item := range req.Items {
		if item.ProductId < 1 {
			violations = append(violations, fieldViolation{Field: fmt.Sprintf("items[%d].product_id", idx), Violation: "must be >= 1"})
		}
		if item.Quantity < 1 || item.Quantity > 999 {
			violations = append(violations, fieldViolation{Field: fmt.Sprintf("items[%d].quantity", idx), Violation: "must be between 1 and 999"})
		}
	}
	return violations
}

func validatePromoCodeCreate(req api.PromoCodeCreateRequest) []fieldViolation {
	violations := make([]fieldViolation, 0)
	code := strings.TrimSpace(req.Code)
	if !promoCodePattern.MatchString(code) {
		violations = append(violations, fieldViolation{Field: "code", Violation: "must match pattern ^[A-Z0-9_]{4,20}$"})
	}
	if !validateDiscountType(req.DiscountType) {
		violations = append(violations, fieldViolation{Field: "discount_type", Violation: "invalid enum value"})
	}
	if req.DiscountValue < 0.01 {
		violations = append(violations, fieldViolation{Field: "discount_value", Violation: "must be >= 0.01"})
	}
	if req.MinOrderAmount < 0 {
		violations = append(violations, fieldViolation{Field: "min_order_amount", Violation: "must be >= 0"})
	}
	if req.MaxUses < 1 {
		violations = append(violations, fieldViolation{Field: "max_uses", Violation: "must be >= 1"})
	}
	if req.ValidUntil.Before(req.ValidFrom) {
		violations = append(violations, fieldViolation{Field: "valid_until", Violation: "must be >= valid_from"})
	}
	return violations
}

func isUniqueViolation(err error) bool {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == "23505"
	}
	return false
}
