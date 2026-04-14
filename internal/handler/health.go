package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

type HealthHandler struct {
	pool         *pgxpool.Pool
	valkeyClient *redis.Client
}

func NewHealthHandler(pool *pgxpool.Pool, valkeyClient *redis.Client) *HealthHandler {
	return &HealthHandler{pool: pool, valkeyClient: valkeyClient}
}

func (h *HealthHandler) GetHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	pgStatus := "up"
	if err := h.pool.Ping(ctx); err != nil {
		pgStatus = "down"
	}

	valkeyStatus := "up"
	if err := h.valkeyClient.Ping(ctx).Err(); err != nil {
		valkeyStatus = "down"
	}

	status := http.StatusOK
	overall := "healthy"
	if pgStatus == "down" || valkeyStatus == "down" {
		status = http.StatusServiceUnavailable
		overall = "unhealthy"
	}

	writeJSON(w, status, map[string]string{
		"status":   overall,
		"postgres": pgStatus,
		"valkey":   valkeyStatus,
	})
}
