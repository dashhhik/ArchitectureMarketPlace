package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"marketplace/internal/app"
)

func main() {
	cfg := app.LoadConfig()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	db, err := app.ConnectDB(ctx, cfg.DatabaseDSN)
	if err != nil {
		log.Fatalf("failed to connect db: %v", err)
	}
	defer db.Close()

	server := app.NewServer(db, cfg)
	router := server.Router()

	httpServer := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("marketplace-service started on :%s", cfg.Port)
	if err = httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server failed: %v", err)
	}
}
