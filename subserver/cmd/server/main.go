package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/hzhq1255/my-clash-config-rule/subserver/internal/config"
	"github.com/hzhq1255/my-clash-config-rule/subserver/internal/handler"
	"github.com/hzhq1255/my-clash-config-rule/subserver/internal/service"
	"github.com/hzhq1255/my-clash-config-rule/subserver/pkg/subconverter"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("Failed to load config", "error", err)
		os.Exit(1)
	}

	logLevel := slog.LevelInfo
	if cfg.LogLevel == "debug" {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)
	slog.Info("Starting Subserver", "version", "0.0.1")

	workDir := filepath.Join(".", "subconverter")
	downloader := subconverter.NewDownloader(workDir, cfg.SubconverterVersion)
	binaryPath, err := downloader.DownloadIfNeeded(cfg.SubconverterDownloadURL)
	if err != nil {
		slog.Error("Failed to prepare subconverter", "error", err)
		os.Exit(1)
	}
	binaryPath, err = filepath.Abs(binaryPath)
	if err != nil {
		slog.Error("Failed to resolve subconverter path", "error", err)
		os.Exit(1)
	}
	workDir = filepath.Dir(binaryPath)

	authService, err := service.NewAuthService(cfg.ZCSSRDomain, cfg.ZCSSRUserEmail, cfg.ZCSSRUserPasswd)
	if err != nil {
		slog.Error("Failed to initialize auth service", "error", err)
		os.Exit(1)
	}

	h := handler.New(
		cfg,
		authService,
		service.NewSubscriptionService(authService, cfg.ZCSSRDomain),
		service.NewNodeService(),
		service.NewCFIPService(),
		service.NewConverterService(subconverter.NewManager(binaryPath, workDir), workDir, cfg.FileCacheTTL),
	)

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.ServerPort),
		Handler:      h.Routes(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		slog.Info("Server listening", "port", cfg.ServerPort)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Server failed", "error", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("Shutting down server")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("Server shutdown error", "error", err)
	}
	slog.Info("Server stopped")
}
