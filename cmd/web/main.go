package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"example.com/customer-crypto-grpc-v2/webapp"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8080", "REST and web listen address (localhost only)")
	grpcAddr := flag.String("grpc", "127.0.0.1:50051", "gRPC server address")
	identityDir := flag.String("identities", "identities", "demo identity directory")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	handler, e := webapp.NewHandler(*identityDir, *grpcAddr, logger)
	if e != nil {
		logger.Error("web client setup failed", "error", e)
		os.Exit(1)
	}
	server := &http.Server{
		Addr:              *listen,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		logger.Info("web client shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if e := server.Shutdown(shutdownCtx); e != nil {
			logger.Error("web client shutdown failed", "error", e)
		}
	}()

	logger.Info("REST and web client listening", "address", *listen, "grpc", *grpcAddr, "identities", *identityDir, "url", "http://"+*listen)
	if e := server.ListenAndServe(); e != nil && !errors.Is(e, http.ErrServerClosed) {
		logger.Error("web client stopped", "error", e)
		os.Exit(1)
	}
}
