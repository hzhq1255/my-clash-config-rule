package subconverter

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// Manager manages subconverter process
type Manager struct {
	binaryPath string
	workDir    string
	cmd        *exec.Cmd
	mu         sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewManager creates a new subconverter manager
func NewManager(binaryPath, workDir string) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		binaryPath: binaryPath,
		workDir:    workDir,
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Start starts the subconverter process
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cmd != nil && m.cmd.Process != nil {
		// Already running
		return nil
	}

	slog.Info("Starting subconverter", "path", m.binaryPath)

	// Create working directory if not exists
	if err := os.MkdirAll(m.workDir, 0755); err != nil {
		return fmt.Errorf("create work dir: %w", err)
	}

	m.cmd = exec.CommandContext(m.ctx, m.binaryPath)
	m.cmd.Dir = m.workDir

	// Redirect output
	m.cmd.Stdout = os.Stdout
	m.cmd.Stderr = os.Stderr

	if err := m.cmd.Start(); err != nil {
		return fmt.Errorf("start subconverter: %w", err)
	}

	// Wait a bit to ensure it started
	time.Sleep(2 * time.Second)

	// Check if process is still running
	if !m.isProcessRunning() {
		return fmt.Errorf("subconverter process exited")
	}

	slog.Info("Subconverter started successfully", "pid", m.cmd.Process.Pid)
	return nil
}

// Stop stops the subconverter process
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cmd == nil || m.cmd.Process == nil {
		return nil
	}

	slog.Info("Stopping subconverter")

	// Cancel context
	m.cancel()

	// Try graceful shutdown first
	done := make(chan error, 1)
	go func() {
		done <- m.cmd.Wait()
	}()

	select {
	case <-time.After(5 * time.Second):
		// Force kill
		if err := m.cmd.Process.Kill(); err != nil {
			slog.Warn("Failed to kill subconverter", "error", err)
		}
	case err := <-done:
		if err != nil {
			slog.Warn("Subconverter exit error", "error", err)
		}
	}

	m.cmd = nil
	slog.Info("Subconverter stopped")
	return nil
}

// isProcessRunning checks if the process is still running
func (m *Manager) isProcessRunning() bool {
	if m.cmd == nil || m.cmd.Process == nil {
		return false
	}

	// Send signal 0 to check if process exists
	err := m.cmd.Process.Signal(syscall.Signal(0))
	return err == nil
}

// GetBinaryPath returns the binary path
func (m *Manager) GetBinaryPath() string {
	return m.binaryPath
}

// GetWorkDir returns the working directory
func (m *Manager) GetWorkDir() string {
	return m.workDir
}

// IsRunning returns true if subconverter is running
func (m *Manager) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.isProcessRunning()
}
