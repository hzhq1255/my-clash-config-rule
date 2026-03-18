package service

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/hzhq1255/my-clash-config-rule/subserver/pkg/subconverter"
)

// ConverterService handles subconverter operations
type ConverterService struct {
	manager        *subconverter.Manager
	lockFile       string
	generateIni    string
	semaphore      chan struct{}
	cache          map[string]*CacheEntry
	cacheMutex     sync.RWMutex
	fileCacheTTL   time.Duration
}

// CacheEntry represents a cached conversion result
type CacheEntry struct {
	Path      string
	ExpiresAt time.Time
}

// NewConverterService creates a new converter service
func NewConverterService(manager *subconverter.Manager, workDir string, fileCacheTTL int) *ConverterService {
	return &ConverterService{
		manager:      manager,
		lockFile:     filepath.Join(workDir, "generate.ini.lock"),
		generateIni:  filepath.Join(workDir, "generate.ini"),
		semaphore:    make(chan struct{}, 3), // Max 3 concurrent conversions
		cache:        make(map[string]*CacheEntry),
		fileCacheTTL: time.Duration(fileCacheTTL) * time.Second,
	}
}

// Convert converts a subscription using subconverter
func (s *ConverterService) Convert(ctx context.Context, configName string, params map[string]string) (string, error) {
	// Check cache first
	cacheKey := s.buildCacheKey(configName, params)
	if entry := s.getFromCache(cacheKey); entry != nil {
		slog.Debug("Using cached conversion", "key", cacheKey, "path", entry.Path)
		return entry.Path, nil
	}

	// Acquire semaphore
	select {
	case s.semaphore <- struct{}{}:
		defer func() { <-s.semaphore }()
	case <-ctx.Done():
		return "", ctx.Err()
	}

	// Acquire lock
	if err := s.acquireLock(); err != nil {
		return "", fmt.Errorf("acquire lock: %w", err)
	}
	defer s.releaseLock()

	// Build output path
	outputPath := filepath.Join(s.manager.GetWorkDir(), "caches", fmt.Sprintf("%s-%d.yaml", configName, time.Now().Unix()))
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return "", fmt.Errorf("create cache dir: %w", err)
	}

	// Set output path parameter
	params["path"] = outputPath

	// Write generate.ini
	if err := s.writeGenerateIni(configName, params); err != nil {
		return "", fmt.Errorf("write generate.ini: %w", err)
	}

	// Run subconverter
	if err := s.runSubconverter(configName); err != nil {
		return "", fmt.Errorf("run subconverter: %w", err)
	}

	// Cache result
	s.addToCache(cacheKey, outputPath, s.fileCacheTTL)

	slog.Info("Conversion completed", "config", configName, "output", outputPath)
	return outputPath, nil
}

// buildCacheKey builds a cache key from parameters
func (s *ConverterService) buildCacheKey(configName string, params map[string]string) string {
	key := configName
	for k, v := range params {
		key += fmt.Sprintf(":%s=%s", k, v)
	}
	return key
}

// getFromCache gets a cached entry if valid
func (s *ConverterService) getFromCache(key string) *CacheEntry {
	s.cacheMutex.RLock()
	defer s.cacheMutex.RUnlock()

	entry, ok := s.cache[key]
	if !ok {
		return nil
	}

	// Check expiration
	if time.Now().After(entry.ExpiresAt) {
		delete(s.cache, key)
		return nil
	}

	// Check file exists
	if _, err := os.Stat(entry.Path); err != nil {
		delete(s.cache, key)
		return nil
	}

	return entry
}

// addToCache adds an entry to cache
func (s *ConverterService) addToCache(key, path string, ttl time.Duration) {
	s.cacheMutex.Lock()
	defer s.cacheMutex.Unlock()

	s.cache[key] = &CacheEntry{
		Path:      path,
		ExpiresAt: time.Now().Add(ttl),
	}
}

// acquireLock acquires file lock
func (s *ConverterService) acquireLock() error {
	for i := 0; i < 30; i++ {
		if _, err := os.Stat(s.lockFile); os.IsNotExist(err) {
			// Create lock file
			if err := os.WriteFile(s.lockFile, []byte("1"), 0644); err != nil {
				return err
			}
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout acquiring lock")
}

// releaseLock releases file lock
func (s *ConverterService) releaseLock() error {
	return os.Remove(s.lockFile)
}

// writeGenerateIni writes the generate.ini file
func (s *ConverterService) writeGenerateIni(configName string, params map[string]string) error {
	var buf bytes.Buffer

	buf.WriteString(fmt.Sprintf("[%s]\n", configName))
	for k, v := range params {
		buf.WriteString(fmt.Sprintf("%s=%s\n", k, v))
	}

	return os.WriteFile(s.generateIni, buf.Bytes(), 0644)
}

// runSubconverter runs the subconverter
func (s *ConverterService) runSubconverter(configName string) error {
	// Check if subconverter is running
	if !s.manager.IsRunning() {
		return fmt.Errorf("subconverter not running")
	}

	// Just touch the generate.ini to trigger conversion
	// Subconverter watches the file and auto-regenerates
	if err := os.Chtimes(s.generateIni, time.Now(), time.Now()); err != nil {
		return err
	}

	// Wait for output file to be created
	outputPath := filepath.Join(s.manager.GetWorkDir(), "caches")
	timeout := time.After(30 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return fmt.Errorf("timeout waiting for conversion")
		case <-ticker.C:
			// Check if any output file was created recently
			entries, err := os.ReadDir(outputPath)
			if err != nil {
				continue
			}
			for _, e := range entries {
				info, err := e.Info()
				if err != nil {
					continue
				}
				if time.Since(info.ModTime()) < 5*time.Second {
					return nil
				}
			}
		}
	}
}
