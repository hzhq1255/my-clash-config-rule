package service

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/hzhq1255/my-clash-config-rule/subserver/pkg/subconverter"
)

// ConverterService handles subconverter operations.
type ConverterService struct {
	manager      *subconverter.Manager
	lockFile     string
	generateIni  string
	semaphore    chan struct{}
	cache        map[string]*CacheEntry
	cacheMutex   sync.RWMutex
	fileCacheTTL time.Duration
}

// CacheEntry represents a cached conversion result.
type CacheEntry struct {
	Path      string
	ExpiresAt time.Time
}

// NewConverterService creates a new converter service.
func NewConverterService(manager *subconverter.Manager, workDir string, fileCacheTTL int) *ConverterService {
	return &ConverterService{
		manager:      manager,
		lockFile:     filepath.Join(workDir, "generate.ini.lock"),
		generateIni:  filepath.Join(workDir, "generate.ini"),
		semaphore:    make(chan struct{}, 1),
		cache:        make(map[string]*CacheEntry),
		fileCacheTTL: time.Duration(fileCacheTTL) * time.Second,
	}
}

// Convert converts a subscription using subconverter.
func (s *ConverterService) Convert(ctx context.Context, configName string, params map[string]string, outputName string) (string, error) {
	cacheKey := s.buildCacheKey(configName, params)
	if entry := s.getFromCache(cacheKey); entry != nil {
		return entry.Path, nil
	}

	select {
	case s.semaphore <- struct{}{}:
		defer func() { <-s.semaphore }()
	case <-ctx.Done():
		return "", ctx.Err()
	}

	if err := s.acquireLock(); err != nil {
		return "", fmt.Errorf("acquire lock: %w", err)
	}
	defer s.releaseLock()

	outputPath := filepath.Join(s.manager.GetWorkDir(), "caches", outputName)
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return "", fmt.Errorf("create cache dir: %w", err)
	}

	iniParams := make(map[string]string, len(params)+1)
	for k, v := range params {
		iniParams[k] = v
	}
	iniParams["path"] = outputPath

	if err := s.writeGenerateIni(configName, iniParams); err != nil {
		return "", fmt.Errorf("write generate.ini: %w", err)
	}
	if err := s.runSubconverter(ctx, configName); err != nil {
		return "", fmt.Errorf("run subconverter: %w", err)
	}
	if _, err := os.Stat(outputPath); err != nil {
		return "", fmt.Errorf("subconverter output missing: %w", err)
	}

	s.addToCache(cacheKey, outputPath, s.fileCacheTTL)
	slog.Info("Conversion completed", "config", configName, "output", outputPath)
	return outputPath, nil
}

func (s *ConverterService) buildCacheKey(configName string, params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	key := configName
	for _, k := range keys {
		key += fmt.Sprintf(":%s=%s", k, params[k])
	}
	return key
}

func (s *ConverterService) getFromCache(key string) *CacheEntry {
	s.cacheMutex.RLock()
	entry := s.cache[key]
	s.cacheMutex.RUnlock()
	if entry == nil {
		return nil
	}
	if time.Now().After(entry.ExpiresAt) {
		s.cacheMutex.Lock()
		delete(s.cache, key)
		s.cacheMutex.Unlock()
		return nil
	}
	if _, err := os.Stat(entry.Path); err != nil {
		s.cacheMutex.Lock()
		delete(s.cache, key)
		s.cacheMutex.Unlock()
		return nil
	}
	return entry
}

func (s *ConverterService) addToCache(key, path string, ttl time.Duration) {
	s.cacheMutex.Lock()
	defer s.cacheMutex.Unlock()
	s.cache[key] = &CacheEntry{
		Path:      path,
		ExpiresAt: time.Now().Add(ttl),
	}
}

func (s *ConverterService) acquireLock() error {
	for i := 0; i < 30; i++ {
		if _, err := os.Stat(s.lockFile); os.IsNotExist(err) {
			if err := os.WriteFile(s.lockFile, []byte("1"), 0644); err != nil {
				return err
			}
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout acquiring lock")
}

func (s *ConverterService) releaseLock() error {
	if err := os.Remove(s.lockFile); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (s *ConverterService) writeGenerateIni(configName string, params map[string]string) error {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("[%s]\n", configName))
	for _, k := range keys {
		buf.WriteString(fmt.Sprintf("%s=%s\n", k, params[k]))
	}
	return os.WriteFile(s.generateIni, buf.Bytes(), 0644)
}

func (s *ConverterService) runSubconverter(ctx context.Context, configName string) error {
	cmd := exec.CommandContext(ctx, s.manager.GetBinaryPath(), "-g", "--artifact", configName)
	cmd.Dir = s.manager.GetWorkDir()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
