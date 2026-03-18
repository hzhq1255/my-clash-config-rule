package service

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hzhq1255/my-clash-config-rule/subserver/internal/model"
)

// AuthService handles authentication
type AuthService struct {
	client       *http.Client
	domain       string
	email        string
	passwd       string
	session      *http.CookieJar
	sessionMutex sync.RWMutex
	loginTime    time.Time
}

// NewAuthService creates a new auth service
func NewAuthService(domain, email, passwd string) *AuthService {
	return &AuthService{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		domain: domain,
		email:  email,
		passwd: passwd,
	}
}

// Login performs login and stores session
func (s *AuthService) Login() error {
	s.sessionMutex.Lock()
	defer s.sessionMutex.Unlock()

	// Check if session is still valid (8 hours)
	if time.Since(s.loginTime) < 8*time.Hour && s.client != nil {
		return nil
	}

	url := fmt.Sprintf("https://%s/auth/login", s.domain)
	params := map[string]string{
		"email": s.email,
		"passwd": s.passwd,
		"code":   "",
	}

	// Build form data
	formData := ""
	for k, v := range params {
		if formData != "" {
			formData += "&"
		}
		formData += fmt.Sprintf("%s=%s", k, v)
	}

	req, err := http.NewRequest("POST", url, strings.NewReader(formData))
	if err != nil {
		return fmt.Errorf("create login request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read login response: %w", err)
	}

	var loginResp model.LoginResponse
	if err := json.Unmarshal(body, &loginResp); err != nil {
		return fmt.Errorf("parse login response: %w", err)
	}

	if loginResp.Ret != 1 {
		return fmt.Errorf("login failed with ret: %d", loginResp.Ret)
	}

	// Store cookies from response
	// TODO: Implement cookie jar to store session cookies

	s.loginTime = time.Now()
	slog.Info("Login successful")
	return nil
}

// GetClient returns an HTTP client with active session
func (s *AuthService) GetClient() (*http.Client, error) {
	if err := s.Login(); err != nil {
		return nil, err
	}
	return s.client, nil
}

// DoRequest executes a request with authentication
func (s *AuthService) DoRequest(req *http.Request) (*http.Response, error) {
	client, err := s.GetClient()
	if err != nil {
		return nil, err
	}

	// Add cookies from session
	// TODO: Implement cookie management

	return client.Do(req)
}
