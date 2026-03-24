package subconverter

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const (
	defaultVersion = "v0.9.2"
	repoOwner      = "MetaCubeX"
	repoName       = "subconverter"
	binaryName     = "subconverter"
	sourceMetaName = ".download-source"
)

// Downloader handles subconverter binary download
type Downloader struct {
	client  *http.Client
	baseDir string
	version string
}

// getPlatformFilename returns the appropriate subconverter filename for the current platform
func getPlatformFilename() string {
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	switch {
	case goos == "darwin" && goarch == "amd64":
		return "subconverter_darwin64.tar.gz"
	case goos == "darwin" && goarch == "arm64":
		return "subconverter_darwinarm.tar.gz"
	case goos == "linux" && goarch == "amd64":
		return "subconverter_linux64.tar.gz"
	case goos == "linux" && goarch == "arm64":
		return "subconverter_aarch64.tar.gz"
	default:
		return "subconverter_linux64.tar.gz" // 默认
	}
}

// buildDownloadURL constructs the download URL for the given version
func buildDownloadURL(version string) string {
	filename := getPlatformFilename()
	return fmt.Sprintf("https://github.com/%s/%s/releases/download/%s/%s", repoOwner, repoName, version, filename)
}

// NewDownloader creates a new downloader
func NewDownloader(baseDir, version string) *Downloader {
	return &Downloader{
		client: &http.Client{
			Timeout: 5 * time.Minute,
		},
		baseDir: baseDir,
		version: version,
	}
}

// DownloadIfNeeded downloads subconverter if not exists
func (d *Downloader) DownloadIfNeeded(customURL string) (string, error) {
	expectedSource := d.expectedSource(customURL)
	if binaryPath, err := d.resolveBinaryPath(); err == nil {
		if d.shouldReuseExistingBinary(expectedSource) {
			slog.Info("Subconverter binary exists", "path", binaryPath, "source", expectedSource)
			return binaryPath, nil
		}

		slog.Info("Subconverter binary source changed, re-downloading", "path", binaryPath, "source", expectedSource)
	}

	// Remove directory if exists (for clean re-download)
	if err := os.RemoveAll(d.baseDir); err != nil {
		return "", fmt.Errorf("remove existing directory: %w", err)
	}

	// Create directory
	if err := os.MkdirAll(d.baseDir, 0755); err != nil {
		return "", fmt.Errorf("create directory: %w", err)
	}

	// Determine download URL
	downloadURL := expectedSource

	slog.Info("Downloading subconverter", "url", downloadURL, "platform", runtime.GOOS+"/"+runtime.GOARCH)

	// Download tar.gz
	resp, err := d.client.Get(downloadURL)
	if err != nil {
		return "", fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed with status: %d", resp.StatusCode)
	}

	// Extract tar.gz
	if err := d.extractTarGz(resp.Body, d.baseDir); err != nil {
		return "", fmt.Errorf("extract failed: %w", err)
	}

	if err := d.writeSourceMeta(expectedSource); err != nil {
		return "", fmt.Errorf("write source metadata: %w", err)
	}

	slog.Info("Subconverter downloaded successfully")
	return d.resolveBinaryPath()
}

func (d *Downloader) expectedSource(customURL string) string {
	if customURL != "" {
		return customURL
	}
	if d.version != "" {
		return buildDownloadURL(d.version)
	}
	return buildDownloadURL(defaultVersion)
}

func (d *Downloader) shouldReuseExistingBinary(expectedSource string) bool {
	sourcePath := filepath.Join(d.baseDir, sourceMetaName)
	content, err := os.ReadFile(sourcePath)
	if err != nil {
		return false
	}

	return string(content) == expectedSource
}

func (d *Downloader) writeSourceMeta(source string) error {
	return os.WriteFile(filepath.Join(d.baseDir, sourceMetaName), []byte(source), 0644)
}

// extractTarGz extracts a tar.gz archive
func (d *Downloader) extractTarGz(r io.Reader, destDir string) error {
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		target := filepath.Join(destDir, header.Name)

		// Create directory
		if header.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
			continue
		}

		// Create file
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}

		f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY, os.FileMode(header.Mode))
		if err != nil {
			return err
		}

		if _, err := io.Copy(f, tr); err != nil {
			f.Close()
			return err
		}
		f.Close()
	}

	return nil
}

func (d *Downloader) resolveBinaryPath() (string, error) {
	candidates := []string{
		filepath.Join(d.baseDir, binaryName),
		filepath.Join(d.baseDir, binaryName, binaryName),
	}
	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("subconverter binary not found under %s", d.baseDir)
}
