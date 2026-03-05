package proxy

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	githubOwner = "greyhavenhq"
	githubRepo  = "greyproxy"
	apiTimeout  = 15 * time.Second
)

// release represents a GitHub release.
type release struct {
	TagName string  `json:"tag_name"`
	Assets  []asset `json:"assets"`
}

// asset represents a release asset.
type asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// InstallOptions controls the greyproxy installation behavior.
type InstallOptions struct {
	Output io.Writer // progress output (typically os.Stderr)
}

// CheckLatestVersion fetches the latest greyproxy release tag from GitHub
// and returns the version string (without the "v" prefix).
func CheckLatestVersion() (string, error) {
	rel, err := fetchLatestRelease()
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(rel.TagName, "v"), nil
}

// IsOlderVersion returns true if current is strictly older than latest,
// or if current is not a valid semver string (e.g. "dev").
// Both strings should be in "major.minor.patch" format (no "v" prefix).
func IsOlderVersion(current, latest string) bool {
	cp := strings.SplitN(current, ".", 3)
	lp := strings.SplitN(latest, ".", 3)
	if len(lp) != 3 {
		return false
	}
	// If current is not valid semver (e.g. "dev"), treat as outdated.
	if len(cp) != 3 {
		return true
	}
	for i := 0; i < 3; i++ {
		c, err1 := strconv.Atoi(cp[i])
		l, err2 := strconv.Atoi(lp[i])
		if err1 != nil {
			return true
		}
		if err2 != nil {
			return false
		}
		if c < l {
			return true
		}
		if c > l {
			return false
		}
	}
	return false
}

// Install downloads the latest greyproxy release and runs "greyproxy install".
// Set GREYWALL_NO_GREYPROXY_INSTALL=1 to skip installation entirely.
func Install(opts InstallOptions) error {
	if os.Getenv("GREYWALL_NO_GREYPROXY_INSTALL") == "1" {
		return nil
	}

	if opts.Output == nil {
		opts.Output = os.Stderr
	}

	// 1. Fetch latest release
	_, _ = fmt.Fprintf(opts.Output, "Fetching latest greyproxy release...\n")
	rel, err := fetchLatestRelease()
	if err != nil {
		return fmt.Errorf("failed to fetch latest release: %w", err)
	}
	ver := strings.TrimPrefix(rel.TagName, "v")
	_, _ = fmt.Fprintf(opts.Output, "Latest version: %s\n", ver)

	// 2. Find the correct asset for this platform
	assetURL, assetName, err := resolveAssetURL(rel)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(opts.Output, "Downloading %s...\n", assetName)

	// 3. Download to temp file
	archivePath, err := downloadAsset(assetURL)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer func() { _ = os.Remove(archivePath) }()

	// 4. Extract
	_, _ = fmt.Fprintf(opts.Output, "Extracting...\n")
	extractDir, err := extractTarGz(archivePath)
	if err != nil {
		return fmt.Errorf("extraction failed: %w", err)
	}
	defer func() { _ = os.RemoveAll(extractDir) }()

	// 5. Find the greyproxy binary in extracted content
	binaryPath := filepath.Join(extractDir, "greyproxy")
	if _, err := os.Stat(binaryPath); err != nil {
		return fmt.Errorf("greyproxy binary not found in archive")
	}

	// 6. Shell out to "greyproxy install"
	_, _ = fmt.Fprintf(opts.Output, "\n")
	if err := runGreyproxyInstall(binaryPath); err != nil {
		return fmt.Errorf("greyproxy install failed: %w", err)
	}

	// 7. Verify
	_, _ = fmt.Fprintf(opts.Output, "\nVerifying installation...\n")
	status := Detect()
	if status.Installed {
		_, _ = fmt.Fprintf(opts.Output, "greyproxy %s installed at %s\n", status.Version, status.Path)
		if status.Running {
			_, _ = fmt.Fprintf(opts.Output, "greyproxy is running.\n")
		}
	} else {
		_, _ = fmt.Fprintf(opts.Output, "Warning: greyproxy not found on PATH after install.\n")
		_, _ = fmt.Fprintf(opts.Output, "Ensure ~/.local/bin is in your PATH.\n")
	}

	return nil
}

// fetchLatestRelease queries the GitHub API for the latest greyproxy release.
func fetchLatestRelease() (*release, error) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", githubOwner, githubRepo)

	client := &http.Client{Timeout: apiTimeout}

	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "greywall-setup")

	resp, err := client.Do(req) //nolint:gosec // apiURL is built from hardcoded constants
	if err != nil {
		return nil, fmt.Errorf("GitHub API request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var rel release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("failed to parse release response: %w", err)
	}
	return &rel, nil
}

// resolveAssetURL finds the correct asset download URL for the current OS/arch.
func resolveAssetURL(rel *release) (downloadURL, name string, err error) {
	ver := strings.TrimPrefix(rel.TagName, "v")
	osName := runtime.GOOS
	archName := runtime.GOARCH

	expected := fmt.Sprintf("greyproxy_%s_%s_%s.tar.gz", ver, osName, archName)

	for _, a := range rel.Assets {
		if a.Name == expected {
			return a.BrowserDownloadURL, a.Name, nil
		}
	}
	return "", "", fmt.Errorf("no release asset found for %s/%s (expected: %s)", osName, archName, expected)
}

// downloadAsset downloads a URL to a temp file, returning its path.
func downloadAsset(downloadURL string) (string, error) {
	client := &http.Client{Timeout: 5 * time.Minute}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req) //nolint:gosec // downloadURL comes from GitHub API response
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download returned status %d", resp.StatusCode)
	}

	tmpFile, err := os.CreateTemp("", "greyproxy-*.tar.gz")
	if err != nil {
		return "", err
	}

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name()) //nolint:gosec // tmpFile.Name() is from os.CreateTemp, not user input
		return "", err
	}
	_ = tmpFile.Close()

	return tmpFile.Name(), nil
}

// extractTarGz extracts a .tar.gz archive to a temp directory, returning the dir path.
func extractTarGz(archivePath string) (string, error) {
	f, err := os.Open(archivePath) //nolint:gosec // archivePath is a temp file we created
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tmpDir, err := os.MkdirTemp("", "greyproxy-extract-*")
	if err != nil {
		return "", err
	}

	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			_ = os.RemoveAll(tmpDir)
			return "", fmt.Errorf("tar read error: %w", err)
		}

		// Sanitize: only extract regular files with safe names
		name := filepath.Base(header.Name)
		if name == "." || name == ".." || strings.Contains(header.Name, "..") {
			continue
		}

		target := filepath.Join(tmpDir, name) //nolint:gosec // name is sanitized via filepath.Base and path traversal check above

		switch header.Typeflag {
		case tar.TypeReg:
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode)) //nolint:gosec // mode from tar header of trusted archive
			if err != nil {
				_ = os.RemoveAll(tmpDir)
				return "", err
			}
			if _, err := io.Copy(out, io.LimitReader(tr, 256<<20)); err != nil { // 256 MB limit per file
				_ = out.Close()
				_ = os.RemoveAll(tmpDir)
				return "", err
			}
			_ = out.Close()
		}
	}

	return tmpDir, nil
}

// runGreyproxyInstall shells out to the extracted greyproxy binary with "install --force".
func runGreyproxyInstall(binaryPath string) error {
	cmd := exec.Command(binaryPath, "install", "--force") //nolint:gosec // binaryPath is from our extracted archive
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
