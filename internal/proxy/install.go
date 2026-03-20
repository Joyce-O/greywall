package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	githubOwner      = "greyhavenhq"
	githubRepo       = "greyproxy"
	greyproxyRepoURL = "https://github.com/greyhavenhq/greyproxy.git"
	apiTimeout       = 15 * time.Second
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

// fetchLatestRelease queries the GitHub API for the latest greyproxy release.
func fetchLatestRelease() (*release, error) {
	return fetchReleaseFor(nil, "", githubOwner, githubRepo, "latest")
}

// runGreyproxyInstall shells out to the extracted greyproxy binary with "install --force".
func runGreyproxyInstall(binaryPath string) error {
	cmd := exec.Command(binaryPath, "install", "--force") //nolint:gosec // binaryPath is from our extracted archive
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// SourceBuildOptions controls the source-build installation behavior.
type SourceBuildOptions struct {
	Output io.Writer // progress output (typically os.Stderr)
	Tag    string    // specific tag to build; if empty, uses latest
	Beta   bool      // if Tag is empty and Beta is true, fetches latest pre-release tag
}

// InstallFromSource clones the greyproxy repo at the given tag, builds it,
// and runs "greyproxy install --force" to register the service.
// Requires git and go on PATH.
func InstallFromSource(opts SourceBuildOptions) error {
	if opts.Output == nil {
		opts.Output = os.Stderr
	}

	tag := opts.Tag
	if tag == "" {
		var err error
		tag, err = CheckLatestTag(opts.Beta)
		if err != nil {
			return fmt.Errorf("failed to fetch latest tag: %w", err)
		}
	}
	_, _ = fmt.Fprintf(opts.Output, "Building greyproxy %s from source...\n", tag)

	if _, err := exec.LookPath("git"); err != nil {
		return fmt.Errorf("git is required to build from source: install git and try again")
	}
	if _, err := exec.LookPath("go"); err != nil {
		return fmt.Errorf("go is required to build from source: install Go from https://go.dev/dl/ and try again")
	}

	tmpDir, err := os.MkdirTemp("", "greyproxy-build-*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	_, _ = fmt.Fprintf(opts.Output, "Cloning greyproxy...\n")
	cloneCmd := exec.Command("git", "clone", "--depth=1", "--branch", tag, greyproxyRepoURL, tmpDir) //nolint:gosec // URL and tag are from hardcoded constants and GitHub API
	cloneCmd.Stdout = opts.Output
	cloneCmd.Stderr = opts.Output
	if err := cloneCmd.Run(); err != nil {
		return fmt.Errorf("git clone failed: %w", err)
	}

	_, _ = fmt.Fprintf(opts.Output, "Building...\n")
	ver := strings.TrimPrefix(tag, "v")
	buildCmd := exec.Command("go", "build", //nolint:gosec // arguments are controlled constants and a sanitized version string
		"-ldflags", fmt.Sprintf("-s -w -X main.version=%s", ver),
		"-o", "greyproxy",
		"./cmd/greyproxy",
	)
	buildCmd.Dir = tmpDir
	buildCmd.Stdout = opts.Output
	buildCmd.Stderr = opts.Output
	if err := buildCmd.Run(); err != nil {
		return fmt.Errorf("build failed: %w", err)
	}

	binaryPath := filepath.Join(tmpDir, "greyproxy")
	_, _ = fmt.Fprintf(opts.Output, "\n")
	if err := runGreyproxyInstall(binaryPath); err != nil {
		return fmt.Errorf("greyproxy install failed: %w", err)
	}

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

// CheckLatestTag returns the latest greyproxy release tag (with "v" prefix).
// If beta is true, returns the latest pre-release tag.
func CheckLatestTag(beta bool) (string, error) {
	return CheckLatestTagFor(githubOwner, githubRepo, beta)
}

// CheckLatestTagFor returns the latest release tag for any GitHub repo.
// If beta is true, returns the latest pre-release tag; otherwise returns the latest stable tag.
func CheckLatestTagFor(owner, repo string, beta bool) (string, error) {
	return checkLatestTagFor(nil, "", owner, repo, beta)
}

func checkLatestTagFor(client *http.Client, apiBase, owner, repo string, beta bool) (string, error) {
	if !beta {
		rel, err := fetchReleaseFor(client, apiBase, owner, repo, "latest")
		if err != nil {
			return "", err
		}
		return rel.TagName, nil
	}
	return fetchLatestPreReleaseTagFor(client, apiBase, owner, repo)
}

// fetchReleaseFor fetches a specific GitHub release endpoint (e.g. "latest" or a tag name).
// client and apiBase are optional; nil/empty use production defaults.
func fetchReleaseFor(client *http.Client, apiBase, owner, repo, endpoint string) (*release, error) {
	if client == nil {
		client = &http.Client{Timeout: apiTimeout}
	}
	if apiBase == "" {
		apiBase = "https://api.github.com"
	}
	apiURL := fmt.Sprintf("%s/repos/%s/%s/releases/%s", apiBase, owner, repo, endpoint)

	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "greywall-setup")

	resp, err := client.Do(req) //nolint:gosec // apiURL is built from controlled inputs
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

// fetchLatestPreReleaseTagFor returns the most recent pre-release tag for the given repo.
// client and apiBase are optional; nil/empty use production defaults.
func fetchLatestPreReleaseTagFor(client *http.Client, apiBase, owner, repo string) (string, error) {
	if client == nil {
		client = &http.Client{Timeout: apiTimeout}
	}
	if apiBase == "" {
		apiBase = "https://api.github.com"
	}
	apiURL := fmt.Sprintf("%s/repos/%s/%s/releases?per_page=20", apiBase, owner, repo)

	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "greywall-setup")

	resp, err := client.Do(req) //nolint:gosec // apiURL is built from controlled inputs
	if err != nil {
		return "", fmt.Errorf("GitHub API request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var releases []struct {
		TagName    string `json:"tag_name"`
		PreRelease bool   `json:"prerelease"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return "", fmt.Errorf("failed to parse releases response: %w", err)
	}

	for _, r := range releases {
		if r.PreRelease {
			return r.TagName, nil
		}
	}
	return "", fmt.Errorf("no pre-release found for %s/%s", owner, repo)
}
