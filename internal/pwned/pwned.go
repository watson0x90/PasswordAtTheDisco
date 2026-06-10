// Package pwned is an admin helper for preparing the offline HaveIBeenPwned NTLM
// hash set: it builds the bundled PwnedPasswordsDownloader (.NET) tool and probes
// the HIBP k-anonymity range API. It shells out to `dotnet` ONLY on an explicit,
// lead-gated request, with fixed arguments (no user input flows into the command),
// so there is no command-injection surface.
package pwned

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// rangeAPI is the HIBP k-anonymity range endpoint; mode=ntlm returns NTLM suffixes.
const rangeAPI = "https://api.pwnedpasswords.com/range/"

const projectName = "HaveIBeenPwned.PwnedPasswords.Downloader.csproj"

// exeName is the assembly the downloader builds (AssemblyName in the .csproj).
func exeName() string {
	if runtime.GOOS == "windows" {
		return "haveibeenpwned-downloader.exe"
	}
	return "haveibeenpwned-downloader"
}

// Status is the local downloader + data state shown on the page.
type Status struct {
	SourceDir     string `json:"source_dir"`
	SourcePresent bool   `json:"source_present"`
	DotnetVersion string `json:"dotnet_version,omitempty"`
	Built         bool   `json:"built"`
	ExePath       string `json:"exe_path,omitempty"`
	DataFile      string `json:"data_file,omitempty"`
	DataBytes     int64  `json:"data_bytes"`
}

// Stat reports whether the downloader source, a prior build, and the data file are
// present. dataFile is the configured HIBP NTLM index path (may be empty).
func Stat(dir, dataFile string) Status {
	s := Status{SourceDir: dir, DataFile: dataFile}
	if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
		s.SourcePresent = true
	}
	if proj, err := findProject(dir); err == nil {
		if exe := findExe(filepath.Dir(proj)); exe != "" {
			s.Built, s.ExePath = true, exe
		}
	}
	if dataFile != "" {
		if fi, err := os.Stat(dataFile); err == nil {
			s.DataBytes = fi.Size()
		}
	}
	if out, err := exec.Command("dotnet", "--version").Output(); err == nil {
		s.DotnetVersion = strings.TrimSpace(string(out))
	}
	return s
}

// BuildResult summarizes a `dotnet build`.
type BuildResult struct {
	OK      bool   `json:"ok"`
	ExePath string `json:"exe_path,omitempty"`
	Output  string `json:"output"` // tail of combined stdout/stderr
	Elapsed string `json:"elapsed"`
}

// Build compiles the downloader (`dotnet build -c Release`). The csproj path is
// derived from dir (not user input). The caller supplies the timeout via ctx.
func Build(ctx context.Context, dir string) (BuildResult, error) {
	proj, err := findProject(dir)
	if err != nil {
		return BuildResult{}, err
	}
	if _, err := exec.LookPath("dotnet"); err != nil {
		return BuildResult{}, fmt.Errorf("dotnet SDK not found on PATH: %w", err)
	}
	start := time.Now()
	cmd := exec.CommandContext(ctx, "dotnet", "build", "-c", "Release", proj)
	out, err := cmd.CombinedOutput()
	res := BuildResult{Output: tail(string(out), 8000), Elapsed: time.Since(start).Round(time.Millisecond).String()}
	if err != nil {
		return res, fmt.Errorf("dotnet build failed: %w", err)
	}
	res.OK = true
	res.ExePath = findExe(filepath.Dir(proj))
	return res, nil
}

// ProbeResult summarizes a single HIBP range request (the "simple request").
type ProbeResult struct {
	OK       bool   `json:"ok"`
	URL      string `json:"url"`
	Status   int    `json:"status"`
	Suffixes int    `json:"suffixes"`
	Sample   string `json:"sample,omitempty"` // first line, e.g. "0005AD7…:10" (public)
	Elapsed  string `json:"elapsed"`
}

// Probe makes ONE NTLM range request to confirm the download source is reachable.
// It downloads only one ~60 KB prefix range, not the full set.
func Probe(ctx context.Context) (ProbeResult, error) {
	url := rangeAPI + "00000?mode=ntlm"
	start := time.Now()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "PasswordAtTheDisco-probe")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ProbeResult{URL: url, Elapsed: time.Since(start).Round(time.Millisecond).String()}, err
	}
	defer resp.Body.Close()
	res := ProbeResult{URL: url, Status: resp.StatusCode}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if res.Suffixes == 0 {
			res.Sample = strings.TrimSpace(sc.Text())
		}
		res.Suffixes++
	}
	res.OK = resp.StatusCode == http.StatusOK && res.Suffixes > 0
	res.Elapsed = time.Since(start).Round(time.Millisecond).String()
	return res, nil
}

// --- helpers ---

func findProject(dir string) (string, error) {
	cands, _ := filepath.Glob(filepath.Join(dir, "src", "*", projectName))
	if len(cands) == 0 {
		cands, _ = filepath.Glob(filepath.Join(dir, "src", "*", "*.csproj"))
	}
	if len(cands) == 0 {
		return "", fmt.Errorf("downloader project not found under %s", filepath.Join(dir, "src"))
	}
	return cands[0], nil
}

func findExe(projDir string) string {
	name := exeName()
	for _, tfm := range []string{"net9.0", "net8.0"} {
		p := filepath.Join(projDir, "bin", "Release", tfm, name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if cands, _ := filepath.Glob(filepath.Join(projDir, "bin", "Release", "*", name)); len(cands) > 0 {
		return cands[0]
	}
	return ""
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "...(truncated)...\n" + s[len(s)-n:]
}
