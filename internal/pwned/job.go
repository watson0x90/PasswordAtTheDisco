package pwned

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/hibp"
)

// Phase is the current stage of the download/index job.
type Phase string

const (
	PhaseIdle        Phase = "idle"
	PhaseDownloading Phase = "downloading"
	PhaseIndexing    Phase = "indexing"
	PhaseDone        Phase = "done"
	PhaseFailed      Phase = "failed"
	PhaseCancelled   Phase = "cancelled"
)

// approxFullBytes is a rough size of the full NTLM set, used only as a denominator
// for a coarse download progress bar when no prior file size is known.
const approxFullBytes int64 = 78 << 30 // ~83 GB

// JobStatus is the snapshot the UI polls.
type JobStatus struct {
	Phase        Phase  `json:"phase"`
	Resume       bool   `json:"resume"`
	StartedAt    string `json:"started_at,omitempty"`
	EndedAt      string `json:"ended_at,omitempty"`
	ElapsedSec   int64  `json:"elapsed_sec"`
	BytesNow     int64  `json:"bytes_now"`     // size of the file currently being written
	EstTotal     int64  `json:"est_total"`     // approx full size (coarse % denominator)
	RateBps      int64  `json:"rate_bps"`      // download rate (bytes/sec)
	IndexScanned int64  `json:"index_scanned"` // bytes scanned during the index build
	IndexEntries int    `json:"index_entries"` // prefixes written (after indexing)
	DataFile     string `json:"data_file"`
	Error        string `json:"error,omitempty"`
}

// Manager runs at most one download/index job at a time for one data file. A
// download writes to a sibling staging file, builds its index, then atomically
// swaps both over the live file -- so the live HIBP corpus stays usable during the
// (long) download and a failed/cancelled download never touches it.
type Manager struct {
	dir       string // PwnedPasswordsDownloader source dir
	dataFile  string // live target .txt (== PATD_HIBP)
	prefixLen int

	// Optional hooks invoked around the final file swap so the server can release
	// its open handle on the live file (needed on Windows) and reacquire it on the
	// freshly downloaded one. No-ops if nil.
	BeforeSwap func()
	AfterSwap  func()

	mu           sync.Mutex
	phase        Phase
	resume       bool
	startedAt    time.Time
	endedAt      time.Time
	bytesAtStart int64
	estTotal     int64
	sizeFile     string // file to stat for BytesNow (staging during a run, live otherwise)
	indexScanned int64
	indexEntries int
	errMsg       string
	cancel       context.CancelFunc
	output       *ringBuffer
}

// NewManager returns a job manager for dataFile (the NTLM .txt) using the
// downloader source under dir. prefixLen is the index prefix length (5).
func NewManager(dir, dataFile string, prefixLen int) *Manager {
	return &Manager{dir: dir, dataFile: dataFile, prefixLen: prefixLen, phase: PhaseIdle, sizeFile: dataFile}
}

func (m *Manager) exePath() string {
	proj, err := findProject(m.dir)
	if err != nil {
		return ""
	}
	return findExe(filepath.Dir(proj))
}

// stagingTxt is the sibling file the downloader writes to (kept separate from the
// live file so the live corpus stays usable until the atomic swap).
func (m *Manager) stagingTxt() string {
	base := strings.TrimSuffix(filepath.Base(m.dataFile), ".txt")
	return filepath.Join(filepath.Dir(m.dataFile), base+".new.txt")
}

func fileSize(path string) int64 {
	if fi, err := os.Stat(path); err == nil {
		return fi.Size()
	}
	return 0
}

// Start launches the downloader in the background, writing to a staging file. On a
// clean exit it builds the staging index and swaps both over the live file. resume
// continues a previous interrupted download. Errors if a job is running or the tool
// isn't built.
func (m *Manager) Start(resume bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.phase == PhaseDownloading || m.phase == PhaseIndexing {
		return fmt.Errorf("a job is already running (%s)", m.phase)
	}
	exe := m.exePath()
	if exe == "" {
		return fmt.Errorf("downloader is not built -- build it first")
	}
	// Absolute paths: exec resolves a relative Path against cmd.Dir, not the parent
	// CWD, so a relative exe + a set Dir fails to find the binary.
	if abs, err := filepath.Abs(exe); err == nil {
		exe = abs
	}
	workDir := filepath.Dir(m.dataFile)
	if abs, err := filepath.Abs(workDir); err == nil {
		workDir = abs
	}
	staging := m.stagingTxt()
	stagingBase := strings.TrimSuffix(filepath.Base(staging), ".txt") // pwnedpasswords_ntlm.new

	m.estTotal = fileSize(m.dataFile) // the live file is a good full-size estimate
	if m.estTotal < approxFullBytes {
		m.estTotal = approxFullBytes
	}
	m.phase = PhaseDownloading
	m.resume = resume
	m.startedAt = time.Now()
	m.endedAt = time.Time{}
	m.errMsg = ""
	m.indexScanned = 0
	m.indexEntries = 0
	m.sizeFile = staging
	if resume {
		m.bytesAtStart = fileSize(staging)
	} else {
		m.bytesAtStart = 0
	}

	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.output = &ringBuffer{max: 16000}

	args := []string{"-n", stagingBase}
	if resume {
		args = append(args, "-r")
	} else {
		args = append(args, "-o")
	}
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Dir = workDir
	// Capture both streams: the .NET tool writes errors (and its progress TUI) to
	// stdout, so discarding it loses the failure reason. The ring buffer keeps only
	// the tail, so the ANSI progress noise doesn't accumulate.
	cmd.Stdout = m.output
	cmd.Stderr = m.output
	if err := cmd.Start(); err != nil {
		m.phase = PhaseFailed
		m.errMsg = "failed to start downloader: " + err.Error()
		m.sizeFile = m.dataFile
		cancel()
		return err
	}
	go m.runDownload(ctx, cmd, staging)
	return nil
}

func (m *Manager) runDownload(ctx context.Context, cmd *exec.Cmd, staging string) {
	err := cmd.Wait()

	m.mu.Lock()
	if ctx.Err() != nil { // cancelled by Cancel()
		m.phase = PhaseCancelled
		m.endedAt = time.Now()
		m.sizeFile = m.dataFile // live file is untouched
		m.mu.Unlock()
		return
	}
	if err != nil {
		m.phase = PhaseFailed
		m.endedAt = time.Now()
		m.sizeFile = m.dataFile
		m.errMsg = fmt.Sprintf("download failed: %v\n%s", err, strings.TrimSpace(m.output.String()))
		m.mu.Unlock()
		return
	}
	m.phase = PhaseIndexing
	prefixLen := m.prefixLen
	m.mu.Unlock()

	// Index the staging file, then atomically swap both into place.
	n, ierr := hibp.BuildIndex(staging, prefixLen, m.indexProgress)
	if ierr != nil {
		m.finish(PhaseFailed, 0, "index build failed: "+ierr.Error(), m.dataFile)
		return
	}
	if serr := m.swapIntoPlace(staging, prefixLen); serr != nil {
		m.finish(PhaseFailed, 0, "swap failed: "+serr.Error(), m.dataFile)
		return
	}
	m.finish(PhaseDone, n, "", m.dataFile)
}

// swapIntoPlace replaces the live data file + index with the staging ones,
// releasing/reacquiring the live HIBP handle around the rename (Windows requires
// the handle released to replace an open file).
func (m *Manager) swapIntoPlace(staging string, prefixLen int) error {
	if m.BeforeSwap != nil {
		m.BeforeSwap()
	}
	rerr := os.Rename(staging, m.dataFile)
	if rerr == nil {
		rerr = os.Rename(hibp.IndexPath(staging, prefixLen), hibp.IndexPath(m.dataFile, prefixLen))
	}
	if m.AfterSwap != nil {
		m.AfterSwap() // reacquire on whatever the live file now is (new on success, old on failure)
	}
	return rerr
}

// StartIndexOnly builds the index for the existing live data file in place, no
// download (rebuild a missing/stale index, or after an out-of-band download).
func (m *Manager) StartIndexOnly() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.phase == PhaseDownloading || m.phase == PhaseIndexing {
		return fmt.Errorf("a job is already running (%s)", m.phase)
	}
	if fileSize(m.dataFile) == 0 {
		return fmt.Errorf("no data file at %s -- download it first", m.dataFile)
	}
	m.phase = PhaseIndexing
	m.resume = false
	m.startedAt = time.Now()
	m.endedAt = time.Time{}
	m.errMsg = ""
	m.indexScanned = 0
	m.indexEntries = 0
	m.sizeFile = m.dataFile
	dataFile, prefixLen := m.dataFile, m.prefixLen
	go func() {
		n, err := hibp.BuildIndex(dataFile, prefixLen, m.indexProgress)
		if err != nil {
			m.finish(PhaseFailed, 0, "index build failed: "+err.Error(), dataFile)
			return
		}
		m.finish(PhaseDone, n, "", dataFile)
	}()
	return nil
}

func (m *Manager) indexProgress(scanned int64) {
	m.mu.Lock()
	m.indexScanned = scanned
	m.mu.Unlock()
}

func (m *Manager) finish(phase Phase, entries int, errMsg, sizeFile string) {
	m.mu.Lock()
	m.phase = phase
	m.endedAt = time.Now()
	m.indexEntries = entries
	m.errMsg = errMsg
	m.sizeFile = sizeFile
	m.mu.Unlock()
}

// Cancel stops an in-progress download (the partial staging file + checkpoint
// remain, so a later resume can continue). Only a download is cancellable.
func (m *Manager) Cancel() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.phase != PhaseDownloading {
		return fmt.Errorf("nothing to cancel (phase %s)", m.phase)
	}
	if m.cancel != nil {
		m.cancel()
	}
	return nil
}

// Status returns a snapshot for the UI to poll.
func (m *Manager) Status() JobStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := JobStatus{
		Phase:        m.phase,
		Resume:       m.resume,
		EstTotal:     m.estTotal,
		IndexScanned: m.indexScanned,
		IndexEntries: m.indexEntries,
		DataFile:     m.dataFile,
		Error:        m.errMsg,
	}
	if !m.startedAt.IsZero() {
		st.StartedAt = m.startedAt.UTC().Format(time.RFC3339)
		end := m.endedAt
		if end.IsZero() {
			end = time.Now()
		}
		if s := int64(end.Sub(m.startedAt).Seconds()); s > 0 {
			st.ElapsedSec = s
		}
	}
	if !m.endedAt.IsZero() {
		st.EndedAt = m.endedAt.UTC().Format(time.RFC3339)
	}
	st.BytesNow = fileSize(m.sizeFile)
	if m.phase == PhaseDownloading && st.ElapsedSec > 0 {
		if r := (st.BytesNow - m.bytesAtStart) / st.ElapsedSec; r > 0 {
			st.RateBps = r
		}
	}
	return st
}

// ringBuffer keeps only the last max bytes written (process output tail).
type ringBuffer struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func (r *ringBuffer) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, p...)
	if len(r.buf) > r.max {
		r.buf = r.buf[len(r.buf)-r.max:]
	}
	return len(p), nil
}

func (r *ringBuffer) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return string(r.buf)
}
