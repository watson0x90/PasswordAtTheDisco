// Package vault provides encrypted-at-rest persistence for audit data. A random
// 32-byte data-encryption key (DEK) encrypts each audit with AES-256-GCM. The DEK
// itself is wrapped with a key-encryption key derived from an operator passphrase
// via argon2id and stored in a keyfile. The DEK exists in memory only after a
// successful Unlock, so on disk nothing is readable without the passphrase.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	keyfileName  = "keyfile.json"
	auditsSubdir = "audits"
	dekLen       = 32
	saltLen      = 16

	keyfileVersion = 1

	// argon2id parameters for deriving the key-encryption key. The unlock is rare,
	// so these are deliberately heavier than an interactive login KDF.
	argonTime    = 4
	argonMemory  = 128 * 1024 // 128 MiB
	argonThreads = 4
	// Floors accepted when reading an existing keyfile (older keyfiles + tamper guard).
	minArgonTime   = 2
	minArgonMemory = 32 * 1024
)

var (
	// ErrLocked is returned when an operation needs the DEK but the vault is locked.
	ErrLocked = errors.New("vault is locked")
	// ErrNotInitialized is returned when unlocking before a keyfile exists.
	ErrNotInitialized = errors.New("vault not initialized")
	// ErrBadPassphrase is returned when the passphrase fails to unwrap the DEK.
	ErrBadPassphrase = errors.New("incorrect passphrase")
	// ErrNoIndex is returned by LoadIndex when no index file exists yet.
	ErrNoIndex = errors.New("no index file")
	// ErrRekeyInProgress is returned when a rekey is requested while one is running.
	ErrRekeyInProgress = errors.New("a data-key rotation is already in progress")
)

type keyfile struct {
	Version    int    `json:"version"`
	KDF        string `json:"kdf"`
	Salt       string `json:"salt"`
	Time       uint32 `json:"time"`
	Memory     uint32 `json:"memory"`
	Threads    uint8  `json:"threads"`
	WrappedDEK string `json:"wrapped_dek"`
	// WrappedPrevDEK is the previous DEK, present only while a Rekey is mid-flight
	// (so blobs not yet re-sealed remain readable). Wrapped under the same KEK.
	WrappedPrevDEK string `json:"wrapped_prev_dek,omitempty"`
}

// Vault stores encrypted audits under a directory. Safe for concurrent use.
type Vault struct {
	dir           string
	mu            sync.RWMutex
	dek           []byte       // primary DEK; nil when locked
	prevDEK       []byte       // previous DEK during a rekey; reads fall back to it
	seals         atomic.Int64 // blob/index seals under the current DEK (nonce odometer)
	noncesWarned  atomic.Bool  // one-shot guard for the nonce-budget warning
	rekeying      atomic.Bool  // true while Rekey holds the exclusive lock (lock-free probe)
	rekeyStartedN atomic.Int64 // unix-nano a rekey began (0 = none); for /healthz observability
}

// Rekeying reports whether a data-key rotation is in progress (lock-free, so it
// stays responsive while Rekey holds the exclusive lock).
func (v *Vault) Rekeying() bool { return v.rekeying.Load() }

// RekeyElapsed reports how long the in-progress rekey has been running (0 if none),
// so a monitor can alert on a wedged rotation without the server self-killing.
func (v *Vault) RekeyElapsed() time.Duration {
	start := v.rekeyStartedN.Load()
	if start == 0 {
		return 0
	}
	return time.Duration(time.Now().UnixNano() - start)
}

// nonceWarnThreshold is a conservative PER-SESSION sanity tripwire (the counter
// resets on each Unlock, so it is not lifetime accounting). Blobs use AES-256-GCM
// with random 96-bit nonces; the birthday bound for a non-negligible collision is
// ~2^48 messages, so this 2^32 line has an enormous margin and is unreachable in
// normal use (one seal per audit save) -- it only flags a pathological write loop
// within a single session. The real high-volume mitigation is DEK rotation
// (Rekey), which generates a fresh key and resets the nonce space entirely.
const nonceWarnThreshold = 1 << 32

// countSeal advances the nonce odometer and warns once if it crosses the bound.
func (v *Vault) countSeal() {
	if v.seals.Add(1) >= nonceWarnThreshold && v.noncesWarned.CompareAndSwap(false, true) {
		log.Printf("WARNING: %d encryptions under one data key -- approaching the GCM random-nonce budget; rotate the store (new data key) for very high write volumes", nonceWarnThreshold)
	}
}

// Open prepares the data directory (creating it if needed). It does not unlock.
// If a keyfile is present it is parse-checked so a corrupt/truncated keyfile is
// surfaced at startup rather than silently treated as "initialized".
func Open(dir string) (*Vault, error) {
	if err := os.MkdirAll(filepath.Join(dir, auditsSubdir), 0o700); err != nil {
		return nil, err
	}
	v := &Vault{dir: dir}
	if v.Initialized() {
		if _, err := v.readKeyfile(); err != nil {
			return nil, fmt.Errorf("keyfile present but unreadable (a backup may exist at %s.bak): %w", v.keyfilePath(), err)
		}
	}
	return v, nil
}

// readKeyfile reads, parses, and validates the keyfile.
func (v *Vault) readKeyfile() (keyfile, error) {
	b, err := os.ReadFile(v.keyfilePath())
	if err != nil {
		if os.IsNotExist(err) {
			return keyfile{}, ErrNotInitialized
		}
		return keyfile{}, err
	}
	var kf keyfile
	if err := json.Unmarshal(b, &kf); err != nil {
		return keyfile{}, fmt.Errorf("corrupt keyfile: %w", err)
	}
	if kf.Version != keyfileVersion || kf.KDF != "argon2id" {
		return keyfile{}, fmt.Errorf("unsupported keyfile (version %d, kdf %q)", kf.Version, kf.KDF)
	}
	if kf.Time < minArgonTime || kf.Memory < minArgonMemory || kf.Threads < 1 {
		return keyfile{}, errors.New("keyfile argon2 parameters below the accepted minimum")
	}
	return kf, nil
}

func (v *Vault) keyfilePath() string { return filepath.Join(v.dir, keyfileName) }
func (v *Vault) auditPath(id string) string {
	return filepath.Join(v.dir, auditsSubdir, id+".enc")
}

// Initialized reports whether a keyfile exists (i.e. a passphrase has been set).
func (v *Vault) Initialized() bool {
	_, err := os.Stat(v.keyfilePath())
	return err == nil
}

// Unlocked reports whether the DEK is currently held in memory.
func (v *Vault) Unlocked() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.dek != nil
}

func deriveKEK(passphrase string, salt []byte, t, m uint32, p uint8) []byte {
	return argon2.IDKey([]byte(passphrase), salt, t, m, p, dekLen)
}

// wrapAndWrite wraps dek under a fresh-salt KEK from passphrase and writes the
// keyfile atomically (no previous DEK).
func (v *Vault) wrapAndWrite(dek []byte, passphrase string) error {
	return v.wrapAndWriteBoth(dek, nil, passphrase)
}

// wrapAndWriteBoth writes the keyfile wrapping dek as primary and, if prevDEK is
// non-nil, also the previous DEK (used mid-rekey so unprocessed blobs stay
// readable). Backs up any existing keyfile first.
func (v *Vault) wrapAndWriteBoth(dek, prevDEK []byte, passphrase string) error {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	kek := deriveKEK(passphrase, salt, argonTime, argonMemory, argonThreads)
	wrapped, err := gcmSeal(kek, dek, nil)
	if err != nil {
		return err
	}
	kf := keyfile{
		Version: keyfileVersion, KDF: "argon2id", Salt: b64(salt),
		Time: argonTime, Memory: argonMemory, Threads: argonThreads,
		WrappedDEK: b64(wrapped),
	}
	if prevDEK != nil {
		wprev, err := gcmSeal(kek, prevDEK, nil)
		if err != nil {
			return err
		}
		kf.WrappedPrevDEK = b64(wprev)
	}
	b, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return err
	}
	if old, err := os.ReadFile(v.keyfilePath()); err == nil {
		_ = os.WriteFile(v.keyfilePath()+".bak", old, 0o600) // best-effort backup before overwrite
	}
	return writeFileAtomic(v.keyfilePath(), b)
}

// Initialize sets the store passphrase on first run: generates a random DEK,
// wraps it under the passphrase, writes the keyfile, and unlocks.
func (v *Vault) Initialize(passphrase string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, err := os.Stat(v.keyfilePath()); err == nil {
		return errors.New("vault already initialized")
	}
	dek := make([]byte, dekLen)
	if _, err := rand.Read(dek); err != nil {
		return err
	}
	if err := v.wrapAndWrite(dek, passphrase); err != nil {
		return err
	}
	v.dek = dek
	v.seals.Store(0)
	v.noncesWarned.Store(false)
	return nil
}

// Unlock derives the key from the passphrase and unwraps the DEK into memory.
func (v *Vault) Unlock(passphrase string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	kf, err := v.readKeyfile()
	if err != nil {
		return err
	}
	salt, err := unb64(kf.Salt)
	if err != nil {
		return err
	}
	wrapped, err := unb64(kf.WrappedDEK)
	if err != nil {
		return err
	}
	kek := deriveKEK(passphrase, salt, kf.Time, kf.Memory, kf.Threads)
	dek, err := gcmOpen(kek, wrapped, nil)
	if err != nil {
		return ErrBadPassphrase
	}
	// If a rekey was interrupted, the previous DEK MUST load -- otherwise the
	// prev-sealed blobs are unreadable. Fail LOUD rather than silently unlocking
	// with prevDEK=nil: a later rebuild would then quarantine those (recoverable!)
	// blobs as "corrupt", destroying them. The operator can restore a good keyfile,
	// or deliberately drop wrapped_prev_dek to accept the loss. Mirrors Rekey.
	var prev []byte
	if kf.WrappedPrevDEK != "" {
		wp, err := unb64(kf.WrappedPrevDEK)
		if err != nil {
			return fmt.Errorf("unlock: corrupt wrapped_prev_dek (interrupted rekey): %w", err)
		}
		if prev, err = gcmOpen(kek, wp, nil); err != nil {
			return fmt.Errorf("unlock: cannot unwrap previous DEK (interrupted rekey) -- restore a good keyfile or drop wrapped_prev_dek to accept the loss: %w", err)
		}
	}
	v.dek = dek
	v.prevDEK = prev
	v.seals.Store(0) // per-session odometer (lifetime tracking would need persistence)
	v.noncesWarned.Store(false)
	return nil
}

// ChangePassphrase re-wraps the existing DEK under a new passphrase (fresh salt +
// current argon2 cost). The encrypted audit blobs are untouched. A crash-safety
// .bak is written during the swap and removed on success (keeping it would let the
// old passphrase still decrypt). Requires the correct current passphrase.
func (v *Vault) ChangePassphrase(oldPass, newPass string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	kf, err := v.readKeyfile()
	if err != nil {
		return err
	}
	salt, err := unb64(kf.Salt)
	if err != nil {
		return err
	}
	wrapped, err := unb64(kf.WrappedDEK)
	if err != nil {
		return err
	}
	dek, err := gcmOpen(deriveKEK(oldPass, salt, kf.Time, kf.Memory, kf.Threads), wrapped, nil)
	if err != nil {
		return ErrBadPassphrase
	}
	if err := v.wrapAndWrite(dek, newPass); err != nil {
		return err
	}
	// Remove the crash-safety backup: it still wraps the DEK under the OLD
	// passphrase, so keeping it would defeat the rotation (the old passphrase
	// could still decrypt via the .bak in any data/ backup).
	_ = os.Remove(v.keyfilePath() + ".bak")
	v.dek = dek
	return nil
}

// Rekey rotates the data-encryption key: it generates a fresh DEK, re-encrypts
// every audit blob + the index under it, and re-wraps it under the (unchanged)
// passphrase. Crash-safe: the keyfile holds BOTH keys during the migration, so an
// interruption leaves every blob readable, and a re-run RESUMES (re-sealing the
// remainder under the in-progress key) rather than starting over. Requires the
// correct current passphrase; holds an exclusive lock for the whole operation.
func (v *Vault) Rekey(passphrase string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.dek == nil {
		return ErrLocked
	}
	kf, err := v.readKeyfile()
	if err != nil {
		return err
	}
	salt, err := unb64(kf.Salt)
	if err != nil {
		return err
	}
	kek := deriveKEK(passphrase, salt, kf.Time, kf.Memory, kf.Threads)
	wrapped, err := unb64(kf.WrappedDEK)
	if err != nil {
		return err
	}
	primary, err := gcmOpen(kek, wrapped, nil)
	if err != nil {
		return ErrBadPassphrase
	}
	// Mark in-progress only AFTER the passphrase verifies, so a wrong-passphrase
	// attempt doesn't flip the flag (which would 503 all readers + report
	// "rekeying" on /healthz for nothing). store.writeMu already serializes rekeys;
	// this CAS just rejects a redundant concurrent one.
	if !v.rekeying.CompareAndSwap(false, true) {
		return ErrRekeyInProgress
	}
	v.rekeyStartedN.Store(time.Now().UnixNano())
	defer func() { v.rekeying.Store(false); v.rekeyStartedN.Store(0) }()

	// Pick the target DEK + the keys blobs may currently be sealed under.
	var target, prev []byte
	if kf.WrappedPrevDEK != "" {
		// Resume an interrupted rekey: re-seal under the existing primary. Blobs are
		// under primary (already done) or the recorded prev (still pending).
		target = primary
		wp, err := unb64(kf.WrappedPrevDEK)
		if err != nil {
			return fmt.Errorf("rekey: corrupt wrapped_prev_dek: %w", err)
		}
		if prev, err = gcmOpen(kek, wp, nil); err != nil {
			return fmt.Errorf("rekey: cannot unwrap previous DEK (interrupted rekey): %w", err)
		}
	} else {
		// Fresh rekey: a new random DEK; persist [new, old] BEFORE touching blobs so
		// a crash mid-migration still has both keys.
		target = make([]byte, dekLen)
		if _, err := rand.Read(target); err != nil {
			return err
		}
		if err := v.wrapAndWriteBoth(target, primary, passphrase); err != nil {
			return err
		}
		prev = primary
	}
	v.dek, v.prevDEK = target, prev
	keys := [][]byte{target, prev}

	ids, err := v.ListAudits()
	if err != nil {
		return err
	}
	for _, id := range ids {
		ct, err := os.ReadFile(v.auditPath(id))
		if err != nil {
			return err
		}
		pt, err := openMany(keys, ct, blobAAD(id))
		if err != nil {
			return fmt.Errorf("rekey: cannot decrypt audit %s: %w", id, err)
		}
		nct, err := gcmSeal(target, pt, blobAAD(id))
		if err != nil {
			return err
		}
		if err := writeFileAtomic(v.auditPath(id), nct); err != nil {
			return err
		}
	}
	if ict, err := os.ReadFile(v.indexPath()); err == nil {
		pt, err := openMany(keys, ict, indexAAD)
		if err != nil {
			return fmt.Errorf("rekey: cannot decrypt index: %w", err)
		}
		nct, err := gcmSeal(target, pt, indexAAD)
		if err != nil {
			return err
		}
		if err := writeFileAtomic(v.indexPath(), nct); err != nil {
			return err
		}
	}

	// Finalize: keyfile with only the new DEK; drop the old.
	if err := v.wrapAndWrite(target, passphrase); err != nil {
		return err
	}
	_ = os.Remove(v.keyfilePath() + ".bak")
	v.prevDEK = nil
	v.seals.Store(0)
	v.noncesWarned.Store(false)
	return nil
}

// Lock zeroes and drops the DEK(s).
func (v *Vault) Lock() {
	v.mu.Lock()
	defer v.mu.Unlock()
	for i := range v.dek {
		v.dek[i] = 0
	}
	for i := range v.prevDEK {
		v.prevDEK[i] = 0
	}
	v.dek = nil
	v.prevDEK = nil
}

// openMany decrypts ct by trying each key in order (AAD first, then a no-AAD
// legacy fallback). Used so reads succeed under the primary DEK or, during/after
// an interrupted rekey, the previous DEK.
func openMany(keys [][]byte, ct, aad []byte) ([]byte, error) {
	for _, k := range keys {
		if k == nil {
			continue
		}
		if pt, _, err := gcmOpenWithLegacy(k, ct, aad); err == nil {
			return pt, nil
		}
	}
	return nil, errors.New("vault: no key could decrypt the blob")
}

// SaveAudit encrypts plaintext under the DEK and writes it atomically.
func (v *Vault) SaveAudit(id string, plaintext []byte) error {
	v.mu.RLock()
	dek := v.dek
	v.mu.RUnlock()
	if dek == nil {
		return ErrLocked
	}
	ct, err := gcmSeal(dek, plaintext, blobAAD(id))
	if err != nil {
		return err
	}
	v.countSeal()
	return writeFileAtomic(v.auditPath(id), ct)
}

func (v *Vault) indexPath() string { return filepath.Join(v.dir, "index.enc") }

// SaveIndex encrypts + writes the audit metadata index.
func (v *Vault) SaveIndex(plaintext []byte) error {
	v.mu.RLock()
	dek := v.dek
	v.mu.RUnlock()
	if dek == nil {
		return ErrLocked
	}
	ct, err := gcmSeal(dek, plaintext, indexAAD)
	if err != nil {
		return err
	}
	v.countSeal()
	return writeFileAtomic(v.indexPath(), ct)
}

// LoadIndex decrypts the metadata index, or returns ErrNoIndex if absent.
func (v *Vault) LoadIndex() ([]byte, error) {
	v.mu.RLock()
	dek, prev := v.dek, v.prevDEK
	v.mu.RUnlock()
	if dek == nil {
		return nil, ErrLocked
	}
	ct, err := os.ReadFile(v.indexPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoIndex
		}
		return nil, err
	}
	return openMany([][]byte{dek, prev}, ct, indexAAD)
}

// LoadOne decrypts a single audit blob.
func (v *Vault) LoadOne(id string) ([]byte, error) {
	v.mu.RLock()
	dek, prev := v.dek, v.prevDEK
	v.mu.RUnlock()
	if dek == nil {
		return nil, ErrLocked
	}
	ct, err := os.ReadFile(v.auditPath(id))
	if err != nil {
		return nil, err
	}
	return openMany([][]byte{dek, prev}, ct, blobAAD(id))
}

// ListAudits returns the ids of all stored audit blobs (no decryption).
func (v *Vault) ListAudits() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(v.dir, auditsSubdir))
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".enc") {
			ids = append(ids, strings.TrimSuffix(e.Name(), ".enc"))
		}
	}
	return ids, nil
}

// DeleteAudit removes an audit's encrypted file (no error if already gone).
func (v *Vault) DeleteAudit(id string) error {
	err := os.Remove(v.auditPath(id))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// LoadAll decrypts every stored audit, returning id -> plaintext.
func (v *Vault) LoadAll() (map[string][]byte, error) {
	v.mu.RLock()
	dek, prev := v.dek, v.prevDEK
	v.mu.RUnlock()
	if dek == nil {
		return nil, ErrLocked
	}
	entries, err := os.ReadDir(filepath.Join(v.dir, auditsSubdir))
	if err != nil {
		return nil, err
	}
	out := make(map[string][]byte)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".enc") {
			continue
		}
		ct, err := os.ReadFile(filepath.Join(v.dir, auditsSubdir, e.Name()))
		if err != nil {
			return nil, err
		}
		id := strings.TrimSuffix(e.Name(), ".enc")
		pt, err := openMany([][]byte{dek, prev}, ct, blobAAD(id))
		if err != nil {
			// One undecryptable blob must not brick the whole store. QUARANTINE it
			// (rename out of the .enc namespace) rather than just skip: otherwise it
			// stays in ListAudits, so reconcile keeps seeing more blobs than index
			// entries and re-rebuilds on EVERY unlock forever. Quarantining converges
			// that loop and leaves the loss visible on disk (+ a loud log line).
			full := filepath.Join(v.dir, auditsSubdir, e.Name())
			if rerr := os.Rename(full, full+".corrupt"); rerr != nil {
				log.Printf("WARNING: audit blob %s is undecryptable (%v) and could not be quarantined: %v", e.Name(), err, rerr)
			} else {
				log.Printf("WARNING: audit blob %s is undecryptable (%v) -- QUARANTINED to %s.corrupt; that audit is lost", e.Name(), err, e.Name())
			}
			continue
		}
		out[id] = pt
	}
	return out, nil
}

// --- crypto + file helpers ---

func gcmSeal(key, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil // nonce || ciphertext
}

func gcmOpen(key, blob, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := blob[:gcm.NonceSize()], blob[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, aad)
}

// gcmOpenWithLegacy opens a blob authenticated with aad, falling back to no-AAD
// for data written before AAD binding (upgrade-on-write re-seals it). The bool
// reports whether the legacy (no-AAD) path was used.
func gcmOpenWithLegacy(key, blob, aad []byte) ([]byte, bool, error) {
	if pt, err := gcmOpen(key, blob, aad); err == nil {
		return pt, false, nil
	}
	pt, err := gcmOpen(key, blob, nil)
	if err != nil {
		return nil, false, err
	}
	return pt, true, nil
}

// AAD labels bind a ciphertext to its role/identity so files can't be swapped.
func blobAAD(id string) []byte { return []byte("patd-audit:" + id) }

var indexAAD = []byte("patd-index")

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// writeFileAtomic writes b durably: a temp file is written + fsync'd, then renamed
// over path, then the directory is fsync'd (best-effort). A crash leaves either the
// old file or the new file, never a truncated one.
func writeFileAtomic(path string, b []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".keyfile-*.tmp") // 0600 by default
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // no-op once renamed
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil { // dir fsync; not supported everywhere
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func b64(b []byte) string            { return base64.StdEncoding.EncodeToString(b) }
func unb64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
