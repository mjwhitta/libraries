package Endpoint

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"io/fs"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Return codes as defined by:
// https://docs.preludesecurity.com/docs/understanding-results
const (
	// Errors
	UnexpectedTestError      int = 1
	MalformedTestError       int = 2
	TimeoutExceeded          int = 102
	CleanupFailed            int = 103
	OutOfMemory              int = 137
	UnexpectedExecutionError int = 256

	// Not Relevant
	NotRelevant   int = 104
	NotRelevantOS int = 108

	// Protected
	TestForceKilled             int = 9
	TestGracefullyKilled        int = 15
	TestCompletedNormally       int = 100
	FileQuarantinedOnExtraction int = 105
	NetworkConnectionBlocked    int = 106
	HostNotVulnerabile          int = 107
	ExecutionPrevented          int = 126
	FileQuarantinedOnExecution  int = 127

	// Unprotected
	Unprotected            int = 101
	TestIncorrectlyBlocked int = 110
)

var cleanup func() = func() {}

var results = map[int]string{
	CleanupFailed:               "cleanup failed",
	ExecutionPrevented:          "execution prevented",
	FileQuarantinedOnExecution:  "file quarantined on execution",
	FileQuarantinedOnExtraction: "file quarantined on extraction",
	HostNotVulnerabile:          "host not vulnerable",
	MalformedTestError:          "malformed test error",
	NetworkConnectionBlocked:    "network connection blocked",
	NotRelevant:                 "not relevant",
	NotRelevantOS:               "not relevant OS",
	OutOfMemory:                 "out of memory",
	TestCompletedNormally:       "test completed normally",
	TestForceKilled:             "test force killed",
	TestGracefullyKilled:        "test gracefully killed",
	TestIncorrectlyBlocked:      "test incorrectly blocked",
	TimeoutExceeded:             "timeout exceeded",
	UnexpectedExecutionError:    "unexpected execution error",
	UnexpectedTestError:         "unexpected test error",
	Unprotected:                 "unprotected",
}

var stopMutex *sync.Mutex = &sync.Mutex{}

// Start takes a test function and runs it in the background. By
// default it waits 30 seconds before timeout. The cleanup function is
// run when Stop() is called. The default cleanup does nothing. A
// custom clean function can be optionally provided. The timeout can
// be overridden by configuring Cfg in advance.
func Start(test func(), clean ...func()) {
	var cfg Config = defaultCfg(Config{timeout: 30 * time.Second})

	if len(clean) > 0 {
		cleanup = clean[0]
	}

	Say("Starting test")

	go func() {
		test()
	}()

	time.Sleep(cfg.timeout)
	Sayf("Test execution exceeded time limit: %s", cfg.timeout)
	Stop(TimeoutExceeded)
}

// Stop will call the associated cleanup function (provided when
// Start() was called) and then exit with the provided code.
func Stop(code int) {
	// Only allow one stop
	stopMutex.Lock()
	defer stopMutex.Unlock()

	cleanup()

	// Get the caller's line number (might have to go up levels if
	// Stop() is used by the module itself)
	caller := 1
	_, fn, line, _ := runtime.Caller(caller)
	for filepath.Base(fn) == "endpoint.go" {
		caller++
		_, fn, line, _ = runtime.Caller(caller)
	}

	// Get user-friendly message for the provided code
	result, ok := results[code]
	if !ok {
		result = "undefined"
	}

	Sayf("Completed with code: %d (%s)", code, result)
	Sayf("Exit called from line: %d", line)
	Say("Ending test")

	os.Exit(code)
}

// Wait will sleep for the specified duration. If duration is <= 0, it
// will default to 3 seconds.
func Wait(dur ...time.Duration) {
	if (len(dur) == 0) || (dur[0] <= 0) { // default
		dur = []time.Duration{3 * time.Second}
	}
	Sayf("Waiting for %s", dur[0].String())
	time.Sleep(dur[0])
}

// Say will print a message prepended with a timestamp and the
// file/test name.
func Say(print string) {
	filename := filepath.Base(os.Args[0])
	name := strings.TrimSuffix(filename, filepath.Ext(filename))
	timeStamp := time.Now().Format("2006-01-02T15:04:05")
	fmt.Printf("[%s][%s] %v\n", timeStamp, name, print)
}

// Sayf will print a formatted message prepended with a timestamp and
// the file/test name.
func Sayf(print string, args ...any) {
	Say(fmt.Sprintf(print, args...))
}

// Find is deprecated. use FindByType().
func Find(ext string) []string {
	return FindByType(ext)
}

// FindByType will walk the provided paths looking for files that have
// the provided file extension. If no paths are provided, it defaults
// to the user's home directory.
func FindByType(ext string, paths ...string) []string {
	var a []string
	if len(paths) == 0 {
		if home, e := os.UserHomeDir(); e != nil {
			Sayf("Unable to determine home directory: %s", e)
		} else {
			paths = []string{home}
		}
	}
	Sayf("Searching for %s files...", ext)
	for _, path := range paths {
		filepath.WalkDir(
			path,
			func(s string, d fs.DirEntry, e error) error {
				if e == nil {
					if filepath.Ext(d.Name()) == ext {
						Sayf("Found: %s", s)
						a = append(a, s)
					}
				}
				return nil
			},
		)
	}
	Sayf("Found %d files", len(a))
	return a
}

// Read will read a file and return the contents. An empty slice means
// failed read. By default the filename is assumed to be in Pwd(). You
// can override this behavior by configuring Cfg in advance.
func Read(filename string) []byte {
	var cfg Config = defaultCfg(Config{directory: Pwd()})
	var path string = filepath.Join(cfg.directory, filename)
	Sayf("Reading %s...", path)
	b, err := os.ReadFile(path)
	if err != nil {
		Sayf("Failed to read %s: %s", path, err)
		return nil
	}
	Sayf("Successfully read %d bytes from %s", len(b), path)
	return b
}

// Write will write the provided contents to the provided file path
// and return any errors. By default the filename is assumed to be in
// Pwd(). You can override this behavior by configuring Cfg in
// advance.
func Write(filename string, contents []byte) bool {
	var cfg Config = defaultCfg(Config{directory: Pwd()})
	var path string = filepath.Join(cfg.directory, filename)
	Sayf("Writing to %s...", path)
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		Sayf("Failed to create parent folder %s: %s", parent, err)
		return false
	}
	if err := os.WriteFile(path, contents, 0o644); err != nil {
		Sayf("Failed to write %s: %s", path, err)
		return false
	}
	Sayf("Successfully wrote %d bytes to %s", len(contents), path)
	return true
}

// Exists checks if a file exists AND can be accessed. If this
// function returns false, the file might still exist, but the current
// user does not have the required privileges to access it. Check the
// log for more details.
func Exists(path string) bool {
	if _, err := os.Stat(path); err == nil {
		return true
	} else if os.IsNotExist(err) {
		return false
	} else {
		err = err.(*fs.PathError).Err
		Sayf("Path %s not accessible: %s", path, err)
		return false
	}
}

// IsAccessible will return whether or not the provided path can be
// opened.
func IsAccessible(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// GetOS returns the runtime OS, or "unsupported", if not supported.
func GetOS() string {
	switch runtime.GOOS {
	case "darwin", "linux", "windows":
		return runtime.GOOS
	default:
		return "unsupported"
	}
}

// Quarantined will write the provided bytes to the proviled filename
// in the same directory as the test executable. It then waits and
// checks to see if the file exists. If the file is not found or is
// inaccessible, it is assumed to have been quarantined. The default
// directory is Pwd(), but can be overridden by configuring Cfg in
// advance. The default wait time is 3 seconds, but can be overridden
// by configuring Cfg in advance.
func Quarantined(filename string, contents []byte) bool {
	var cfg Config = defaultCfg(
		Config{directory: Pwd(), timeout: 3 * time.Second},
	)
	var path string = filepath.Join(cfg.directory, filename)
	// Use the local config for nested Write()
	Cfg = &cfg
	// Do not use full path here b/c Write() will handle that
	Write(filename, contents)
	Wait(cfg.timeout)
	Say("Checking for quarantine")
	if Exists(path) && IsAccessible(path) {
		Say("Not quarantined")
		return false
	}
	Say("Successfully quarantined")
	return true
}

// Remove will attempt to remove a file and returns true upon success.
// See the log for any errors.
func Remove(path string) bool {
	if err := os.Remove(path); err != nil {
		Sayf("Failed to remove %s: %s", path, err)
		return false
	}
	Sayf("Successfully removed %s", path)
	return true
}

// RemoveAll will attempt to remove a directory and returns true upon
// success. See the log for any errors.
func RemoveAll(path string) bool {
	if err := os.RemoveAll(path); err != nil {
		Sayf("Failed to recursively remove %s: %s", path, err)
		return false
	}
	Sayf("Successfully removed %s", path)
	return true
}

// Run will attempt to run the provided command and args as a new
// process. It returns the new process handle and any error that
// occurs. The caller should decide whether to call Kill() or Wait()
// on the returned process handle.
func Run(args []string) (*os.Process, error) {
	var cfg Config = defaultCfg(Config{})
	Sayf("Running \"%s\" in the background", strings.Join(args, " "))
	cmd := exec.Command(args[0], args[1:]...)
	if attrs := procAttrs(args); cfg.noEscape && (attrs != nil) {
		cmd.SysProcAttr = attrs
	}
	if err := cmd.Start(); err != nil {
		err = fmt.Errorf("failed to run cmd: %w", err)
		return nil, err
	}
	return cmd.Process, nil
}

// Shell will attempt to run the provided command and args as a new
// process. It returns the STDOUT or an error containing the STDERR.
func Shell(args []string) (string, error) {
	var cfg Config = defaultCfg(Config{})
	Sayf("Running \"%s\"", strings.Join(args, " "))
	cmd := exec.Command(args[0], args[1:]...)
	if attrs := procAttrs(args); cfg.noEscape && (attrs != nil) {
		cmd.SysProcAttr = attrs
	}
	stdout, err := cmd.Output()
	if err != nil {
		switch err := err.(type) {
		case *exec.ExitError:
			return "", fmt.Errorf("%s", string(err.Stderr))
		default:
			err = fmt.Errorf("failed to read cmd output: %w", err)
			return "", err
		}
	}
	return string(stdout), nil
}

// ExecuteRandomCommand will choose a random command from the provided
// list and execute it with Shell().
func ExecuteRandomCommand(commands [][]string) (string, error) {
	var command []string
	if len(commands) == 0 {
		return "", fmt.Errorf("command slice is empty")
	} else if len(commands) == 1 {
		command = commands[0]
	} else {
		index := rand.Intn(len(commands))
		command = commands[index]
	}
	return Shell(command)
}

// IsAvailable will look for a list of tools and check to see if any
// on in the system's PATH. It returns true upon the first tool found,
// false if none are found.
func IsAvailable(programs ...string) bool {
	for _, program := range programs {
		if _, err := exec.LookPath(program); err == nil {
			return true
		}
	}
	return false
}

// Pwd will return the directory where the test is located on disk. It
// is important to note that this may not be the directory from which
// the test is running.
func Pwd(filename ...string) string {
	bin, err := os.Executable()
	if err != nil {
		Say("Failed to get path")
		Stop(UnexpectedExecutionError)
	}
	if len(filename) == 0 {
		return filepath.Dir(bin)
	}
	return filepath.Join(
		append([]string{filepath.Dir(bin)}, filename...)...,
	)
}

// XorEncrypt will use xor to encrypt data with a randomly
// generated key. It returns the encrypted data with the key.
func XorEncrypt(data []byte) ([]byte, []byte, error) {
	key, err := generateKey(32)
	if err != nil {
		return nil, nil, err
	}

	encrypted := make([]byte, len(data))
	for i, v := range data {
		encrypted[i] = v ^ (key[i%len(key)] + byte(i))
	}
	return encrypted, key, nil
}

// XorDecrypt will use xor to decrypt data with the provided key.
func XorDecrypt(data []byte, key []byte) []byte {
	decrypted := make([]byte, len(data))
	for i, v := range data {
		decrypted[i] = v ^ (key[i%len(key)] + byte(i))
	}
	return decrypted
}

// AES256GCMEncrypt will use AES256GCM to encrypt data with a randomly
// generated key. It returns the encrypted data with the key.
func AES256GCMEncrypt(data []byte) ([]byte, []byte, error) {
	key, err := generateKey(32)
	if err != nil {
		return nil, nil, err
	}

	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	for i := range nonce {
		nonce[i] = byte(rand.Intn(256))
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, key, nil
}

// AES256GCMDecrypt will use AES256GCM to decrypt data with the
// provided key.
func AES256GCMDecrypt(data, key []byte) ([]byte, error) {
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// generateKey is used by the module's encryption functions to create
// a random key of the provided size.
func generateKey(size int) ([]byte, error) {
	key := make([]byte, size)
	for i := range key {
		key[i] = byte(rand.Intn(256))
	}
	return key, nil
}

// Unzip will extract files from the provided zip data. If no path is
// provided, it will default to Pwd().
func Unzip(zipData []byte, path ...string) error {
	location := Pwd()
	if len(path) > 0 {
		location = path[0]
	}

	Sayf("Extracting zip contents to %s", location)

	zipReader, err := zip.NewReader(
		bytes.NewReader(zipData),
		int64(len(zipData)),
	)
	if err != nil {
		return err
	}

	for _, file := range zipReader.File {
		filePath := filepath.Join(location, file.Name)

		if file.FileInfo().IsDir() {
			Sayf("Creating %s%c", filePath, filepath.Separator)
			os.MkdirAll(filePath, os.ModePerm)
			continue
		}

		if dir := filepath.Dir(filePath); !Exists(dir) {
			Sayf("Creating %s%c", dir, filepath.Separator)
			os.MkdirAll(dir, os.ModePerm)
		}

		Sayf("Extracting %s", filePath)

		fileData, err := file.Open()
		if err != nil {
			return err
		}
		defer fileData.Close()

		outFile, err := os.Create(filePath)
		if err != nil {
			return err
		}
		defer outFile.Close()

		_, err = io.Copy(outFile, fileData)
		if err != nil {
			return err
		}
	}

	Say("Finished extracting")

	return nil
}
