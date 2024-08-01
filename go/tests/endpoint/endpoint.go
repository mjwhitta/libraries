package Endpoint

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/gob"
	"fmt"
	"io"
	"io/fs"
	"math/rand"
	"net"
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
	NotRelevant            int = 104
	NotRelevantOS          int = 108
	InsufficientPrivileges int = 109

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

// DropperPayload is used to transmit encoded data via IPC.
type DropperPayload struct {
	Filename string
	Contents []byte
}

var (
	bin, binErr        = os.Executable()
	cleanup     func() = func() {}
	cwd, cwdErr        = os.Getwd()
	results            = map[int]string{
		CleanupFailed:               "cleanup failed",
		ExecutionPrevented:          "execution prevented",
		FileQuarantinedOnExecution:  "file quarantined on execution",
		FileQuarantinedOnExtraction: "file quarantined on extraction",
		HostNotVulnerabile:          "host not vulnerable",
		InsufficientPrivileges:      "insufficient privileges",
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
	socketPath string
	stopMutex  *sync.Mutex = &sync.Mutex{}
)

func init() {
	if binErr != nil {
		Say("Failed to get executable: %s", binErr.Error())
		Stop(UnexpectedExecutionError)
	}

	if cwdErr != nil {
		Say("Failed to get path: %s", cwdErr.Error())
		Stop(UnexpectedExecutionError)
	}

	bindir := filepath.Dir(bin)
	if bindir != cwd {
		Say(
			"Current directory is \"%s\", changing to executable"+
				"directory \"%s\" for test execution",
			cwd,
			bindir,
		)
		if e := os.Chdir(bindir); e != nil {
			Say("Failed to change directory to \"%s\"", cwd)
			Stop(UnexpectedExecutionError)
		}
		cwd = bindir
		Say("Directory successfully changed to \"%s\"", cwd)
	}
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

// CheckAdmin will return whether or not the test is running as admin.
func CheckAdmin() bool {
	switch platform := runtime.GOOS; platform {
	case "windows":
		_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
		if err != nil {
			return false
		}
		return true
	case "linux", "darwin":
		return os.Getuid() == 0
	default:
		Say("Platform not supported")
		return false
	}
}

func clearSocketPath() {
	Say("Clearing socket path")
	socketPath = ""
}

// Dropper will write the specified dropper bytes to disk and then set
// the IPC socket path for future use.
func Dropper(dropper []byte) bool {
	var ext string
	Say("Writing dropper executable to disk")
	if GetOS() == "windows" {
		ext = ".exe"
	}
	ok := Write(
		fmt.Sprintf(
			"%s_prelude_dropper%s",
			GetTestIdFromExecutableName(),
			ext,
		),
		dropper,
	)
	setSocketPath()
	if ok {
		Say("Wrote dropper successfully")
	}
	return ok
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
		Say("Path %s not accessible: %s", path, err)
		return false
	}
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
		home, err := os.UserHomeDir()
		if err != nil {
			Say("Unable to determine home directory: %s", err)
			return a
		}
		paths = []string{home}
	}
	Say("Searching for %s files", ext)
	for _, path := range paths {
		_ = filepath.WalkDir(
			path,
			func(s string, d fs.DirEntry, e error) error {
				if e == nil {
					if filepath.Ext(d.Name()) == ext {
						Say("Found: %s", s)
						a = append(a, s)
					}
				}
				return nil
			},
		)
	}
	Say("Found %d files", len(a))
	return a
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

// GetOS returns the runtime OS, or "unsupported", if not supported.
func GetOS() string {
	switch runtime.GOOS {
	case "darwin", "linux", "windows":
		return runtime.GOOS
	}
	return "unsupported"
}

// GetTestIdFromExecutableName will return the test ID by parsing the
// exe file name.
func GetTestIdFromExecutableName() string {
	if GetOS() == "windows" {
		return strings.Split(filepath.Base(os.Args[0]), ".")[0]
	}
	return filepath.Base(os.Args[0])
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
	if len(filename) == 0 {
		return cwd
	}
	return filepath.Join(
		append([]string{cwd}, filename...)...,
	)
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

// Read will read a file and return the contents. An empty slice means
// failed read. By default the filename is assumed to be in Pwd(). You
// can override this behavior by configuring Cfg in advance.
func Read(filename string) []byte {
	var cfg Config = defaultCfg(Config{directory: Pwd()})
	var path string = filepath.Join(cfg.directory, filename)
	Say("Reading %s", path)
	b, err := os.ReadFile(path)
	if err != nil {
		Say("Failed to read %s: %s", path, err)
		return nil
	}
	Say("Successfully read %d bytes from %s", len(b), path)
	return b
}

// Remove will attempt to remove a file and returns true upon success.
// See the log for any errors.
func Remove(path string) bool {
	if err := os.Remove(path); err != nil {
		Say("Failed to remove %s: %s", path, err)
		return false
	}
	Say("Successfully removed %s", path)
	return true
}

// RemoveAll will attempt to remove a directory and returns true upon
// success. See the log for any errors.
func RemoveAll(path string) bool {
	if err := os.RemoveAll(path); err != nil {
		Say("Failed to recursively remove %s: %s", path, err)
		return false
	}
	Say("Successfully removed %s", path)
	return true
}

// Run will attempt to run the provided command and args as a new
// process. It returns the new process handle and any error that
// occurs. The caller should decide whether to call Kill() or Wait()
// on the returned process handle.
func Run(args []string) (*os.Process, error) {
	var cfg Config = defaultCfg(Config{})
	Say("Running \"%s\" in the background", strings.Join(args, " "))
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

// Say will print a message prepended with a timestamp and the
// file/test name.
func Say(print string, ifc ...any) {
	filename := filepath.Base(os.Args[0])
	name := strings.TrimSuffix(filename, filepath.Ext(filename))
	timeStamp := time.Now().Format("2006-01-02T15:04:05")
	fmt.Printf(
		"[%s][%s] %v\n",
		timeStamp,
		name,
		fmt.Sprintf(print, ifc...),
	)
}

func setSocketPath() {
	Say("Setting socket path")
	execPath, _ := os.Executable()
	socketPath = filepath.Join(
		filepath.Dir(execPath),
		"prelude_socket",
	)
}

// Shell will attempt to run the provided command and args as a new
// process. It returns the STDOUT or an error containing the STDERR.
func Shell(args []string) (string, error) {
	var cfg Config = defaultCfg(Config{})
	Say("Running \"%s\"", strings.Join(args, " "))
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

// Start takes a test function and runs it in the background. By
// default it waits 30 seconds before timeout. The cleanup function is
// run when Stop() is called. The default cleanup does nothing. A
// custom clean function can be optionally provided. The timeout can
// be overridden by configuring Cfg in advance.
func Start(test func(), clean ...func()) {
	var cfg Config = defaultCfg(Config{timeout: 30 * time.Second})
	var done chan struct{} = make(chan struct{}, 1)

	defer close(done)

	if len(clean) > 0 {
		cleanup = clean[0]
	}

	Say("Starting test")

	go func() {
		test()
		done <- struct{}{}
	}()

	select {
	case <-done:
		Stop(TestCompletedNormally)
	case <-time.After(cfg.timeout):
		Say("Test execution exceeded time limit: %s", cfg.timeout)
		Stop(TimeoutExceeded)
	}
}

func startDropperChildProcess() (*os.Process, error) {
	execDir := filepath.Dir(socketPath)

	var ext string
	var listenerPath string

	if GetOS() == "windows" {
		ext = ".ext"
	}

	listenerPath = filepath.Join(
		execDir,
		fmt.Sprintf(
			"%s_prelude_dropper%s",
			GetTestIdFromExecutableName(),
			ext,
		),
	)
	Say("Launching " + listenerPath)

	cmd := exec.Command(listenerPath)

	if err := cmd.Start(); err != nil {
		err = fmt.Errorf(
			"failed to start dropper child process: \"%v\"",
			err,
		)
		return nil, err
	}

	return cmd.Process, nil
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

	Say("Completed with code: %d (%s)", code, result)
	Say("Exit called from %s:%d", filepath.Base(fn), line)
	Say("Ending test")

	os.Exit(code)
}

// Unzip will extract files from the provided zip data. If no path is
// provided, it will default to Pwd().
func Unzip(zipData []byte, path ...string) error {
	location := Pwd()
	if len(path) > 0 {
		location = path[0]
	}

	Say("Extracting zip contents to %s", location)

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
			Say("Creating %s%c", filePath, filepath.Separator)
			_ = os.MkdirAll(filePath, os.ModePerm)
			continue
		}

		if dir := filepath.Dir(filePath); !Exists(dir) {
			Say("Creating %s%c", dir, filepath.Separator)
			_ = os.MkdirAll(dir, os.ModePerm)
		}

		Say("Extracting %s", filePath)

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

// Wait will sleep for the specified duration. If duration is <= 0, it
// will default to 3 seconds.
func Wait(dur ...time.Duration) {
	if (len(dur) == 0) || (dur[0] <= 0) { // default
		dur = []time.Duration{3 * time.Second}
	}
	Say("Waiting for %s", dur[0].String())
	time.Sleep(dur[0])
}

// Write will write the provided contents to the provided file path
// and return any errors. By default the filename is assumed to be in
// Pwd(). You can override this behavior by configuring Cfg in
// advance.
func Write(filename string, contents []byte) bool {
	var cfg Config = defaultCfg(Config{directory: Pwd()})
	var err error
	var path string = filepath.Join(cfg.directory, filename)
	if socketPath != "" {
		Say("Performing IPC-style file write")
		if err = writeIPC(path, contents); err != nil {
			Say("Failed to write to socket: %s", err)
			return false
		}
	} else {
		Say("Writing to %s", path)
		parent := filepath.Dir(path)
		if err := os.MkdirAll(parent, 0o755); err != nil {
			Say("Failed to create parent folder %s: %s", parent, err)
			return false
		}
		if err := os.WriteFile(path, contents, 0o755); err != nil {
			Say("Failed to write %s: %s", path, err)
			return false
		}
		Say("Successfully wrote %d bytes to %s", len(contents), path)
	}
	return true
}

func writeIPC(filename string, contents []byte) error {
	dropProc, err := startDropperChildProcess()
	if err != nil {
		return fmt.Errorf(
			"got error \"%v\" when starting dropper child process",
			err,
		)
	}
	Say("Started dropper child process with PID %d", dropProc.Pid)

	Wait()

	Say("Connecting to socket: %s", socketPath)
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return fmt.Errorf(
			"got error \"%v\" when connecting to socket",
			err,
		)
	}
	Say("Connected to socket!")
	defer conn.Close()

	payload := DropperPayload{
		Filename: filename,
		Contents: contents,
	}

	if err = gob.NewEncoder(conn).Encode(payload); err != nil {
		return fmt.Errorf(
			"got error \"%v\" when writing to socket",
			err,
		)
	}

	Wait(1)
	Say("Killing dropper child process")
	_ = dropProc.Kill()
	clearSocketPath()

	return nil
}

// XorDecrypt will use xor to decrypt data with the provided key.
func XorDecrypt(data []byte, key []byte) []byte {
	decrypted := make([]byte, len(data))
	for i, v := range data {
		decrypted[i] = v ^ (key[i%len(key)] + byte(i))
	}
	return decrypted
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
