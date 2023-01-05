package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"time"
)

// When unmarshaling JSON to a struct via json.Unmarshal, object keys which
// don't have a corresponding struct field are ignored. So we define a struct
// that will contain only the parts of the JSON that we are interested in.
// Field names must be exported so that encoding/json can access them.
type payload struct {
	After   string
	Commits []commit
}

type commit struct {
	Added    []string
	Removed  []string
	Modified []string
}

const builderLogPath = "./builder.log"

func main() {
	key := "WEBHOOK_SECRET"
	secret, ok := os.LookupEnv(key)
	if !ok {
		log.Fatal(key + " not set.")
	}
	builderChan := make(chan string)
	go builder(builderChan)
	randSrc := rand.New(rand.NewSource(time.Now().UnixNano()))

	path := "/multi-life-dev"
	dependencies := []string{".vimrc", "Dockerfile", "plugins.vim"}
	http.HandleFunc("/handle-push-event"+path, func(w http.ResponseWriter, r *http.Request) {
		handlePushEvent(r, path, secret, dependencies, builderChan, randSrc)
	})
	path2 := "/multi-life"
	dependencies2 := []string{"go.mod", "go.sum"}
	http.HandleFunc("/handle-push-event"+path2, func(w http.ResponseWriter, r *http.Request) {
		handlePushEvent(r, path2, secret, dependencies2, builderChan, randSrc)
	})
	log.Fatal(http.ListenAndServe(":8000", nil))
}

func handlePushEvent(r *http.Request, path string, secret string, dep []string,
	builderChan chan string, randSrc *rand.Rand) {
	macStr := r.Header.Get("X-Hub-Signature-256")
	if macStr == "" {
		log.Printf("Request at %v is missing a MAC.\n", path)
		return
	}
	// macStr should contain a hex string prepended with "sha256=".
	// Remove the "sha256=" and decode the hex string to bytes.
	mac, err := hex.DecodeString(macStr[7:])
	if err != nil {
		log.Printf("Request at %v contains a malformed MAC.\n%v\n", path, err)
		return
	}
	hashFn := hmac.New(sha256.New, []byte(secret))
	body, err := readBody(r)
	if err != nil {
		log.Println(err)
		return
	}
	_, err = hashFn.Write(body)
	if err != nil {
		log.Println(err)
		return
	}
	expectedMac := hashFn.Sum(nil)
	if !hmac.Equal(mac, expectedMac) {
		log.Printf("Request at %v contains an unexpected MAC.\n"+
			"Expected %x\nGot %x\n", path, expectedMac, mac)
	}
	p := &payload{}
	err = json.Unmarshal(body, p)
	if err != nil {
		log.Println(err)
	}
	// Remove the leading slash to get the repository name.
	repo := path[1:]
	for _, com := range p.Commits {
		for _, file := range com.Added {
			if buildIfDependent(dep, file, repo, p.After, builderChan, randSrc) {
				return
			}
		}
		for _, file := range com.Removed {
			if buildIfDependent(dep, file, repo, p.After, builderChan, randSrc) {
				return
			}
		}
		for _, file := range com.Modified {
			if buildIfDependent(dep, file, repo, p.After, builderChan, randSrc) {
				return
			}
		}
	}
}

func readBody(r *http.Request) ([]byte, error) {
	body := make([]byte, r.ContentLength)
	for i := 0; ; {
		n, err := r.Body.Read(body[i:])
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		i += n
	}
	return body, nil
}

// buildIfDependent starts a build if the given file is a build dependency.
// It returns a bool indicating whether a build was started.
func buildIfDependent(dep []string, file string, repo string, commitID string,
	builderChan chan string, r *rand.Rand) bool {
	for _, d := range dep {
		if file == d {
			buildID := generateBuildID(r)
			log.Printf("Build triggered...\n"+
				"File changed: %v\n"+
				"Repository: %v\n"+
				"HEAD at time of build: %v\n"+
				"Build ID: %v\n"+
				"See %v for output.\n",
				file, repo, commitID, buildID, builderLogPath)
			builderChan <- buildID
			return true
		}
	}
	return false
}

func generateBuildID(r *rand.Rand) string {
	b := make([]byte, 4)
	r.Read(b)
	return hex.EncodeToString(b)
}

// builder builds and pushes the multi-life-dev image in response to build ID
// (string) messages sent on a channel. builder will always build from the
// latest multi-life-dev code, regardless of the commit that triggered the
// build.
//
// If a build ID comes in while a build is in progress, the build is canceled
// and a new one is started.
//
// builder logs to a separate file specified by the builderLogPath variable.
// This is done so that when builder runs on a separate goroutine its output is
// easily distinguishable from the output of the main goroutine. This would be
// difficult to achieve with log tags because much of builder's output comes
// from external commands, which do not use Go's logging mechanism.
func builder(builderChan chan string) {
	// Open the log file, creating it if it doesn't exist.
	logFile, err := os.OpenFile(builderLogPath,
		os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
	if err != nil {
		panic(err)
	}
	defer logFile.Close()
	// Create a logger pointing to the log file.
	logger := log.New(logFile, "", log.LstdFlags)
	// variable buildID stores the build ID message that interrupted the
	// previous build, if any.
	var buildID string
	for {
		if buildID == "" {
			// The previous build completed (was not interrupted).
			// Wait for a build ID.
			buildID = <-builderChan
		}
		logger.Printf("Starting build. Build ID: %v\n", buildID)

		cmd := exec.Command("docker", "build", "--no-cache", "-t",
			"alexnicoll/multi-life-dev",
			"https://github.com/alex-nicoll/multi-life-dev.git#main")
		if !run(cmd, builderChan, logFile, logger, &buildID) {
			continue
		}
		cmd = exec.Command("docker", "push", "alexnicoll/multi-life-dev")
		if !run(cmd, builderChan, logFile, logger, &buildID) {
			continue
		}
		buildID = ""
	}
}

func run(cmd *exec.Cmd, builderChan chan string, logFile *os.File,
	logger *log.Logger, buildID *string) bool {
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	logger.Printf("Running command %v\n", cmd)
	if err := cmd.Start(); err != nil {
		logger.Printf("An error occurred while starting the command: %v\n",
			err)
		*buildID = ""
		return false
	}
	// Wait for either the command to exit or for a message to arrive.
	waitChan := make(chan error)
	go func() {
		waitChan <- cmd.Wait()
	}()
	select {
	case err := <-waitChan:
		if err != nil {
			logger.Printf("An error occurred while running the command: %v\n",
				err)
			*buildID = ""
			return false
		}
		return true
	case *buildID = <-builderChan:
		// Another build has been requested.
		logger.Println("Canceling build...")
		// Assume that it is safe to call cmd.Process.Signal()
		// while cmd.Wait() is running in a separate goroutine.
		if err := cmd.Process.Signal(os.Interrupt); err != nil {
			logger.Printf("An error occurred while attempting to interrupt "+
				"the command: %v\n", err)
		}
		if err := <-waitChan; err != nil {
			logger.Printf("An error occurred while running the command: %v\n",
				err)
		}
		return false
	}
}
