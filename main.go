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
	"net/smtp"
	"os"
	"os/exec"
	"time"
)

const (
	serverLogFileName  = "server.log"
	builderLogFileName = "builder.log"
)

func main() {
	logFile := openLogFile(serverLogFileName)
	defer logFile.Close()
	log.SetOutput(logFile)
	secret := lookupEnvOrExit("WEBHOOK_SECRET")
	m := newMailer()
	builderChan := make(chan string)
	go builder(builderChan, m)
	randSrc := rand.New(rand.NewSource(time.Now().UnixNano()))

	http.HandleFunc("/handle-push-event/multi-life-dev", func(w http.ResponseWriter, r *http.Request) {
		requestID := generateRequestID(randSrc)
		log.Printf("Handling request. Request ID: %v\n", requestID)

		macStr := r.Header.Get("X-Hub-Signature-256")
		if macStr == "" {
			log.Println("Request is missing a MAC.")
			sendEmail(m, newRqstProcFailureMsg(requestID))
			return
		}
		// macStr should contain a hex string prepended with "sha256=".
		// Remove the "sha256=" and decode the hex string to bytes.
		mac, err := hex.DecodeString(macStr[7:])
		if err != nil {
			log.Printf("Request contains a malformed MAC.\n%v\n", err)
			sendEmail(m, newRqstProcFailureMsg(requestID))
			return
		}
		hashFn := hmac.New(sha256.New, []byte(secret))
		body, err := readBody(r)
		if err != nil {
			log.Println(err)
			sendEmail(m, newRqstProcFailureMsg(requestID))
			return
		}
		_, err = hashFn.Write(body)
		if err != nil {
			log.Println(err)
			sendEmail(m, newRqstProcFailureMsg(requestID))
			return
		}
		expectedMac := hashFn.Sum(nil)
		if !hmac.Equal(mac, expectedMac) {
			log.Printf("Request contains an unexpected MAC.\n"+
				"Expected %x\nGot %x\n", expectedMac, mac)
			sendEmail(m, newRqstProcFailureMsg(requestID))
			return
		}
		p := &payload{}
		err = json.Unmarshal(body, p)
		if err != nil {
			log.Println(err)
			sendEmail(m, newRqstProcFailureMsg(requestID))
			return
		}
		for _, com := range p.Commits {
			for _, file := range com.Added {
				if buildIfDependent(file, p.After, builderChan) {
					return
				}
			}
			for _, file := range com.Removed {
				if buildIfDependent(file, p.After, builderChan) {
					return
				}
			}
			for _, file := range com.Modified {
				if buildIfDependent(file, p.After, builderChan) {
					return
				}
			}
		}
	})
	log.Fatal(http.ListenAndServe(":8000", nil))
}

// openLogFile opens the given file for appending, creating it if it doesn't
// exist.
func openLogFile(path string) *os.File {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
	if err != nil {
		panic(err)
	}
	return file
}

func lookupEnvOrExit(key string) string {
	value, ok := os.LookupEnv(key)
	if !ok {
		log.Fatal(key + " not set.")
	}
	return value
}

// mailer is just the collection of args to pass to smtp.SendMail.
type mailer struct {
	addr string
	auth smtp.Auth
	from string
	to   []string
}

func newMailer() *mailer {
	username := "code.alexn@gmail.com"
	secret := lookupEnvOrExit("EMAIL_AUTH_SECRET")
	host := "smtp.elasticemail.com"
	auth := smtp.PlainAuth("", username, secret, host)
	return &mailer{
		addr: host + ":2525",
		auth: auth,
		from: username,
		to:   []string{"alex.nicoll@outlook.com"},
	}
}

func sendEmail(m *mailer, msg []byte) {
	err := smtp.SendMail(m.addr, m.auth, m.from, m.to, msg)
	if err != nil {
		log.Fatal("Failed to send email.")
	}
}

func newRqstProcFailureMsg(requestID string) []byte {
	return []byte("Subject: multi-life-dev-builder: error processing request\r\n" +
		"\r\n" +
		"Request ID: " + requestID + "\r\n" +
		"See " + serverLogFileName + " for details.\r\n")
}

func newBuildFailureMsg(commitID string) []byte {
	return []byte("Subject: multi-life-dev-builder: build failure\r\n" +
		"\r\n" +
		"Commit ID: " + commitID + "\r\n" +
		"See " + builderLogFileName + " for details.\r\n")
}

func generateRequestID(r *rand.Rand) string {
	b := make([]byte, 4)
	r.Read(b)
	return hex.EncodeToString(b)
}

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
func buildIfDependent(file string, commitID string, builderChan chan string) bool {
	if file == ".vimrc" || file == "Dockerfile" || file == "plugins.vim" {
		log.Printf("Build triggered...\n"+
			"File changed: %v\n"+
			"Commit ID: %v\n"+
			"See %v for output.\n",
			file, commitID, builderLogFileName)
		builderChan <- commitID
		return true
	}
	return false
}

// builder builds and pushes the multi-life-dev image in response to commit IDs
// sent on builderChan. If a commit ID comes in while a build is in progress,
// the build is canceled and a new one is started.
//
// builder logs to a separate file specified by the builderLogPath variable.
// This is done so that when builder runs on a separate goroutine its output is
// easily distinguishable from the output of the main goroutine. This would be
// difficult to achieve with log tags because much of builder's output comes
// from external commands, which do not use Go's logging mechanism.
func builder(builderChan chan string, m *mailer) {
	logFile := openLogFile(builderLogFileName)
	defer logFile.Close()
	// Create a logger pointing to the log file.
	logger := log.New(logFile, "", log.LstdFlags)
	// variable commitID stores the commit ID that interrupted the previous
	// build, if any.
	var commitID string
	for {
		if commitID == "" {
			// The previous build completed (was not interrupted).
			// Wait for a commit ID.
			commitID = <-builderChan
		}
		logger.Printf("Starting build. Commit ID: %v\n", commitID)

		cmd := exec.Command("docker", "build", "--no-cache", "-t",
			"alexnicoll/multi-life-dev",
			"https://github.com/alex-nicoll/multi-life-dev.git#"+commitID)
		if !run(cmd, builderChan, logFile, logger, &commitID, m) {
			continue
		}
		cmd = exec.Command("docker", "push", "alexnicoll/multi-life-dev")
		if !run(cmd, builderChan, logFile, logger, &commitID, m) {
			continue
		}
		commitID = ""
		logger.Println("Build complete.")
	}
}

func run(cmd *exec.Cmd, builderChan chan string, logFile *os.File,
	logger *log.Logger, commitID *string, m *mailer) bool {
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	logger.Printf("Running command %v\n", cmd)
	if err := cmd.Start(); err != nil {
		logger.Printf("An error occurred while starting the command: %v\n",
			err)
		sendEmail(m, newBuildFailureMsg(*commitID))
		*commitID = ""
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
			sendEmail(m, newBuildFailureMsg(*commitID))
			*commitID = ""
			return false
		}
		return true
	case *commitID = <-builderChan:
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
		// Don't send a build failure email in this case. A canceled build
		// isn't considered a failure.
		return false
	}
}
