package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
)

// When unmarshaling JSON to a struct via json.Unmarshal, object keys which
// don't have a corresponding struct field are ignored. We'll use this property
// to define the payload struct such that it contains only the parts of the
// JSON that we are interested in. Field names must be exported so that
// encoding/json can access them.
type payload struct {
	Commits []commit
}

type commit struct {
	Added    []string
	Removed  []string
	Modified []string
}

func main() {
	secret := os.Getenv("MULTI_LIFE_DEV_HOOK_SECRET")
	http.HandleFunc("/handle-push-event/multi-life-dev", func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		macStr := r.Header.Get("X-Hub-Signature-256")
		if macStr == "" {
			log.Println("Request at /multi-life-dev is missing a MAC.")
			return
		}
		// macStr should contain a hex string prepended with "sha256=".
		// Remove the "sha256=" and decode the hex string to bytes.
		mac, err := hex.DecodeString(macStr[7:])
		if err != nil {
			log.Println("Request at /multi-life-dev contains a malformed MAC.")
			return
		}
		hashFn := hmac.New(sha256.New, []byte(secret))
		body := make([]byte, r.ContentLength)
		for i := 0; ; {
			n, err := r.Body.Read(body[i:])
			if err == io.EOF {
				break
			}
			if err != nil {
				log.Println(err)
				return
			}
			i += n
		}
		hashFn.Write(body)
		expectedMac := hashFn.Sum(nil)
		if !hmac.Equal(mac, expectedMac) {
			log.Printf("Request at /multi-life-dev contains an unexpected "+
				"MAC.\nExpected %x\nGot %x\n", expectedMac, mac)
		}
		p := &payload{}
		json.Unmarshal(body, p)
		for _, com := range p.Commits {
			for _, file := range com.Added {
				if isDependency(file) {
					log.Println("build triggered")
					return
				}
			}
			for _, file := range com.Removed {
				if isDependency(file) {
					log.Println("build triggered")
					return
				}
			}
			for _, file := range com.Modified {
				if isDependency(file) {
					log.Println("build triggered")
					return
				}
			}
		}
	})
	http.HandleFunc("/handle-push-event/multi-life", func(w http.ResponseWriter, r *http.Request) {
	})
	log.Fatal(http.ListenAndServe(":8000", nil))
}

// isDependency returns true if the given file should trigger a build when it changes.
func isDependency(file string) bool {
	return file == ".vimrc" || file == "Dockerfile" || file == "plugins.vim"
}
