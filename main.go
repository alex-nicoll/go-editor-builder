package main

import (
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/handle-push-event/multi-life-dev", func(w http.ResponseWriter, r *http.Request) {
	})
	http.HandleFunc("/handle-push-event/multi-life", func(w http.ResponseWriter, r *http.Request) {
	})
	log.Fatal(http.ListenAndServe(":8000", nil))
}
