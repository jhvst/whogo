package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
	"whogo"
)

type response map[string]interface{}

func (r response) String() (s string) {
	b, err := json.Marshal(r)
	if err != nil {
		s = ""
		return
	}
	s = string(b)
	return
}

func main() {

	// Launch HTTP server to take in domain queries.
	// For example, navigate to localhost:8080/medium.com to see the results.

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		status, _ := whogo.Whois(r.URL.Path[1:], 3*time.Second)
		records := whogo.Records(status)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, response{"available": whogo.Available(status), "whois": records})
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
