package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

// VulnerableServer creates a simple HTTP server with known vulnerabilities for testing
func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8089"
	}

	// XSS vulnerability - reflects user input without sanitization
	http.HandleFunc("/xss", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		fmt.Fprintf(w, "<html><body>Hello %s!</body></html>", name)
	})

	// Information disclosure - exposes server headers
	http.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "Go/1.19")
		w.Header().Set("Server", "VulnerableServer/1.0")
		fmt.Fprintf(w, "Server Information Page")
	})

	// Directory listing vulnerability
	http.HandleFunc("/files/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Index of /files/\n")
		fmt.Fprintf(w, "config.txt\n")
		fmt.Fprintf(w, "backup.sql\n")
		fmt.Fprintf(w, ".env\n")
	})

	// Sensitive file exposure
	http.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "DB_PASSWORD=secret123\n")
		fmt.Fprintf(w, "API_KEY=sk-1234567890abcdef\n")
	})

	// Admin panel without authentication
	http.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><body><h1>Admin Panel</h1><p>Welcome to admin area</p></body></html>")
	})

	// Basic page for technology detection
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><head><title>Test Server</title></head><body>Welcome</body></html>")
	})

	log.Printf("Starting vulnerable server on port %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}
