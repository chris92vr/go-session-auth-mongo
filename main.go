package main

import (
	"log"
	"net/http"
	"os"
)

func main() {
	// "Signin" and "Signup" are handlers that we have to implement
	port := os.Getenv("PORT")

	if port == "" {
		port = "8000"
	}

	http.HandleFunc("/signin", Login)
	http.HandleFunc("/signup", Signup)
	http.HandleFunc("/welcome", Welcome)
	http.HandleFunc("/refresh", Refresh)
	http.HandleFunc("/logout", Logout)
	http.HandleFunc("/profile", MyProfile)
	// start the server on port 8080
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
