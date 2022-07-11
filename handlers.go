package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"gopkg.in/mgo.v2/bson"

	"github.com/chris92vr/go-session-auth-mongo/database"
	"github.com/chris92vr/go-session-auth-mongo/models"
)

var userCollection = database.OpenCollection(database.Client, "users")
var validate = validator.New()

// this map stores the users sessions. For larger scale applications, you can use a database or cache for this purpose
var sessions = map[string]session{}

// each session contains the username of the user and the time at which it expires
type session struct {
	username string
	expiry   time.Time
}

// we'll use this method later to determine if the session has expired
func (s session) isExpired() bool {
	return s.expiry.Before(time.Now())
}

type Credentials struct {
	Password string `json:"password"`
	Username string `json:"email"`
}

func Login(w http.ResponseWriter, r *http.Request) {
	var credentials Credentials
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = validate.Struct(credentials)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var user models.User
	err = userCollection.FindOne(context.TODO(), bson.M{"email": credentials.Username}).Decode(&user)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if user.Password != credentials.Password {
		fmt.Println("wrong password")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	sessionToken := uuid.NewString()
	expiresAt := time.Now().Add(time.Minute * 30)
	sessions[sessionToken] = session{username: credentials.Username, expiry: expiresAt}

	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   sessionToken,
		Expires: expiresAt,
	})

	fmt.Println("user logged in")
	fmt.Println(&http.Cookie{
		Name:    "session_token",
		Value:   sessionToken,
		Expires: expiresAt,
	})

	// we'll use this later to determine if the session has expired
	// func (s session) isExpired() bool {
	// 	return s.expiry.Before(time.Now())
	// }

}

func Signup(w http.ResponseWriter, r *http.Request) {
	var user models.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = validate.Struct(user)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	count, err := userCollection.CountDocuments(context.TODO(), bson.M{"email": user.Email})
	if err != nil {
		fmt.Println(err, "error counting documents")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if count > 0 {
		fmt.Println("user already exists")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	user.ID = primitive.NewObjectID()
	user.Created_at = time.Now()
	user.Updated_at = time.Now()
	user.User_id = user.ID.Hex()

	_, err = userCollection.InsertOne(context.TODO(), user)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"userID": user.ID.Hex()})

	fmt.Println("user created")

}

func Welcome(w http.ResponseWriter, r *http.Request) {
	// We can obtain the session token from the requests cookies, which come with every request
	c, err := r.Cookie("session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			// If the cookie is not set, return an unauthorized status
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// For any other type of error, return a bad request status
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	sessionToken := c.Value

	// We then get the name of the user from our session map, where we set the session token
	userSession, exists := sessions[sessionToken]
	if !exists {
		// If the session token is not present in session map, return an unauthorized error
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if userSession.isExpired() {
		delete(sessions, sessionToken)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// Finally, return the welcome message to the user
	fmt.Fprintf(w, "Welcome, %s!", userSession.username)
	fmt.Print("Welcome, ", userSession.username)

}

func Refresh(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_token")
	if sessionID == "" {
		fmt.Println("no sessionID provided")
		return
	}

	if sessions[sessionID].isExpired() {
		fmt.Println("session expired")
		return
	}

	var user models.User
	err := userCollection.FindOne(context.TODO(), bson.M{"user_id": sessions[sessionID].username}).Decode(&user)
	if err != nil {
		fmt.Println(err)
		return
	}

	sessionID = uuid.New().String()
	sessions[sessionID] = session{user.User_id, time.Now().Add(time.Minute * 30)}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"sessionID": sessionID})
}

func Logout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			// If the cookie is not set, return an unauthorized status
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// For any other type of error, return a bad request status
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	sessionToken := c.Value

	// remove the users session from the session map
	delete(sessions, sessionToken)

	// We need to let the client know that the cookie is expired
	// In the response, we set the session token to an empty
	// value and set its expiry as the current time
	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   "",
		Expires: time.Now(),
	})
}
