package main

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MyServer struct {
	tmpID       int64
	tmpLogin    string
	tmpPassword string

	accessSecret  string
	refreshSecret string

	db         *mongo.Client
	collection *mongo.Collection
	ctx        context.Context

	accessTtl  time.Duration
	refreshTtl time.Duration
}

// type ForInsert struct {
// 	id           int
// 	refreshToken string
// }

func main() {

	client, err := mongo.NewClient(options.Client().ApplyURI("mongodb://localhost:8080"))
	if err != nil {
		log.Fatal(err)
	}
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(ctx)

	refreshCollection := client.Database("testing").Collection("tokens")

	s := &MyServer{
		tmpID:       1,
		tmpLogin:    "User",
		tmpPassword: "qwerty123",

		accessSecret:  "tmpAccess",
		refreshSecret: "tmpRefresh",

		db:         client, //mongoDBs
		collection: refreshCollection,
		ctx:        ctx,
		accessTtl:  20 * time.Second,
		refreshTtl: 10 * time.Minute,
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/login", s.Login)
	// mux.HandleFunc("/update", s.Update)

	//if no such page
	mux.Handle("/", s.MiddlewareToken(http.HandlerFunc(s.MainPage)))

	if err := http.ListenAndServe(":8080", mux); err != nil {
		return
	}

}

func (s *MyServer) MainPage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Auth is successed")
}

func (s *MyServer) Login(w http.ResponseWriter, r *http.Request) {

	if r.URL.Path != "/login" {
		http.Error(w, "Not found", 404)
		return
	}

	loginPage, err := template.ParseFiles("login.html")
	if err != nil {
		http.Error(w, "error", 500)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if err := loginPage.Execute(w, nil); err != nil {
			http.Error(w, "error", 500)
			return
		}
	case http.MethodPost:
		login, password := r.FormValue("login"), r.FormValue("password")

		if login != s.tmpLogin || password != s.tmpPassword {
			http.Redirect(w, r, "/", http.StatusSeeOther)
		}

		s.GenerateAndSendToken(w, r)

		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

// Create JWT access/refresh token
func (s *MyServer) GenerateAndSendToken(w http.ResponseWriter, r *http.Request) {
	//token

	accessTokenExp := time.Now().Add(s.accessTtl).Unix()

	accessTokenClaims := jwt.MapClaims{}
	accessTokenClaims["id"] = s.tmpID
	accessTokenClaims["iat"] = time.Now().Unix() //now
	accessTokenClaims["exp"] = accessTokenExp
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, accessTokenClaims) //HS512: crypto.SHA512

	accessSignedToken, err := accessToken.SignedString([]byte(s.accessSecret)) //access+secret part
	if err != nil {
		http.Error(w, "error with token", 500)
		return
	}

	refreshTokenExp := time.Now().Add(s.refreshTtl).Unix()
	refreshTokenClaims := jwt.MapClaims{}
	refreshTokenClaims["id"] = s.tmpID
	refreshTokenClaims["iat"] = time.Now().Unix()
	refreshTokenClaims["exp"] = refreshTokenExp
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS512, refreshTokenClaims)

	refreshSignedToken, err := refreshToken.SignedString([]byte(s.refreshSecret))
	if err != nil {
		http.Error(w, "error with token", 500)
		return
	}

	if err := s.insertToken(r, refreshSignedToken); err != nil { //insert refresh to mgD
		http.Error(w, "error with token", 500)
		return
	}

	fmt.Fprintf(w, "Access token: %s\nRefresh token: %s", accessSignedToken, refreshSignedToken)
}

func (s *MyServer) insertToken(r *http.Request, refresh string) error {

	result, err := s.collection.InsertOne(s.ctx, bson.D{
		{Key: "id", Value: s.tmpID},
		{Key: "refreshToken", Value: refresh},
	})

	fmt.Println(result)
	if err != nil {
		return err
	}
	return nil
}

func extractTokens(r *http.Request) (string, error) {
	header := string(r.Header.Get("Authorization"))
	if header == "" {
		return "", errors.New("Authorization header not found")
	}
	parsedHeader := strings.Split(header, " ")
	if len(parsedHeader) != 2 || parsedHeader[0] != "Bearer" {
		return "", errors.New("Invalid authorization header")

	}

	return parsedHeader[1], nil
}

func (s *MyServer) MiddlewareToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := extractTokens(r)
		if err != nil {
			log.Printf("Extract access token error: %v", err)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		}

		id, err := s.parseTokens(token, true)
		fmt.Println(id)
		if err != nil {
			log.Printf("Parse access token error: %v", err)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		} else {
			next.ServeHTTP(w, r)
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
}

func (s *MyServer) parseTokens(token string, isAccess bool) (int64, error) {
	JWTToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Failed to extract token metadata, unexpected signing method: %v", token.Header["alg"])
		}
		if isAccess {
			return []byte(s.accessSecret), nil
		}
		return []byte(s.refreshSecret), nil
	})

	if err != nil {
		return 0, err
	}

	creds, ok := JWTToken.Claims.(jwt.MapClaims)

	var credId float64
	if ok && JWTToken.Valid {

		credId, ok = creds["id"].(float64)
		if !ok {
			return 0, fmt.Errorf("Field id not found")
		}

		exp, ok := creds["exp"].(float64)
		if !ok {
			return 0, fmt.Errorf("exp not found")
		}

		expiredTime := time.Unix(int64(exp), 0)
		log.Printf("Expired: %v", expiredTime)
		if time.Now().After(expiredTime) {
			return 0, fmt.Errorf("Token expired")
		}
		return int64(credId), nil
	}

	return 0, fmt.Errorf("Invalid token")
}

func (s *MyServer) Update(w http.ResponseWriter, r *http.Request) {
	refreshToken := string(r.FormValue("refresh"))

	//checking update token
	id, err := s.parseTokens(refreshToken, false)
	if err != nil {
		log.Printf("Parse refresh token error: %v", err)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// find token
	ok := s.GetToken(id, refreshToken)
	if !ok {
		log.Printf("finding token failed")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	s.GenerateAndSendToken(w, r)
}

func (s *MyServer) GetToken(id int64, token string) bool {
	val, err := s.collection.Find(s.ctx, bson.M{})
	if err != nil {
		return false
	}

	var values []bson.M
	if err = val.All(s.ctx, values); err != nil {
		return false
	}
	fmt.Println(values)
	return token == values[0]["refreshToken"]
}
