package main

import (
  "fmt"
  "log"
  "net/http"
  "os"
  "strconv"
  "encoding/base64"
  "encoding/json"
  "github.com/jmoiron/sqlx"
  _ "github.com/lib/pq"
  "github.com/gorilla/securecookie"
  "code.google.com/p/go.crypto/bcrypt"
)

var db *sqlx.DB

func main() {
  var err error
  // Connect to a database and verify with a ping.
  // postgres://uname:pwd@host/dbname?sslmode=disable
  dbUrl := os.Getenv("PG_HOST")
  db, err = sqlx.Connect("postgres", dbUrl)
  if err != nil {
    panic(err)
  }

  http.HandleFunc("/auth/signup", createUser)
  http.HandleFunc("/auth/login", login)
  http.HandleFunc("/auth/test", test)

  log.Println("listening...")
  err = http.ListenAndServe(":"+os.Getenv("AUTH_PORT"), nil)
  if err != nil {
    panic(err)
  }
}

type User struct {
  Id             int64
  Username       string
  PasswordDigest string `db:"password_digest"`
  AuthToken      string `db:"auth_token"`
}

func test(res http.ResponseWriter, req *http.Request) {
  res.Header().Set("Content-Type", "application/json") 
  authTkn := base64.URLEncoding.EncodeToString(securecookie.GenerateRandomKey(32)) 
  log.Printf("len(authTkn): %s", len(authTkn))
  fmt.Fprintln(res, "authTkn: " + authTkn)
}

func createUser(res http.ResponseWriter, req *http.Request) {
  res.Header().Set("Content-Type", "application/json") 

  username := req.FormValue("username")
  if len(username) == 0 {
    http.Error(res, "username missing", http.StatusBadRequest)
    return
  }

  password := req.FormValue("password")
  if len(password) < 5 {
    http.Error(res, "invalid password", http.StatusBadRequest)
    return
  }

  _, err := queryUser(username)
  if err == nil {
    http.Error(res, "username taken", http.StatusBadRequest)
    return
  }

  hashedPwd, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
  if err != nil {
    http.Error(res, err.Error(), http.StatusInternalServerError)
    return
  }
  log.Printf("hashedPwd: %s", string(hashedPwd))

  authTkn := base64.URLEncoding.EncodeToString(securecookie.GenerateRandomKey(32)) 
  log.Printf("authTkn: %s", authTkn)

  uId, err := insertUser(username, string(hashedPwd), authTkn)
  if err != nil {
    http.Error(res, err.Error(), http.StatusInternalServerError)
    return
  }

  uMap := make(map[string]string)
  uMap["id"] = strconv.Itoa(int(uId))
  uMap["username"] = username
  json, err := json.Marshal(uMap)
  if err != nil {
    http.Error(res, err.Error(), http.StatusInternalServerError)
    return
  }

  fmt.Fprintln(res, string(json))
}

func login(res http.ResponseWriter, req *http.Request) {
  res.Header().Set("Content-Type", "application/json") 

  username := req.FormValue("username")
  if len(username) == 0 {
    http.Error(res, "username missing", http.StatusBadRequest)
    return
  }

  password := req.FormValue("password")
  if len(password) == 0 {
    http.Error(res, "password missing", http.StatusBadRequest)
    return
  }

  user, err := queryUser(username)
  if err != nil {
    http.Error(res, err.Error(), http.StatusNotFound)
    return
  }

  hashedPassword := []byte(user.PasswordDigest)
  err = bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
  if err != nil {
    http.Error(res, err.Error(), http.StatusUnauthorized)
    return
  }

  uMap := make(map[string]string)
  uMap["id"] = strconv.Itoa(int(user.Id))
  uMap["username"] = user.Username
  jsonStr, err := jsonWrapMap(uMap)
  if err != nil {
    http.Error(res, err.Error(), http.StatusInternalServerError)
    return
  }

  fmt.Fprintln(res, jsonStr)
}

func insertUser(username string, pwdDigest string, authTkn string) (uId int64, err error) {
  _, err = db.Execv("INSERT INTO users (username, password_digest, auth_token) VALUES ($1, $2, $3)", 
                    username,
                    pwdDigest, 
                    authTkn)
  if err != nil {
    return uId,err
  }

  user, err := queryUser(username)
  return user.Id, err
}

func queryUser(username string) (u User, err error) {
  err = db.Get(&u, "SELECT * FROM users WHERE username=$1", username)
  if err != nil {
    return u,err
  }
  return u,nil
}

func jsonWrapStr(s string) (js string, err error) {
  m := make(map[string]string)
  m["msg"] = s
  return jsonWrapMap(m)
}

func jsonWrapMap(m map[string]string) (s string, err error) {
  json, err := json.Marshal(m)
  if err != nil {
    return s, err
  }
  return string(json),nil
}
