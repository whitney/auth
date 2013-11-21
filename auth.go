package main

import (
  "fmt"
  "log"
  "net/http"
  "os"
  "strconv"
  "encoding/json"
  "github.com/whitney/auth/authcore"
  "github.com/jmoiron/sqlx"
  _ "github.com/lib/pq"
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

  http.HandleFunc("/auth/signup", signup)
  http.HandleFunc("/auth/login", login)
  http.HandleFunc("/auth/logout", logout)
  http.HandleFunc("/auth/authenticated", authenticated)

  log.Println("listening...")
  err = http.ListenAndServe(":"+os.Getenv("AUTH_PORT"), nil)
  if err != nil {
    panic(err)
  }
}

// API
func authenticated(res http.ResponseWriter, req *http.Request) {
  res.Header().Set("Content-Type", "application/json") 
  authTkn, err := authcore.ReadAuthCookie(req)
  if err != nil {
    http.Error(res, err.Error(), http.StatusUnauthorized)
    return
  }

  user, err := authcore.QueryUserByAuthTkn(db, authTkn)
  if err != nil {
    http.Error(res, err.Error(), http.StatusNotFound)
    return
  }

  uMap := make(map[string]string)
  uMap["id"] = strconv.Itoa(int(user.Id))
  uMap["username"] = user.Username
  jsonStr, err := authcore.JsonWrapMap(uMap)
  if err != nil {
    http.Error(res, err.Error(), http.StatusInternalServerError)
    return
  }

  fmt.Fprintln(res, jsonStr)
}

// API
func signup(res http.ResponseWriter, req *http.Request) {
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

  _, err := authcore.QueryUserByUsername(db, username)
  if err == nil {
    http.Error(res, "username taken", http.StatusBadRequest)
    return
  }

  hashedPwd, err := authcore.HashPassword(password)
  if err != nil {
    http.Error(res, err.Error(), http.StatusInternalServerError)
    return
  }

  authTkn := authcore.CreateAuthTkn()
  log.Printf("authTkn: %s", authTkn)

  uId, err := authcore.InsertUser(db, username, string(hashedPwd), authTkn)
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

// API
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

  user, err := authcore.QueryUserByUsername(db, username)
  if err != nil {
    http.Error(res, err.Error(), http.StatusNotFound)
    return
  }

  err = authcore.CompareHashAndPassword(user.PasswordDigest, password)
  if err != nil {
    http.Error(res, err.Error(), http.StatusUnauthorized)
    return
  }

  uMap := make(map[string]string)
  uMap["id"] = strconv.Itoa(int(user.Id))
  uMap["username"] = user.Username
  jsonStr, err := authcore.JsonWrapMap(uMap)
  if err != nil {
    http.Error(res, err.Error(), http.StatusInternalServerError)
    return
  }

  err = authcore.SetAuthCookie(user.AuthToken, res)
  if err != nil {
    http.Error(res, err.Error(), http.StatusInternalServerError)
    return
  }

  fmt.Fprintln(res, jsonStr)
}

// API
func logout(res http.ResponseWriter, req *http.Request) {
  res.Header().Set("Content-Type", "application/json") 
  authcore.InvalidateAuthCookie(res)
  fmt.Fprintln(res, "{'msg': 'ok'}")
}
