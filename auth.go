package main

import (
  "fmt"
  "log"
  "net/http"
  "os"
  "time"
  "strconv"
  "encoding/base64"
  "encoding/json"
  "github.com/jmoiron/sqlx"
  _ "github.com/lib/pq"
  "github.com/gorilla/securecookie"
  "code.google.com/p/go.crypto/bcrypt"
)

const (
  cookieName string = "AUTHID"
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
  http.HandleFunc("/auth/logout", logout)
  http.HandleFunc("/auth/authenticated", authenticated)

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

func authenticated(res http.ResponseWriter, req *http.Request) {
  res.Header().Set("Content-Type", "application/json") 
  authTkn, err := readAuthCookie(req)
  if err != nil {
    http.Error(res, err.Error(), http.StatusUnauthorized)
    return
  }

  user, err := queryUserByAuthTkn(authTkn)
  if err != nil {
    http.Error(res, err.Error(), http.StatusNotFound)
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

  _, err := queryUserByUsername(username)
  if err == nil {
    http.Error(res, "username taken", http.StatusBadRequest)
    return
  }

  hashedPwd, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
  if err != nil {
    http.Error(res, err.Error(), http.StatusInternalServerError)
    return
  }

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

func readAuthCookie(req *http.Request) (authTkn string, err error) {
  cookie, err := req.Cookie(cookieName)
  if err != nil {
    return authTkn, err
  }

  hashKey := []byte("very-secret")
  var blockKey []byte
  if os.Getenv("COOKIE_SEC") == "encrypted" {
    blockKey = []byte("a-lot-secret")
  } else {
    blockKey = nil
  }
  s := securecookie.New(hashKey, blockKey)
  err = s.Decode(cookieName, cookie.Value, &authTkn)
  return authTkn, err
}

func setAuthCookie(authTkn string, res http.ResponseWriter) (err error) {
  hashKey := []byte("very-secret")
  var blockKey []byte
  var secureCookie bool
  if os.Getenv("COOKIE_SEC") == "encrypted" {
    blockKey = []byte("a-lot-secret")
    secureCookie = true
  } else {
    blockKey = nil
    secureCookie = false
  }
  s := securecookie.New(hashKey, blockKey)
  encoded, err := s.Encode(cookieName, authTkn)
  expiry := time.Now().Add(24*365*time.Hour)
  if err == nil {
    cookie := &http.Cookie{
      Name:  cookieName,
      Value: encoded,
      Path:  "/",
      HttpOnly: true,
      Secure: secureCookie,
      Expires: expiry,
    }
    http.SetCookie(res, cookie)
  }
  return err
}

func invalidateAuthCookie(res http.ResponseWriter) (err error) {
  expiry := time.Now().Add(-24*time.Hour)
  if err == nil {
    cookie := &http.Cookie{
      Name:  cookieName,
      Value: "xxx",
      Path:  "/",
      HttpOnly: true,
      Expires: expiry,
    }
    http.SetCookie(res, cookie)
  }
  return err
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

  user, err := queryUserByUsername(username)
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

  err = setAuthCookie(user.AuthToken, res)
  if err != nil {
    http.Error(res, err.Error(), http.StatusInternalServerError)
    return
  }

  fmt.Fprintln(res, jsonStr)
}

func logout(res http.ResponseWriter, req *http.Request) {
  res.Header().Set("Content-Type", "application/json") 
  err := invalidateAuthCookie(res)
  if err != nil {
    http.Error(res, err.Error(), http.StatusInternalServerError)
    return
  }
  fmt.Fprintln(res, "{'msg': 'ok'}")
}

func insertUser(username string, pwdDigest string, authTkn string) (uId int64, err error) {
  _, err = db.Execv("INSERT INTO users (username, password_digest, auth_token) VALUES ($1, $2, $3)", 
                    username,
                    pwdDigest, 
                    authTkn)
  if err != nil {
    return uId,err
  }

  user, err := queryUserByUsername(username)
  return user.Id, err
}

func queryUserByUsername(username string) (u User, err error) {
  err = db.Get(&u, "SELECT * FROM users WHERE username=$1", username)
  if err != nil {
    return u,err
  }
  return u,nil
}

func queryUserByAuthTkn(authTkn string) (u User, err error) {
  err = db.Get(&u, "SELECT * FROM users WHERE auth_token=$1", authTkn)
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
