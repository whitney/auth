package main

import (
  "fmt"
  "log"
  "net/http"
  "os"
  "github.com/jmoiron/sqlx"
  _ "github.com/lib/pq"
  //"github.com/gorilla/securecookie"
  "code.google.com/p/go.crypto/bcrypt"
)

var db *sqlx.DB

func main() {
  var err error
  // Connect to a database and verify with a ping.
  db, err = sqlx.Connect("postgres", "user=whitney password=pants dbname=auth_devel sslmode=disable")
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
  Id             int
  Username       string
  PasswordDigest string `db:"password_digest"`
  AuthToken      string `db:"auth_token"`
}

func test(res http.ResponseWriter, req *http.Request) {
  res.Header().Set("Content-Type", "application/json") 

  password := req.FormValue("password")
  if len(password) < 5 {
    http.Error(res, "invalid password", http.StatusBadRequest)
    return
  }

  hashedPwd, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
  if err != nil {
    http.Error(res, err.Error(), http.StatusInternalServerError)
    return
  }

  fmt.Fprintln(res, "hashedPwd: " + string(hashedPwd))
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

  //authTkn := string(securecookie.GenerateRandomKey(64)) 
  authTkn := "pants"
  log.Printf("authTkn: %s", authTkn)

  uId, err := insertUser(username, string(hashedPwd), authTkn)
  if err != nil {
    http.Error(res, err.Error(), http.StatusInternalServerError)
    return
  }

  uMap := make(map[string]string)
  uMap["id"] = string(uId)
  uMap["username"] = username

  //fmt.Fprintln(res, "{'msg': 'ok'}")
  fmt.Fprintln(res, uMap)
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

  fmt.Fprintln(res, "{'msg': 'ok'}")
}

func insertUser(username string, pwdDigest string, authTkn string) (uId int64, err error) {
  tx := db.MustBegin()
  res, err := tx.Execv("INSERT INTO users (username, password_digest, auth_token) VALUES ($1, $2, $3)", 
                    username,
                    pwdDigest, 
                    authTkn)
  tx.Commit()
  return res.LastInsertId()
}

func queryUser(username string) (u User, err error) {
  u = User{}
  row := db.QueryRowx("SELECT * FROM users WHERE username=?", username)
  err = row.StructScan(&u)
  log.Printf("u.Username: %s", u.Username)
  if err != nil {
    return u,err
  }
  return u,nil
}
