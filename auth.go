package auth

import (
  //"log"
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

type User struct {
  Id             int64
  Username       string
  PasswordDigest string `db:"password_digest"`
  AuthToken      string `db:"auth_token"`
}

func (u *User) Json() (string, error) {
  uMap := make(map[string]string)
  uMap["id"] = strconv.Itoa(int(u.Id))
  uMap["username"] = u.Username
  return JsonWrapMap(uMap)
}

func AuthenticateUser(db *sqlx.DB, req *http.Request) (u User, err error) {
  authTkn, err := readAuthCookie(req)
  if err != nil {
    return u,err
  }
  return queryUserByAuthTkn(db, authTkn)
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

func SetAuthCookie(authTkn string, res http.ResponseWriter) (err error) {
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

func InvalidateAuthCookie(res http.ResponseWriter) {
  cookie := &http.Cookie{
    Name:  cookieName,
    Value: "xxx",
    Path:  "/",
    HttpOnly: true,
    Expires: time.Now().Add(-24*time.Hour),
  }
  http.SetCookie(res, cookie)
}

func CreateAuthTkn() string {
  return base64.URLEncoding.EncodeToString(securecookie.GenerateRandomKey(32))
}

func HashPassword(pwd string) ([]byte, error) {
  return bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
}

func CompareHashAndPassword(pwdDigest string, pwd string) error {
  return bcrypt.CompareHashAndPassword([]byte(pwdDigest), []byte(pwd))
}

func InsertUser(db *sqlx.DB, username string, pwdDigest string, authTkn string) (u User, err error) {
  _, err = db.Execv("INSERT INTO users (username, password_digest, auth_token) VALUES ($1, $2, $3)", 
                    username,
                    pwdDigest, 
                    authTkn)
  if err != nil {
    return u,err
  }

  return QueryUserByUsername(db, username)
}

func QueryUserByUsername(db *sqlx.DB, username string) (u User, err error) {
  err = db.Get(&u, "SELECT * FROM users WHERE username=$1", username)
  if err != nil {
    return u,err
  }
  return u,nil
}

func queryUserByAuthTkn(db *sqlx.DB, authTkn string) (u User, err error) {
  err = db.Get(&u, "SELECT * FROM users WHERE auth_token=$1", authTkn)
  if err != nil {
    return u,err
  }
  return u,nil
}

func JsonWrapStr(s string) (js string, err error) {
  m := make(map[string]string)
  m["msg"] = s
  return JsonWrapMap(m)
}

func JsonWrapMap(m map[string]string) (s string, err error) {
  json, err := json.Marshal(m)
  if err != nil {
    return s, err
  }
  return string(json),nil
}
