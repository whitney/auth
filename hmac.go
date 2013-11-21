package authcore

import (
  "bytes"
  "crypto/hmac"
  "crypto/sha256"
  "errors"
  "encoding/hex"
  "net/http"
  "os"
  "strings"
  "log"
  "sort"
  "net/url"
)

const (
  defaultMaxMemory = 32 << 20 // 32 MB
  authHeader = "Authentication"
  xHMACPrefix = "Hmac"
  xHMACDate = "X-Hmac-Date"
  xHMACNonce = "X-Hmac-Nonce"
)

func Authenticate(req *http.Request) (err error) {
  authHeader := req.Header.Get(authHeader)
  if len(authHeader) == 0 {
    return errors.New("Missing Authentication header")
  }

  authTkns := strings.Split(authHeader, " ")
  if len(authTkns) != 2 {
    return errors.New("Malformed auth-tokens")
  }

  apiKey := []byte(authTkns[0])
  signature := []byte(authTkns[1])

  if !checkApiClient(apiKey) {
    log.Println("ERROR unknown API client")
    return errors.New("Error authenticating")
  }

  canonicalRep, err := canonicalRep(req)
  if err != nil {
    log.Printf("ERROR creating canonicalRep: %s", err)
    return err
  }
  sharedSecret := []byte(os.Getenv("GAUTH_SHARED_SECRET"))
  expectedMAC := computeSignature([]byte(canonicalRep), sharedSecret)

  if !hmac.Equal(signature, expectedMAC){
    log.Printf("ERROR signature and expectedMAC mismatch for:\n%s", canonicalRep)
    log.Printf("*** expected signature: %s", string(expectedMAC))
    log.Printf("*** computed signature: %s", string(signature))
    return errors.New("Error authenticating")
  }

  return nil
}

func checkApiClient(apiKey []byte) bool {
  // constant time byte comparison
  return hmac.Equal(apiKey, []byte(os.Getenv("GAUTH_API_TOKEN")))
}

func computeSignature(message, sharedSecret []byte) []byte {
  mac := hmac.New(sha256.New, sharedSecret)
  mac.Write(message)
  return []byte(hex.EncodeToString(mac.Sum(nil)))
}

func canonicalRep(req *http.Request) (rep string, err error) {
  err = req.ParseMultipartForm(defaultMaxMemory)
  if err != nil {
    return rep, err
  }
  var repBuff bytes.Buffer

  // HTTP verb (GET, POST,...) uppercased
  repBuff.WriteString(strings.ToUpper(req.Method+"\n"))
  // original URI
  repBuff.WriteString(req.RequestURI+"\n")

  // original headers
  headers := req.Header
  if hmacDate := headers[xHMACDate]; len(hmacDate) > 0 {
    repBuff.WriteString("date:"+hmacDate[0]+"\n")
  } else {
    repBuff.WriteString("date:\n")
  }
  if hmacNonce := headers[xHMACNonce]; len(hmacNonce) > 0 {
    repBuff.WriteString("nonce:"+hmacNonce[0]+"\n")
  } else {
    repBuff.WriteString("nonce:\n")
  }

  // request params
  params := canonicalParams(req.Form)
  for _, v := range params {
    repBuff.WriteString(v+":"+req.Form[v][0]+"\n")
  }

  rep = repBuff.String()
  return rep, nil
}

func canonicalParams(m url.Values) []string {
    mk := make([]string, len(m))
    i := 0
    for k, _ := range m {
        mk[i] = k
        i++
    }
    sort.Strings(mk)
    return mk
}
