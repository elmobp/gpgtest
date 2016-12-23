package main

import (
    "encoding/hex"
    "bytes"
    "golang.org/x/crypto/openpgp"
    "github.com/jcmdev0/gpgagent"
   "encoding/base64"
    "io/ioutil"
    "log"
    "os"
    "strings"
)

// create gpg keys with
// $ gpg --gen-key
// ensure you correct paths and passphrase

func getKeyByEmail(keyring openpgp.EntityList, email string) *openpgp.Entity {
  for _, entity := range keyring {
    for _, ident := range entity.Identities {
      if ident.UserId.Email == email {
        return entity
      }
    }
  }

  return nil
}

func encryptPassword(password string, email string) (string, error) {
    homeDir := os.Getenv("HOME") // *nix
    secretKeyring := homeDir + "/.gnupg/secring.gpg"
    publicKeyring := homeDir + "/.gnupg/pubring.gpg"

    // Read in public key
    keyringFileBuffer, _ := os.Open(publicKeyring)
    defer keyringFileBuffer.Close()
    privringFile, _ := os.Open(secretKeyring)
    privring, _ := openpgp.ReadKeyRing(privringFile)
    // encrypt string
    buf := new(bytes.Buffer)
    myPrivateKey := getKeyByEmail(privring, email)
    w, err := openpgp.Encrypt(buf, []*openpgp.Entity{myPrivateKey}, nil, nil, nil)
    if err != nil {
        return "", err
    }
    _, err = w.Write([]byte(password))
    if err != nil {
        return "", err
    }
    err = w.Close()
    if err != nil {
        return "", err
    }

    // Encode to base64
    bytes, err := ioutil.ReadAll(buf)
    if err != nil {
        return "", err
    }
    encStr := base64.StdEncoding.EncodeToString(bytes)

    return encStr, nil
}

func decryptPassword(encString string, email string) (string, error) {
    homeDir := os.Getenv("HOME") // *nix
    secretKeyring := homeDir + "/.gnupg/secring.gpg"
    conn, err := gpgagent.NewGpgAgentConn()
    if err != nil {
       panic(err)
    }
    defer conn.Close()

    privringFile, _ := os.Open(secretKeyring)
    if err != nil {
	panic(err)
    }
    defer privringFile.Close()
    privring, err := openpgp.ReadKeyRing(privringFile)
    if err != nil {
	panic(err)
    } 
    myPrivateKey := getKeyByEmail(privring, email)
    keyId   := []byte(myPrivateKey.PrivateKey.KeyIdString())
    cacheId := strings.ToUpper(hex.EncodeToString(keyId))
    request := gpgagent.PassphraseRequest{CacheKey: cacheId}
    passphrase, err := conn.GetPassphrase(&request)

    // init some vars
    var entity *openpgp.Entity
    var entityList openpgp.EntityList

    // Open the private key file
    keyringFileBuffer, err := os.Open(secretKeyring)
    if err != nil {
        return "", err
    }
    defer keyringFileBuffer.Close()
    entityList, err = openpgp.ReadKeyRing(keyringFileBuffer)
    if err != nil {
        return "", err
    }
    entity = entityList[0]

    passphraseByte := []byte(passphrase)
    entity.PrivateKey.Decrypt(passphraseByte)
    for _, subkey := range entity.Subkeys {
        subkey.PrivateKey.Decrypt(passphraseByte)
    }

    dec, err := base64.StdEncoding.DecodeString(encString)
    if err != nil {
        return "", err
    }

    md, err := openpgp.ReadMessage(bytes.NewBuffer(dec), entityList, nil, nil)
    if err != nil {
        return "", err
    }
    bytes, err := ioutil.ReadAll(md.UnverifiedBody)
    if err != nil {
        return "", err
    }
    decStr := string(bytes)

    return decStr, nil
}

func main() {
    encStr, err := encryptPassword("test", "michael.baker@bulletproof.net")
    if err != nil {
        log.Fatal(err)
    }
    decStr, err := decryptPassword(encStr, "michael.baker@bulletproof.net")
    if err != nil {
        log.Fatal(err)
    }
    // should be done
    log.Println("Decrypted Secret:", decStr)
}
