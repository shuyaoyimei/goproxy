package goproxy

import (
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"strings"
)

var HTTP_407 = []byte("HTTP/1.1 407 Proxy Authorization Required\r\nProxy-Authenticate: Basic realm=\"Secure Proxys\"\r\n\r\n")

//Auth provides basic authorizaton for proxy server.
func (proxys *ProxyHttpServer) Auth(rw http.ResponseWriter, req *http.Request) error {
	//代理服务器登入认证
	err := auth(rw, req)
	if err != nil {
		// log.Fatalln(err)
		return err
	}
	// defer fmt.Println("11112222")
	return nil
}

//Auth provides basic authorizaton for proxy server.
func auth(rw http.ResponseWriter, req *http.Request) error {

	auth := req.Header.Get("Proxy-Authorization")
	auth = strings.Replace(auth, "Basic ", "", 1)

	if auth == "" {
		NeedAuth(rw, HTTP_407)
		return errors.New("Need Proxy Authorization!")
	}
	data, err := base64.StdEncoding.DecodeString(auth)
	if err != nil {
		log.Fatalln("when decoding %v, got an error of %v", auth, err)
		return errors.New("Fail to decoding Proxy-Authorization")
	}

	var user, passwd string

	userPasswdPair := strings.Split(string(data), ":")
	if len(userPasswdPair) != 2 {
		NeedAuth(rw, HTTP_407)
		return errors.New("user and paswd lack Fail!!!")
	} else {
		user = userPasswdPair[0]
		passwd = userPasswdPair[1]
	}
	if Check(user, passwd) == false {
		NeedAuth(rw, HTTP_407)
		return errors.New("user and passwd not match Fail!!!")
	}
	return nil
}

func NeedAuth(rw http.ResponseWriter, challenge []byte) error {
	hj, _ := rw.(http.Hijacker)
	Client, _, err := hj.Hijack()
	if err != nil {
		return errors.New("lolooo Fail!!!")
	}
	defer Client.Close()

	Client.Write(challenge)
	return nil
}

// Check checks username and password
func Check(user, passwd string) bool {
	if user != "" && passwd != "" && user == "admin" && passwd == "admin" {
		return true
	} else {
		return false
	}
}
