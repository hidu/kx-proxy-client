package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/elazarl/goproxy"
	"github.com/hidu/kx-proxy-client/client"
	"io"
	"log"
	"net/http"
	"net/url"
)

const (
	aesTable = "kxproxyb8PsyCQ4b"
)

var (
	aesBlock cipher.Block
)
var confPath = flag.String("conf", "conf.json", "json conf")
var verbose = flag.Bool("v", false, "should every proxy request be logged to stdout")
var addr = flag.String("addr", ":8080", "proxy listen address")

var conf *client.ClientConf

var MitmConnect *goproxy.ConnectAction

func init() {
	var err error
	aesBlock, err = aes.NewCipher([]byte(aesTable))

	if err != nil {
		panic(err)
	}
}

func initMimtConnect() {
	MitmConnect = &goproxy.ConnectAction{
		Action:    goproxy.ConnectMitm,
		TLSConfig: goproxy.TLSConfigFromCA(&conf.SslCert),
	}
}

var AlwaysMitm goproxy.FuncHttpsHandler = func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	log.Println("https conn", host, ctx.Req.URL.String())
	return MitmConnect, host
}

var HttpMitmConnect = &goproxy.ConnectAction{
	Action: goproxy.ConnectHTTPMitm,
}
var AlwaysHttpMitm goproxy.FuncHttpsHandler = func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	log.Println("https conn", host, ctx.Req.URL.String())
	return HttpMitmConnect, host
}

func responseHanderFunc(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	if resp != nil {
		resp.Header.Set("Connection", "close")
	}
	return resp
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func encryptUrl(srcUrl string) (string, error) {
	src := []byte(srcUrl)
	padLen := aes.BlockSize - (len(src) % aes.BlockSize)

	for i := 0; i < padLen; i++ {
		src = append(src, byte(padLen))
	}

	srcLen := len(src)
	encryptText := make([]byte, srcLen+aes.BlockSize)

	iv := encryptText[srcLen:]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(aesBlock, iv)

	mode.CryptBlocks(encryptText[:srcLen], src)
	s := base64.URLEncoding.EncodeToString(encryptText)
	return s, nil

}

func requestHanderFunc(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	urlOld := r.URL.String()
	log.Println("url->", urlOld)
	r.Header.Set("Connection", "Close")
	r.Header.Del("Proxy-Connection")

	if conf.IsProxyHost(urlOld) {
		log.Println(urlOld, "direct")
		return r, nil
	}

	//	var urlReq = base64.StdEncoding.EncodeToString([]byte(urlOld))
	urlReq, err := encryptUrl(urlOld)

	if err != nil {
		log.Println("encryptUrl", urlOld, "failed", err)
		return r, nil
	}

	proxyUrl := conf.GetOneHost()
	urlNew := proxyUrl + "/p/" + urlReq
	log.Println(urlOld, "--->", urlNew)
	//	var err error
	r.URL, err = url.Parse(urlNew)
	r.Host = r.URL.Host

	r.Header.Add("is_client", "1")
	r.Header.Set("KxKey", conf.GetSecertKeyByUrl(proxyUrl))
	if conf.HiddenIp {
		r.Header.Set("hidden_ip", "1")
	}

	if err != nil {
		log.Println("parse new url failed", err)
	}
	return r, nil
}
func init() {
	df := flag.Usage
	flag.Usage = func() {
		df()
		fmt.Println("\nkx-proxy client\n config eg:\n", client.Assest.GetContent("res/conf.json"))
	}
}

func main() {
	flag.Parse()
	conf = client.LoadConf(*confPath)
	initMimtConnect()

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = *verbose
	if conf.SSlOn {
		proxy.OnRequest().HandleConnectFunc(AlwaysMitm)
	} else {
		proxy.OnRequest().HandleConnectFunc(AlwaysHttpMitm)
	}
	proxy.OnRequest().DoFunc(requestHanderFunc)
	proxy.OnResponse().DoFunc(responseHanderFunc)
	if conf.ParentProxy != "" {
		proxy.Tr = &http.Transport{
			Proxy: func(req *http.Request) (*url.URL, error) {
				return url.Parse(conf.ParentProxy)
			},
		}
	}
	log.Println("proxy client listen at ", *addr)
	err := http.ListenAndServe(*addr, proxy)
	log.Fatal(err)
}
