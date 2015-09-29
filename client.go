package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
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
	//	"bytes"
	//	"bufio"
	"io/ioutil"
	"strings"
	//"net/http/httputil"
)

const (
	aesTable = "kxproxyb8PsyCQ4b"
	kxKey    = "KxKey"
	kxEnc    = "kxEnc"
)

var (
	aesBlock cipher.Block
)
var confPath = flag.String("conf", "conf.json", "json conf")
var verbose = flag.Bool("v", false, "should every proxy request be logged to stdout")
var addr = flag.String("addr", ":8080", "proxy listen address")

var conf *client.ClientConf

var mitmConnect *goproxy.ConnectAction

func init() {
	var err error
	aesBlock, err = aes.NewCipher([]byte(aesTable))

	if err != nil {
		panic(err)
	}
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func initMimtConnect() {
	mitmConnect = &goproxy.ConnectAction{
		Action:    goproxy.ConnectMitm,
		TLSConfig: goproxy.TLSConfigFromCA(&conf.SslCert),
	}
}

var alwaysMitm goproxy.FuncHttpsHandler = func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	log.Println("https conn", host, ctx.Req.URL.String())
	return mitmConnect, host
}

var httpMitmConnect = &goproxy.ConnectAction{
	Action: goproxy.ConnectHTTPMitm,
}
var alwaysHTTPMitm goproxy.FuncHttpsHandler = func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	log.Println("https conn", host, ctx.Req.URL.String())
	return httpMitmConnect, host
}

func responseHanderFunc(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	if resp == nil {
		return resp
	}
	resp.Header.Set("Connection", "close")
	if true {
		//		fmt.Println("resp_header:\n",resp.Header)
		//		bd,_:=ioutil.ReadAll(resp.Body)
		//		fmt.Println("bd:",string(bd))
	}
	kxEnc := resp.Header.Get("_kx_enc_")
	if kxEnc == "1" {
		_ContentEncoding := resp.Header.Get("_kx_content_encoding")
		resp.Header.Del("_kx_content_encoding")
		fmt.Println("_ContentEncoding", _ContentEncoding)
		if _ContentEncoding != "" {
			resp.Header.Set("Content-Encoding", _ContentEncoding)
		}

		body := resp.Body
		skey := resp.Request.Header.Get(kxKey)
		encodeURL := resp.Request.URL.Path[len("/p/"):]
		r := cipherStreamReader(skey, encodeURL, body)
		resp.Body = ioutil.NopCloser(r)
	}
	//			bd,err:=ioutil.ReadAll(resp.Body)
	//		fmt.Println("bd:",string(bd),"err:",err)

	return resp
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

//对数据流进行加密
func cipherStreamReader(skey string, encodeURL string, reader io.Reader) *cipher.StreamReader {
	key := strMd5(fmt.Sprintf("%s#kxsw#%s", skey, encodeURL))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	var iv [aes.BlockSize]byte
	stream := cipher.NewOFB(block, iv[:])
	return &cipher.StreamReader{S: stream, R: reader}
}

func strMd5(mystr string) []byte {
	h := md5.New()
	h.Write([]byte(mystr))
	return h.Sum(nil)
}

func encryptURL(srcURL string) (string, error) {
	src := []byte(srcURL)
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
	log.Println("raw_url->", urlOld)
	r.Header.Set("Connection", "Close")
	r.Header.Del("Proxy-Connection")

	if conf.IsProxyHost(urlOld) {
		log.Println("direct IsProxyHost->", urlOld)
		return r, nil
	}

	//	var urlReq = base64.StdEncoding.EncodeToString([]byte(urlOld))
	urlReq, err := encryptURL(urlOld)

	if err != nil {
		log.Println("encryptURL", urlOld, "failed", err)
		return r, goproxy.NewResponse(r, goproxy.ContentTypeHtml, http.StatusBadGateway, "encrypt url failed")
	}

	proxy := conf.GetOneProxy()
	if proxy == nil {
		log.Println("no proxy")
		return r, goproxy.NewResponse(r, goproxy.ContentTypeHtml, http.StatusBadGateway, "no proxy")
	}

	urlNew := strings.TrimRight(proxy.Url, "/") + "/p/" + urlReq

	log.Println(urlOld, "--->", urlNew)
	//	var err error
	r.URL, err = url.Parse(urlNew)

	if err != nil {
		log.Println("parse new url failed", err)
		return r, goproxy.NewResponse(r, goproxy.ContentTypeHtml, http.StatusBadGateway, "create url failed,check proxy url")
	}

	r.Host = r.URL.Host

	r.Header.Add("is_client", "1")
	r.Header.Set(kxKey, proxy.SecertKey)
	if conf.HiddenIp {
		r.Header.Set("hidden_ip", "1")
	}
	//	panic("a")

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
		proxy.OnRequest().HandleConnectFunc(alwaysMitm)
	} else {
		proxy.OnRequest().HandleConnectFunc(alwaysHTTPMitm)
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
