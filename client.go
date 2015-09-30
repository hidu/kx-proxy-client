package main

import (
	"flag"
	"fmt"
	"github.com/elazarl/goproxy"
	"github.com/hidu/kx-proxy-client/client"
	kxutil "github.com/hidu/kx-proxy/util"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
)

const (
	kxKey = "KxKey"
	kxEnc = "kxEnc"
)

var confPath = flag.String("conf", "conf.json", "json conf")
var verbose = flag.Bool("v", false, "should every proxy request be logged to stdout")
var addr = flag.String("addr", ":8080", "proxy listen address")

var conf *client.ClientConf

var mitmConnect *goproxy.ConnectAction

func init() {
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

	kxEnc := resp.Header.Get("_kx_enc_")

	kxutil.HeaderDec(resp.Header)
	//goproxy 会对Content-Encoding =gzip 做处理
	//HeaderDec 会对 Content-Encoding 做处理可以让这里的逻辑读取到原始的加密的数据流

	if kxEnc == "1" {
		body := resp.Body
		skey := resp.Request.Header.Get(kxKey)
		encodeURL := resp.Request.URL.Path[len("/p/"):]
		r := kxutil.CipherStreamReader(skey, encodeURL, body)
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

func requestHanderFunc(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	urlOld := r.URL.String()
	log.Println("raw_url->", urlOld)
	r.Header.Set("Connection", "Close")
	r.Header.Del("Proxy-Connection")

	if conf.IsProxyHost(urlOld) {
		log.Println("direct IsProxyHost->", urlOld)
		return r, nil
	}

	proxy := conf.GetOneProxy()
	if proxy == nil {
		log.Println("no proxy")
		return r, goproxy.NewResponse(r, goproxy.ContentTypeHtml, http.StatusBadGateway, "no proxy")
	}

	urlNew, _, err := proxy.GenReqUrl(urlOld)

	if err != nil {
		log.Println("encryptURL", urlOld, "failed", err)
		return r, goproxy.NewResponse(r, goproxy.ContentTypeHtml, http.StatusBadGateway, "encrypt url failed")
	}

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

	//	body:=r.Body
	//	reader := kxutil.CipherStreamReader(proxy.SecertKey, encodeURL, body)
	//	r.Body = ioutil.NopCloser(reader)
	//	r.Header.Set("_kx_enc_","1")
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
