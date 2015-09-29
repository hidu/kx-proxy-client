package client

import (
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"log"
	"math/rand"
	"strings"
	"time"
)

type ClientConf struct {
	Proxies         []*ProxyItem `json:"proxy"`
	Proxy_All       []int
	Total           int
	ParentProxy     string `json:"parent"`
	SSlOn           bool   `json:"ssl"`
	SecertKeyMaps   map[string]string
	SslCert         tls.Certificate
	Ssl_client_cert string `json:"ssl_client_cert"`
	Ssl_server_key  string `json:"ssl_server_key"`
	HiddenIp        bool   `json:"hidden_ip"`
}

type ProxyItem struct {
	Url       string `json:"url"`
	Weight    int    `json:"weight"`
	SecertKey string `json:"secertKey"`
}

func (conf *ClientConf) GetOneProxy() *ProxyItem {
	if conf.Total < 1 {
		return nil
	}
	n := rand.Int() % conf.Total
	index := conf.Proxy_All[n]
	return conf.Proxies[index]
}

func (conf *ClientConf) IsProxyHost(urlClient string) bool {
	urlClient = strings.ToLower(urlClient)
	for _, host := range conf.Proxies {
		if strings.HasPrefix(urlClient, host.Url) {
			return true
		}
	}
	return false
}

func LoadConf(confPath string) *ClientConf {
	data, err := ioutil.ReadFile(confPath)
	if err != nil {
		log.Fatalln("load json conf failed,err:", err)
	}
	var conf *ClientConf
	err = json.Unmarshal(data, &conf)
	if err != nil {
		log.Fatalln("parse json conf failed,err:", err)
	}
	if len(conf.Proxies) < 1 {
		log.Fatalln("no hosts")
	}
	conf.SecertKeyMaps = make(map[string]string)
	for index, item := range conf.Proxies {
		if item.Weight < 1 {
			log.Println("skip ", item.Url)
			continue
		}

		proxyUrl := strings.TrimRight(item.Url, "/")
		conf.SecertKeyMaps[proxyUrl] = item.SecertKey
		if item.Weight > 1000 {
			log.Fatalln("weight must <1000,current is :", item.Weight)
		}
		for i := 0; i < item.Weight; i++ {
			conf.Proxy_All = append(conf.Proxy_All, index)
		}
	}
	conf.Total = len(conf.Proxy_All)
	rand.Seed(time.Now().Unix())

	if conf.SSlOn {
		log.Println("sslon", conf.Ssl_client_cert, conf.Ssl_server_key)
		cert, err := getSslCert(conf.Ssl_client_cert, conf.Ssl_server_key)
		if err != nil {
			log.Fatalln("ssl ca config error:", err)
		} else {
			conf.SslCert = cert
		}
	}

	log.Println("load conf success")
	return conf
}
