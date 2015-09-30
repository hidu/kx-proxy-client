package client

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	kxutil "github.com/hidu/kx-proxy/util"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"strconv"
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
	Url                 string `json:"url"`
	Weight              int    `json:"weight"`
	SecertKey           string `json:"secertKey"`
	timeOffsetSec       int64  //和服务器的时间偏移量
	timeOffsetCheckTime *time.Time
}

func (conf *ClientConf) GetOneProxy() *ProxyItem {
	if conf.Total < 1 {
		return nil
	}
	n := rand.Int() % conf.Total
	index := conf.Proxy_All[n]
	item := conf.Proxies[index]
	return item
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

func (item *ProxyItem) getTimeOffset() error {
	if item.timeOffsetCheckTime != nil {
		return nil
	}
	now := time.Now()

	urlStr := strings.TrimRight(item.Url, "/") + "/hello"
	resp, err := http.Get(urlStr)
	if err != nil {
		log.Println("get timeout osset failed [", urlStr, "],", err)
		return nil
	}
	defer resp.Body.Close()
	data, _ := ioutil.ReadAll(resp.Body)
	d, err := kxutil.DecryptURL(string(data))
	if err != nil {
		log.Println("decode data failed,data [", string(data), "]", err)
		return nil
	}
	unixTime, err := strconv.ParseInt(d, 10, 64)
	if err != nil {
		log.Println("parse data to int failed:", d, "err:", err)
		return nil
	}
	item.timeOffsetSec = now.Unix() - unixTime
	item.timeOffsetCheckTime = &now
	log.Println("gettimeoffsetsec_suc:",item.timeOffsetSec)
	return nil
}

// 获取远程服务的时间
func (item *ProxyItem) getServerTime() int64 {
	item.getTimeOffset()
	return time.Now().Unix() - item.timeOffsetSec
}

// GenReqUrl 生成一个新的url地址
func (item *ProxyItem) GenReqUrl(urlReq string) (string, error) {
	str := fmt.Sprintf("%d|%s", item.getServerTime(), urlReq)
	enURL, err := kxutil.EncryptURL(str)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/p/%s", strings.TrimRight(item.Url, "/"), enURL), nil
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
