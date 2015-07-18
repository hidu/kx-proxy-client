

kx-proxy-client


install

go get -u  github.com/hidu/kx-proxy-client



ssl keygen


openssl genrsa -out key.pem 2048

openssl req -new -x509 -key key.pem -out cert.pem -days 3650