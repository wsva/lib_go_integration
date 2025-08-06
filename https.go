package lib

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"os"
	"time"
)

func InitHttpsClient(caCrtFile string) (*http.Client, error) {
	caCert, err := os.ReadFile(caCrtFile)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		return nil, errors.New("add ca to cert pool error")
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		},
		Timeout: 10 * time.Second,
	}, nil
}
