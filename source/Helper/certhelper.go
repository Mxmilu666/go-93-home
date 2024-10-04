package helper

import (
	"anythingathome-golang/source/logger"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

type CloudflareConfig struct {
	AuthEmail string
	AuthKey   string
	Domain    string
}

type zeroSSLRes struct {
	Success    bool   `json:"success"`
	EabKid     string `json:"eab_kid"`
	EabHmacKey string `json:"eab_hmac_key"`
}

type MyUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *MyUser) GetEmail() string {
	return u.Email
}

func (u *MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

type CertRequestStatus struct {
	mu               sync.Mutex
	inProgress       map[string]bool
	cloudflareConfig *CloudflareConfig
}

// 初始化 CloudflareConfig
func NewCloudflareConfig(authEmail, authKey, domain string) *CloudflareConfig {
	return &CloudflareConfig{
		AuthEmail: authEmail,
		AuthKey:   authKey,
		Domain:    domain,
	}
}

func NewCertRequestStatus(cfConfig *CloudflareConfig, database *mongo.Client) *CertRequestStatus {
	return &CertRequestStatus{
		inProgress:       make(map[string]bool),
		cloudflareConfig: cfConfig,
	}
}

// Lock 一下防止申请多了
func (s *CertRequestStatus) RequestCert(id string, user *MyUser) <-chan *certificate.Resource {
	resultChan := make(chan *certificate.Resource)

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.inProgress[id] {
		logger.Error("Certificate request for %s is already in progress.\n", id)
		close(resultChan) // 关闭通道
		return resultChan
	}

	s.inProgress[id] = true
	go func() {
		defer func() {
			s.mu.Lock()
			delete(s.inProgress, id)
			s.mu.Unlock()
		}()

		certificates, err := s.applyCert(id, user)
		if err != nil {
			log.Printf("Failed to apply cert for %s: %v", id, err)
			resultChan <- nil // 发送 nil 或者处理错误
		} else {
			resultChan <- certificates // 发送证书
		}
		close(resultChan) // 关闭通道
	}()

	return resultChan // 返回通道
}

func (s *CertRequestStatus) applyCert(id string, user *MyUser) (*certificate.Resource, error) {
	defer func() {
		s.mu.Lock()
		delete(s.inProgress, id)
		s.mu.Unlock()
	}()

	// 创建 ECDSA private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	myUser := *user
	myUser.key = privateKey

	config := lego.NewConfig(&myUser)
	config.CADirURL = "https://acme.zerossl.com/v2/DV90"
	config.Certificate.KeyType = certcrypto.EC256

	// 初始化 Cloudflare DNS
	cfConfig := cloudflare.NewDefaultConfig()
	cfConfig.AuthEmail = s.cloudflareConfig.AuthEmail
	cfConfig.AuthKey = s.cloudflareConfig.AuthKey
	dnsProvider, err := cloudflare.NewDNSProviderConfig(cfConfig)
	if err != nil {
		log.Fatalf("Unable to create DNS provider: %v", err)
	}

	client, err := lego.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	// 设置 DNS-01 模式
	err = client.Challenge.SetDNS01Provider(dnsProvider)
	if err != nil {
		log.Fatal(err)
	}

	var kid string
	var hmacEncoded string

	// 获取 EAB
	var res *zeroSSLRes
	res, err = getZeroSSLEabCredentials(s.cloudflareConfig.AuthEmail)
	if err != nil {
		logger.Error("%v", err)
		return nil, err
	}
	if res.Success {
		logger.Info("%v", res)
		kid = res.EabKid
		hmacEncoded = res.EabHmacKey
	} else {
		logger.Error("get zero ssl eab credentials failed")
		return nil, err
	}

	// 注册用户
	reg, err := client.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
		TermsOfServiceAgreed: true,
		Kid:                  kid,
		HmacEncoded:          hmacEncoded,
	})
	if err != nil {
		log.Fatal(err)
	}
	myUser.Registration = reg

	request := certificate.ObtainRequest{
		Domains: []string{fmt.Sprintf("%s.%s", id, s.cloudflareConfig.Domain)},
		Bundle:  true,
	}
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		log.Fatal(err)
	}

	return certificates, nil
}

func GetCertificateExpiry(certData []byte) (*time.Time, error) {
	block, _ := pem.Decode(certData)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM block containing the certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return &cert.NotAfter, nil
}

// 代码来自 https://github.com/1Panel-dev/1Panel/blob/e03b728240888ca0cb3882b9f7e5bd8e12dd2d27/backend/utils/ssl/acme.go#L169
func getZeroSSLEabCredentials(email string) (*zeroSSLRes, error) {
	baseURL := "https://api.zerossl.com/acme/eab-credentials-email"
	params := url.Values{}
	params.Add("email", email)
	requestURL := fmt.Sprintf("%s?%s", baseURL, params.Encode())

	req, err := http.NewRequest("POST", requestURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned non-200 status: %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	var result zeroSSLRes
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}
