package helper

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
)

// MyUser struct as defined previously
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
	mu         sync.Mutex
	inProgress map[string]bool
}

func NewCertRequestStatus() *CertRequestStatus {
	return &CertRequestStatus{
		inProgress: make(map[string]bool),
	}
}

func (s *CertRequestStatus) RequestCert(id string, user *MyUser) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.inProgress[id] {
		fmt.Printf("Certificate request for %s is already in progress.\n", id)
		return
	}

	s.inProgress[id] = true
	go s.applyCert(id, user)
}

func (s *CertRequestStatus) applyCert(id string, user *MyUser) {
	defer func() {
		s.mu.Lock()
		delete(s.inProgress, id)
		s.mu.Unlock()
	}()

	// Generate ECDSA private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Println(err)
		return
	}

	myUser := *user
	myUser.key = privateKey

	config := lego.NewConfig(&myUser)
	config.CADirURL = "https://acme.zerossl.com/v2/DV90"
	config.Certificate.KeyType = certcrypto.EC256

	// 初始化 Cloudflare DNS
	cfConfig := cloudflare.NewDefaultConfig()
	cfConfig.AuthEmail = "mxmilu666@163.com"
	cfConfig.AuthKey = "f5fc92f901930d6aa88b6fb19d97cd6b8c2ef" // 或者使用 AuthKey 和 AuthEmail
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

	// 设置 EAB
	kid := "FIjBBtApA3Hlaj_BU_0DBw"
	hmacEncoded := "e9EwF3sjcSpl_Zoe7jfbmvAH9yEMAYdRgM1HNsywlFQHpTFckOtalYubBU_N3fUfnu3EsN60lHOcb5WZ5wfP4w"

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
		Domains: []string{fmt.Sprintf("%s.wz-clouds.com", id)},
		Bundle:  true,
	}
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		log.Fatal(err)
	}

	// Save certificate and key to files
	if err := saveCertificate(fmt.Sprintf("%s.cert", id), fmt.Sprintf("%s.key", id), certificates); err != nil {
		log.Fatal(err)
	}

	// Get certificate expiry date
	expiry, err := getCertificateExpiry(certificates.Certificate)
	if err != nil {
		log.Fatalf("Failed to get certificate expiry: %v", err)
	}
	fmt.Printf("Certificate for %s saved successfully. Expiry date: %s\n", id, expiry)
}

func saveCertificate(certPath, keyPath string, certs *certificate.Resource) error {
	if err := os.WriteFile(certPath, certs.Certificate, 0644); err != nil {
		return fmt.Errorf("failed to save certificate: %v", err)
	}
	if err := os.WriteFile(keyPath, certs.PrivateKey, 0600); err != nil {
		return fmt.Errorf("failed to save private key: %v", err)
	}
	return nil
}

func getCertificateExpiry(certData []byte) (*time.Time, error) {
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

func adf() {
	certStatus := NewCertRequestStatus()
	myUser := MyUser{
		Email: "milu@milu.moe",
	}

	// Simulate multiple requests with the same ID
	for i := 0; i < 100; i++ {
		id := "unify" // 使用相同的 ID 来模拟并发请求
		certStatus.RequestCert(id, &myUser)
		time.Sleep(1 * time.Second) // 每秒请求一次
	}

	// 等待一段时间以便申请完成
	time.Sleep(10 * time.Second)
}
