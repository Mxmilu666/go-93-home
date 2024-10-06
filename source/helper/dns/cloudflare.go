package dns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const cloudflareAPIURL = "https://api.cloudflare.com/client/v4/"

type ZoneResponse struct {
	Result []struct {
		ID string `json:"id"`
	} `json:"result"`
}

type DNSRecord struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

func GetZoneID(email, apiToken, domain string) (string, error) {
	secondLevelDomain := getSecondLevelDomain(domain)
	url := fmt.Sprintf("%s/zones?name=%s", cloudflareAPIURL, secondLevelDomain)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("X-Auth-Key", apiToken)
	req.Header.Set("X-Auth-Email", email)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get zone ID, status: %s", resp.Status)
	}

	var zoneResponse ZoneResponse
	if err := json.NewDecoder(resp.Body).Decode(&zoneResponse); err != nil {
		return "", err
	}

	if len(zoneResponse.Result) == 0 {
		return "", fmt.Errorf("no zone found for domain %s", domain)
	}

	return zoneResponse.Result[0].ID, nil
}

func AddDNSRecord(email, apiToken, zoneID string, record DNSRecord) error {
	url := fmt.Sprintf("%s/zones/%s/dns_records", cloudflareAPIURL, zoneID)

	recordJSON, err := json.Marshal(record)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(recordJSON))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Auth-Key", apiToken)
	req.Header.Set("X-Auth-Email", email)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	bodyString := string(bodyBytes)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to add DNS record, status: %s %s", resp.Status, bodyString)
	}

	return nil
}

func getSecondLevelDomain(domain string) string {
	// 将域名按 '.' 分割
	parts := strings.Split(domain, ".")

	// 检查域名部分的数量
	if len(parts) < 2 {
		return ""
	}

	// 返回倒数第二个部分（即二级域名）
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}
