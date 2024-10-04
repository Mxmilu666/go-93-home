package dns

import (
	"bytes"
	"encoding/json"
	"fmt"
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

	req.Header.Set("Authorization", "Bearer "+apiToken)
	req.Header.Set("X-Auth-Key", apiToken)
	req.Header.Set("X-Auth-Email", email)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to add DNS record, status: %s", resp.Status)
	}

	return nil
}

func getSecondLevelDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) >= 3 {
		// 处理三级或更高级的域名
		return strings.Join(parts[len(parts)-3:], ".")
	} else if len(parts) == 2 {
		// 已经是二级域名
		return domain
	} else {
		// 无效的域名
		return ""
	}
}
