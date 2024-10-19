package source

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
)

const (
	githubClientID     = "YOUR_GITHUB_CLIENT_ID"     // 替换为您的 GitHub Client ID
	githubClientSecret = "YOUR_GITHUB_CLIENT_SECRET" // 替换为您的 GitHub Client Secret
)

// 存储 OAuth 配置
type OAuthConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	TokenURL     string
	UserInfoURL  string
}

// GitHub 的 OAuth 配置
func getGitHubOAuthConfig(c *gin.Context) OAuthConfig {
	proto := "http"
	if c.Request.Header.Get("X-Forwarded-Proto") != "" {
		proto = c.Request.Header.Get("X-Forwarded-Proto")
	} else if c.Request.TLS != nil {
		proto = "https"
	}

	baseURL := fmt.Sprintf("%s://%s", proto, c.Request.Host)
	redirectURI := fmt.Sprintf("%s/callback", baseURL)

	return OAuthConfig{
		ClientID:     githubClientID,
		ClientSecret: githubClientSecret,
		RedirectURI:  redirectURI,
		TokenURL:     "https://github.com/login/oauth/access_token",
		UserInfoURL:  "https://api.github.com/user",
	}
}

// 处理 OAuth 登录请求
func loginWithOAuth(c *gin.Context, config OAuthConfig) {
	authURL := fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s", config.ClientID, url.QueryEscape(config.RedirectURI))
	c.Redirect(http.StatusTemporaryRedirect, authURL)
}

// 处理 OAuth 回调
func handleOAuthCallback(c *gin.Context, config OAuthConfig) ([]byte, error) {
	code := c.Query("code")
	if code == "" {
		return nil, fmt.Errorf("missing code")
	}

	resp, err := http.PostForm(config.TokenURL, url.Values{
		"client_id":     {config.ClientID},
		"client_secret": {config.ClientSecret},
		"code":          {code},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to exchange token: %w", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	token := string(body)
	userResp, err := http.Get(config.UserInfoURL + "?" + token)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer userResp.Body.Close()

	userData, err := ioutil.ReadAll(userResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read user response: %w", err)
	}

	return userData, nil
}
