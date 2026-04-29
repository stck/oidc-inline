package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
	"gopkg.in/yaml.v3"
)


type Config struct {
	BaseURL    string `yaml:"base_url"`
	Username   string `yaml:"username"`
	Password   string `yaml:"password"`
	TOTPSecret string `yaml:"totp_secret"`
	Socks5     string `yaml:"socks5"`
}

type Challenge struct {
	Component      string                 `json:"component"`
	Type           string                 `json:"type"`
	FlowInfo       map[string]interface{} `json:"flow_info"`
	ResponseErrors map[string]interface{} `json:"response_errors,omitempty"`
	To             string                 `json:"to,omitempty"`
	URL            string                 `json:"url,omitempty"`
	Token          string                 `json:"token,omitempty"`
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.BaseURL == "" || cfg.Username == "" || cfg.Password == "" || cfg.TOTPSecret == "" {
		return nil, fmt.Errorf("config missing required fields: base_url, username, password, totp_secret")
	}
	return &cfg, nil
}

func findConfigPath(provided string) (string, error) {
	if provided != "" {
		return provided, nil
	}

	pwdConfig := "config.yaml"
	if _, err := os.Stat(pwdConfig); err == nil {
		return pwdConfig, nil
	}

	exe, err := os.Executable()
	if err == nil {
		binDir := filepath.Dir(exe)
		nextToBin := filepath.Join(binDir, "config.yaml")
		if _, err := os.Stat(nextToBin); err == nil {
			return nextToBin, nil
		}
	}

	etcConfig := "/etc/oidc-inline/config.yaml"
	if _, err := os.Stat(etcConfig); err == nil {
		return etcConfig, nil
	}

	return "", fmt.Errorf("no config.yaml found in current directory, next to binary, or /etc/oidc-inline; provide --config flag")
}

func generateTOTP(secret string) (string, error) {
	code, err := totp.GenerateCode(secret, time.Now().UTC())
	if err != nil {
		return "", fmt.Errorf("generate totp: %w", err)
	}
	return code, nil
}

func main() {
	configFlag := flag.String("config", "", "Path to config file (defaults to config.yaml in PWD or next to binary)")
	flag.Parse()

	if len(flag.Args()) == 0 {
		log.Fatal("Browser authentication URL is required as argument")
	}
	browserURL := flag.Args()[0]

	configPath, err := findConfigPath(*configFlag)
	if err != nil {
		log.Fatal(err)
	}

	cfg, err := loadConfig(configPath)
	if err != nil {
		log.Fatalf("Config error: %v", err)
	}

	log.Printf("Starting OIDC flow executor (config: %s)", configPath)

	if err := runFlow(cfg, browserURL); err != nil {
		log.Fatalf("Flow execution failed: %v", err)
	}
}

// discoverFlowParams follows the redirect chain from the initial browser URL
// until it reaches authentik's flow executor page (/if/flow/:slug/?query=...).
// Returns the flow slug and the query string that should be passed to the API.
func discoverFlowParams(client *http.Client, browserURL string, baseURL string) (flowSlug string, queryStr string, err error) {
	noRedirectClient := &http.Client{
		Jar:       client.Jar,
		Timeout:   client.Timeout,
		Transport: client.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	currentURL := browserURL
	for i := 0; i < 20; i++ {
		log.Printf("Following redirect chain: %s", currentURL)

		resp, err := noRedirectClient.Get(currentURL)
		if err != nil {
			return "", "", fmt.Errorf("follow redirect chain at %s: %w", currentURL, err)
		}
		resp.Body.Close()

		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			location := resp.Header.Get("Location")
			if location == "" {
				return "", "", fmt.Errorf("redirect with no Location header at %s", currentURL)
			}

			nextURL, err := resolveRedirect(currentURL, location)
			if err != nil {
				return "", "", fmt.Errorf("resolve redirect: %w", err)
			}

			// Check if we've landed on the flow executor page
			slug, query, found := parseFlowExecutorURL(nextURL)
			if found {
				log.Printf("Discovered flow: slug=%s", slug)
				return slug, query, nil
			}

			currentURL = nextURL
			continue
		}

		// Non-redirect response - check if current URL is the flow page
		slug, query, found := parseFlowExecutorURL(currentURL)
		if found {
			log.Printf("Discovered flow: slug=%s", slug)
			return slug, query, nil
		}

		return "", "", fmt.Errorf("redirect chain ended at non-flow URL: %s (status %d)", currentURL, resp.StatusCode)
	}

	return "", "", fmt.Errorf("exceeded max redirects while discovering flow params")
}

// parseFlowExecutorURL checks if a URL matches /if/flow/:slug/ pattern
// and extracts the slug and the full query string (which becomes the `query`
// parameter for the flow executor API).
func parseFlowExecutorURL(rawURL string) (slug string, query string, found bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", false
	}

	path := u.Path
	if strings.HasPrefix(path, "/if/flow/") {
		parts := strings.Split(strings.TrimPrefix(path, "/if/flow/"), "/")
		if len(parts) > 0 && parts[0] != "" {
			slug = parts[0]
			// The full query string of the /if/flow/ URL becomes the `query`
			// param for the API. e.g. /if/flow/slug/?next=/app/o/authorize/...
			// means query="next=/app/o/authorize/..."
			query = u.RawQuery
			return slug, query, true
		}
	}

	return "", "", false
}

func resolveRedirect(currentURL string, location string) (string, error) {
	base, err := url.Parse(currentURL)
	if err != nil {
		return "", err
	}
	ref, err := url.Parse(location)
	if err != nil {
		return "", err
	}
	return base.ResolveReference(ref).String(), nil
}

func runFlow(cfg *Config, browserURL string) error {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return fmt.Errorf("create cookie jar: %w", err)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
	}

	if cfg.Socks5 != "" {
		proxyURL, err := url.Parse(cfg.Socks5)
		if err != nil {
			return fmt.Errorf("parse socks5 url: %w", err)
		}
		transport.Proxy = func(req *http.Request) (*url.URL, error) {
			if isLocalhost(req.URL.Host) {
				return nil, nil
			}
			return proxyURL, nil
		}
		log.Printf("Using SOCKS5 proxy: %s", cfg.Socks5)
	}

	client := &http.Client{
		Jar:       jar,
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	baseURL := strings.TrimRight(cfg.BaseURL, "/")

	// Step 1: Follow the redirect chain from the browser URL to discover
	// which flow authentik wants us to execute and what query params to use.
	flowSlug, queryStr, err := discoverFlowParams(client, browserURL, baseURL)
	if err != nil {
		return fmt.Errorf("discover flow params: %w", err)
	}

	// Step 2: Execute flows until we get the final redirect with the authorization code.
	// authentik may chain multiple flows (auth -> authorization) via redirects.
	for flowIteration := 0; flowIteration < 5; flowIteration++ {
		log.Printf("Executing flow: %s", flowSlug)
		encodedQuery := url.QueryEscape(queryStr)
		executorURL := fmt.Sprintf("%s/api/v3/flows/executor/%s/?query=%s", baseURL, flowSlug, encodedQuery)

		challenge, err := getChallenge(client, executorURL)
		if err != nil {
			return fmt.Errorf("get initial challenge for flow %s: %w", flowSlug, err)
		}

		log.Printf("Initial challenge: %s", challenge.Component)

		// Execute stages within this flow
		redirectTo, err := executeFlowStages(client, cfg, executorURL, challenge)
		if err != nil {
			return err
		}

		if redirectTo == "" {
			return fmt.Errorf("flow %s completed without a redirect", flowSlug)
		}

		log.Printf("Flow %s completed, redirect to: %s", flowSlug, redirectTo)

		// Make the redirect URL absolute
		if strings.HasPrefix(redirectTo, "/") {
			redirectTo = baseURL + redirectTo
		}

		// Check if this redirect contains the authorization code (final step)
		if u, err := url.Parse(redirectTo); err == nil && u.Query().Get("code") != "" {
			return deliverCode(client, redirectTo)
		}

		// Follow this redirect - it may lead to another flow (e.g., authorization/consent)
		// or back to the authorize endpoint which will issue the code.
		nextSlug, nextQuery, isFlow := parseFlowExecutorURL(redirectTo)
		if isFlow {
			flowSlug = nextSlug
			queryStr = nextQuery
			continue
		}

		// Not a flow URL - follow the redirect chain again to find the next flow or final code
		return followRedirectsToCompletion(client, redirectTo, cfg, baseURL)
	}

	return fmt.Errorf("exceeded max flow iterations")
}

// executeFlowStages runs through all stages of a single flow and returns
// the redirect URL from the final xak-flow-redirect challenge.
func executeFlowStages(client *http.Client, cfg *Config, executorURL string, challenge *Challenge) (string, error) {
	for i := 0; i < 15; i++ {
		switch challenge.Component {
		case "ak-stage-identification":
			log.Println("Stage: identification")
			resp := map[string]interface{}{
				"component": "ak-stage-identification",
				"uid_field": cfg.Username,
			}
			next, err := postChallenge(client, executorURL, resp)
			if err != nil {
				return "", fmt.Errorf("identification stage: %w", err)
			}
			challenge = next

		case "ak-stage-password":
			log.Println("Stage: password")
			resp := map[string]interface{}{
				"component": "ak-stage-password",
				"password":  cfg.Password,
			}
			next, err := postChallenge(client, executorURL, resp)
			if err != nil {
				return "", fmt.Errorf("password stage: %w", err)
			}
			challenge = next

		case "ak-stage-authenticator-validate":
			log.Println("Stage: TOTP validation")
			code, err := generateTOTP(cfg.TOTPSecret)
			if err != nil {
				return "", err
			}
			resp := map[string]interface{}{
				"component": "ak-stage-authenticator-validate",
				"code":      code,
			}
			next, err := postChallenge(client, executorURL, resp)
			if err != nil {
				return "", fmt.Errorf("authenticator stage: %w", err)
			}
			challenge = next

		case "ak-stage-consent":
			log.Println("Stage: consent")
			token := challenge.Token
			if token == "" {
				return "", fmt.Errorf("consent stage returned no token")
			}
			resp := map[string]interface{}{
				"component": "ak-stage-consent",
				"token":     token,
			}
			next, err := postChallenge(client, executorURL, resp)
			if err != nil {
				return "", fmt.Errorf("consent stage: %w", err)
			}
			challenge = next

		case "ak-stage-user-login":
			log.Println("Stage: user-login (auto-continue)")
			resp := map[string]interface{}{
				"component": "ak-stage-user-login",
			}
			next, err := postChallenge(client, executorURL, resp)
			if err != nil {
				return "", fmt.Errorf("user-login stage: %w", err)
			}
			challenge = next

		case "xak-flow-redirect":
			redirectURL := challenge.To
			if redirectURL == "" {
				redirectURL = challenge.URL
			}
			return redirectURL, nil

		case "ak-stage-access-denied":
			return "", fmt.Errorf("flow denied: access denied stage reached")

		default:
			if challenge.Type == "redirect" {
				redirectURL := challenge.To
				if redirectURL == "" {
					redirectURL = challenge.URL
				}
				if redirectURL != "" {
					return redirectURL, nil
				}
			}
			return "", fmt.Errorf("unsupported stage component: %s", challenge.Component)
		}

		log.Printf("Next challenge: %s", challenge.Component)
	}

	return "", fmt.Errorf("exceeded max stages in flow")
}

// followRedirectsToCompletion follows HTTP redirects from the given URL until
// it either finds another flow to execute, gets the final code redirect,
// or reaches a non-redirect response.
func followRedirectsToCompletion(client *http.Client, startURL string, cfg *Config, baseURL string) error {
	noRedirectClient := &http.Client{
		Jar:       client.Jar,
		Timeout:   client.Timeout,
		Transport: client.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	currentURL := startURL
	for i := 0; i < 20; i++ {
		log.Printf("Following post-flow redirect: %s", currentURL)

		req, err := http.NewRequest("GET", currentURL, nil)
		if err != nil {
			return fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("User-Agent", "oidc-inline/1.0")

		resp, err := noRedirectClient.Do(req)
		if err != nil {
			return fmt.Errorf("follow redirect at %s: %w", currentURL, err)
		}
		resp.Body.Close()

		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			location := resp.Header.Get("Location")
			if location == "" {
				return fmt.Errorf("redirect with no Location at %s", currentURL)
			}

			nextURL, err := resolveRedirect(currentURL, location)
			if err != nil {
				return fmt.Errorf("resolve redirect: %w", err)
			}

			// Check for authorization code in the redirect
			if u, err := url.Parse(nextURL); err == nil && u.Query().Get("code") != "" {
				return deliverCode(client, nextURL)
			}

			// Check if we need to execute another flow
			slug, query, isFlow := parseFlowExecutorURL(nextURL)
			if isFlow {
				log.Printf("Discovered next flow from redirect: %s", slug)
				encodedQuery := url.QueryEscape(query)
				executorURL := fmt.Sprintf("%s/api/v3/flows/executor/%s/?query=%s", baseURL, slug, encodedQuery)

				challenge, err := getChallenge(client, executorURL)
				if err != nil {
					return fmt.Errorf("get challenge for flow %s: %w", slug, err)
				}

				redirectTo, err := executeFlowStages(client, cfg, executorURL, challenge)
				if err != nil {
					return err
				}

				if redirectTo == "" {
					return fmt.Errorf("flow %s completed without redirect", slug)
				}

				if strings.HasPrefix(redirectTo, "/") {
					redirectTo = baseURL + redirectTo
				}

				if u, err := url.Parse(redirectTo); err == nil && u.Query().Get("code") != "" {
					return deliverCode(client, redirectTo)
				}

				currentURL = redirectTo
				continue
			}

			currentURL = nextURL
			continue
		}

		return fmt.Errorf("redirect chain ended without authorization code at %s (status %d)", currentURL, resp.StatusCode)
	}

	return fmt.Errorf("exceeded max redirects following post-flow chain")
}

func deliverCode(client *http.Client, redirectURL string) error {
	log.Printf("Following callback chain from: %s", redirectURL)

	noRedirectClient := &http.Client{
		Jar:       client.Jar,
		Timeout:   client.Timeout,
		Transport: client.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	currentURL := redirectURL
	for i := 0; i < 10; i++ {
		resp, err := noRedirectClient.Get(currentURL)
		if err != nil {
			if strings.Contains(err.Error(), "connection refused") {
				u, _ := url.Parse(currentURL)
				if u != nil && isLocalhost(u.Host) {
					log.Printf("Local callback not reachable, but code was delivered to: %s", currentURL)
					fmt.Printf("code=%s\nstate=%s\n", u.Query().Get("code"), u.Query().Get("state"))
					return nil
				}
			}
			return fmt.Errorf("callback request to %s: %w", currentURL, err)
		}
		resp.Body.Close()

		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			location := resp.Header.Get("Location")
			if location == "" {
				return fmt.Errorf("redirect with no Location at %s", currentURL)
			}
			nextURL, err := resolveRedirect(currentURL, location)
			if err != nil {
				return fmt.Errorf("resolve callback redirect: %w", err)
			}
			log.Printf("Callback redirect: %s", nextURL)
			currentURL = nextURL
			continue
		}

		u, _ := url.Parse(currentURL)
		if u != nil && u.Query().Get("code") != "" {
			log.Printf("Code delivered to callback: %s (status %d)", currentURL, resp.StatusCode)
			fmt.Println("Success: Authorization code delivered to redirect_uri")
			return nil
		}

		log.Printf("Callback chain ended at %s (status %d)", currentURL, resp.StatusCode)
		fmt.Println("Success: Callback chain completed")
		return nil
	}

	return fmt.Errorf("exceeded max redirects in callback chain")
}

func isLocalhost(host string) bool {
	h := strings.Split(host, ":")[0]
	return h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "[::1]"
}

func getChallenge(client *http.Client, urlStr string) (*Challenge, error) {
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "oidc-inline/1.0")

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
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, string(body))
	}

	var challenge Challenge
	if err := json.Unmarshal(body, &challenge); err != nil {
		return nil, fmt.Errorf("unmarshal challenge: %w (body: %s)", err, string(body))
	}

	return &challenge, nil
}

func postChallenge(client *http.Client, urlStr string, data interface{}) (*Challenge, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", urlStr, bytes.NewReader(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "oidc-inline/1.0")

	csrfToken := getCSRFToken(client, urlStr)
	if csrfToken != "" {
		req.Header.Set("X-authentik-CSRF", csrfToken)
	}

	// Referer must be set to the base origin for CSRF validation
	if u, err := url.Parse(urlStr); err == nil {
		req.Header.Set("Referer", fmt.Sprintf("%s://%s/", u.Scheme, u.Host))
	}

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
		return nil, fmt.Errorf("post failed %d: %s", resp.StatusCode, string(body))
	}

	var challenge Challenge
	if err := json.Unmarshal(body, &challenge); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w (body: %s)", err, string(body))
	}

	if challenge.ResponseErrors != nil && len(challenge.ResponseErrors) > 0 {
		return nil, fmt.Errorf("flow returned errors: %v", challenge.ResponseErrors)
	}

	return &challenge, nil
}

func getCSRFToken(client *http.Client, urlStr string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == "authentik_csrf" {
			return c.Value
		}
	}
	return ""
}
