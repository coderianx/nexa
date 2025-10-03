package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// ANSI colors
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
	colorCustom = "\033[38;5;87m"
)

var NoColor = false

func colorize(col, s string) string {
	if NoColor {
		return s
	}
	return col + s + colorReset
}

func printBanner() {
	banner := `                      
  _   _                
 | \ | | _____  ____ _ 
 |  \| |/ _ \ \/ / _  |
 | |\  |  __/>  < (_| |
 |_| \_|\___/_/\_\__,_|
                       

Nexa Scanner
	`
	fmt.Println(banner)
}

type Finding struct {
	Type    string
	Param   string
	Payload string
	URL     string
	When    time.Time
	Latency time.Duration
	Detail  string
}

func main() {
	var scan_type int
	printBanner()
	fmt.Println(colorCustom, "       NEXA", colorReset)
	fmt.Println("=====================")
	fmt.Println("[1] XSS Scan")
	fmt.Println("[2] SQLi Scan")
	fmt.Println("[3] Whois Scan")
	fmt.Println("[4] Port Scan")
	fmt.Println("[0] Exit")
	fmt.Println("=====================")
	fmt.Print("\nEnter Scan Type: ")

	fmt.Scanln(&scan_type)

	switch scan_type {
	case 1:
		Xss()
	case 2:
		Sqli()
	case 3:
		Whois()
	case 4:
		PortScan()
	case 0:
		fmt.Println("Good Bye Hacker...")
	default:
		fmt.Println("Unknown scan type.")
	}
}

// /////////////////////////////////////////////////////////////////////////////
// XSS (unchanged behavior, slightly adapted)
// /////////////////////////////////////////////////////////////////////////////
func Xss() {
	startAll := time.Now()

	var target string
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter Target url: ")
	rawTarget, _ := reader.ReadString('\n')
	target = strings.TrimSpace(rawTarget)
	if target == "" {
		fmt.Println(colorize(colorRed, "No target provided."))
		return
	}

	fmt.Print("Enter payload JSON filename (default: xss.json): ")
	rawFile, _ := reader.ReadString('\n')
	filename := strings.TrimSpace(rawFile)
	if filename == "" {
		filename = "xss.json"
	}

	payloads, err := loadPayloads(filename)
	if err != nil {
		fmt.Printf("%s %v\n", colorize(colorRed, "Failed to load payloads:"), err)
		return
	}
	if len(payloads) == 0 {
		fmt.Println(colorize(colorYellow, "No payloads found in "+filename))
		return
	}

	parsed, err := url.Parse(target)
	if err != nil {
		fmt.Printf("%s %v\n", colorize(colorRed, "Invalid URL:"), err)
		return
	}

	client := &http.Client{Timeout: 12 * time.Second}
	fmt.Printf("\nStarting XSS scan on %s with %d payload(s) from %s\n\n",
		colorize(colorBold, target), len(payloads), filename)

	totalTests := 0
	var findings []Finding

	doRequest := func(u string, payload string) (bool, time.Duration, error) {
		start := time.Now()
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			return false, 0, err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "+
			"AppleWebKit/537.36 (KHTML, like Gecko) "+
			"Chrome/117.0.0.0 Safari/537.36")

		resp, err := client.Do(req)
		if err != nil {
			return false, time.Since(start), err
		}
		defer resp.Body.Close()
		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		if err != nil {
			return false, time.Since(start), err
		}
		body := string(bodyBytes)
		lat := time.Since(start)
		if strings.Contains(body, payload) {
			return true, lat, nil
		}
		escaped := htmlEscapeSimple(payload)
		if escaped != payload && strings.Contains(body, escaped) {
			return true, lat, nil
		}
		return false, lat, nil
	}

	if parsed.RawQuery != "" {
		values := parsed.Query()
		for param := range values {
			totalTests += len(payloads)
			_ = param
		}
		tested := 0
		for param := range values {
			original := values.Get(param)
			for _, payload := range payloads {
				values.Set(param, payload)
				parsed.RawQuery = values.Encode()
				testURL := parsed.String()
				found, lat, err := doRequest(testURL, payload)
				tested++
				if err != nil {
					fmt.Printf("%s %s | %d/%d %s\n", time.Now().Format("15:04:05"),
						colorize(colorCyan, "[progress]"),
						tested, totalTests,
						colorize(colorYellow, fmt.Sprintf("[!] error requesting %s : %v", testURL, err)),
					)
					values.Set(param, original)
					continue
				}
				if found {
					msg := colorize(colorBold, colorize(colorRed, "[VULN]")) + " param=" + param + " payload=" + fmt.Sprintf("%q", payload)
					fmt.Printf("%s %s | %d/%d %s (%dms)\n", time.Now().Format("15:04:05"),
						colorize(colorCyan, "[progress]"),
						tested, totalTests, msg, lat.Milliseconds())
					findings = append(findings, Finding{Type: "XSS", Param: param, Payload: payload, URL: testURL, When: time.Now(), Latency: lat})
					values.Set(param, original)
					break
				} else {
					fmt.Printf("%s %s | %d/%d %s (%dms)\n", time.Now().Format("15:04:05"),
						colorize(colorCyan, "[progress]"),
						tested, totalTests, fmt.Sprintf("ok payload=%q", payload), lat.Milliseconds())
				}
				values.Set(param, original)
			}
		}
	} else {
		totalTests = len(payloads)
		tested := 0
		for _, payload := range payloads {
			q := parsed.Query()
			q.Set("q", payload)
			parsed.RawQuery = q.Encode()
			testURL := parsed.String()
			found, lat, err := doRequest(testURL, payload)
			tested++
			if err != nil {
				fmt.Printf("%s %s | %d/%d %s\n", time.Now().Format("15:04:05"),
					colorize(colorCyan, "[progress]"),
					tested, totalTests,
					colorize(colorYellow, fmt.Sprintf("[!] error requesting %s : %v", testURL, err)),
				)
				continue
			}
			if found {
				msg := colorize(colorBold, colorize(colorRed, "[VULN]")) + " param=q payload=" + fmt.Sprintf("%q", payload)
				fmt.Printf("%s %s | %d/%d %s (%dms)\n", time.Now().Format("15:04:05"),
					colorize(colorCyan, "[progress]"),
					tested, totalTests, msg, lat.Milliseconds())
				findings = append(findings, Finding{Type: "XSS", Param: "q", Payload: payload, URL: testURL, When: time.Now(), Latency: lat})
				break
			} else {
				fmt.Printf("%s %s | %d/%d %s (%dms)\n", time.Now().Format("15:04:05"),
					colorize(colorCyan, "[progress]"),
					tested, totalTests, fmt.Sprintf("ok payload=%q", payload), lat.Milliseconds())
			}
		}
	}

	fmt.Println()
	fmt.Println(colorize(colorBold, "XSS Scan summary"))
	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("Target: %s\n", colorize(colorBlue, target))
	fmt.Printf("Payloads tested: %d\n", totalTests)
	fmt.Printf("Findings: %d\n", len(findings))
	fmt.Println(strings.Repeat("-", 60))
	for i, f := range findings {
		fmt.Printf("%d) [%s] param=%s payload=%s url=%s time=%dms\n", i+1, f.Type, f.Param, f.Payload, f.URL, f.Latency.Milliseconds())
	}
	fmt.Println(colorize(colorCyan, "XSS scan finished.\nOverall elapsed:"), time.Since(startAll).String())
}

// /////////////////////////////////////////////////////////////////////////////
// SQLi scanner
// /////////////////////////////////////////////////////////////////////////////
func Sqli() {
	startAll := time.Now()

	var target string
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter Target url: ")
	rawTarget, _ := reader.ReadString('\n')
	target = strings.TrimSpace(rawTarget)
	if target == "" {
		fmt.Println(colorize(colorRed, "No target provided."))
		return
	}

	fmt.Print("Enter SQLi payload JSON filename (default: sqli.json): ")
	rawFile, _ := reader.ReadString('\n')
	filename := strings.TrimSpace(rawFile)
	if filename == "" {
		filename = "sqli.json"
	}

	payloads, err := loadPayloads(filename)
	if err != nil {
		fmt.Printf("%s %v\n", colorize(colorRed, "Failed to load payloads:"), err)
		return
	}
	if len(payloads) == 0 {
		fmt.Println(colorize(colorYellow, "No payloads found in "+filename))
		return
	}

	parsed, err := url.Parse(target)
	if err != nil {
		fmt.Printf("%s %v\n", colorize(colorRed, "Invalid URL:"), err)
		return
	}

	client := &http.Client{Timeout: 12 * time.Second}
	fmt.Printf("\nStarting SQLi scan on %s with %d payload(s) from %s\n\n",
		colorize(colorBold, target), len(payloads), filename)

	sqlErrorSignatures := []string{
		"you have an error in your sql syntax",
		"warning: mysql",
		"mysql_fetch",
		"supplied argument is not a valid mysql",
		"unclosed quotation mark after the character string",
		"quoted string not properly terminated",
		"pg_query():",
		"psql: error",
		"sqlite error",
		"sqlite3.OperationalError",
		"syntax error at or near",
		"sql syntax error",
		"odbc_sql_state",
		"sqlstate",
		"sql syntax",
	}

	doGet := func(u string) (string, int, time.Duration, error) {
		start := time.Now()
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			return "", 0, 0, err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "+
			"AppleWebKit/537.36 (KHTML, like Gecko) "+
			"Chrome/117.0.0.0 Safari/537.36")

		resp, err := client.Do(req)
		lat := time.Since(start)
		if err != nil {
			return "", 0, lat, err
		}
		defer resp.Body.Close()
		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		if err != nil {
			return "", resp.StatusCode, lat, err
		}
		return string(bodyBytes), resp.StatusCode, lat, nil
	}

	doPost := func(u string, form url.Values) (string, int, time.Duration, error) {
		start := time.Now()
		req, err := http.NewRequest("POST", u, strings.NewReader(form.Encode()))
		if err != nil {
			return "", 0, 0, err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "+
			"AppleWebKit/537.36 (KHTML, like Gecko) "+
			"Chrome/117.0.0.0 Safari/537.36")

		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(req)
		lat := time.Since(start)
		if err != nil {
			return "", 0, lat, err
		}
		defer resp.Body.Close()
		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		if err != nil {
			return "", resp.StatusCode, lat, err
		}
		return string(bodyBytes), resp.StatusCode, lat, nil
	}

	commonFields := [][]string{
		{"username", "password"},
		{"user", "pass"},
		{"username", "passwd"},
		{"id"},
		{"search"},
		{"q"},
	}

	totalTests := 0
	var findings []Finding

	if parsed.RawQuery != "" {
		values := parsed.Query()
		for range values {
			totalTests += len(payloads) * 2
		}
	} else {
		totalTests = len(payloads) * (1 + len(commonFields))
	}

	tested := 0

	analyze := func(baseBody string, baseStatus int, body string, status int) (foundError string, lenDiff int, statusDiff bool) {
		lower := strings.ToLower(body)
		for _, sig := range sqlErrorSignatures {
			if strings.Contains(lower, sig) {
				return sig, len(body) - len(baseBody), status != baseStatus
			}
		}
		return "", len(body) - len(baseBody), status != baseStatus
	}

	if parsed.RawQuery != "" {
		values := parsed.Query()
		for param := range values {
			original := values.Get(param)
			values.Set(param, original)
			parsed.RawQuery = values.Encode()
			baseURL := parsed.String()
			baseBody, baseStatus, _, _ := doGet(baseURL)

			for _, payload := range payloads {
				values.Set(param, payload)
				parsed.RawQuery = values.Encode()
				testURL := parsed.String()
				tested++
				body, status, lat, err := doGet(testURL)
				if err != nil {
					fmt.Printf("%s %s | %d/%d %s\n", time.Now().Format("15:04:05"), colorize(colorCyan, "[progress]"), tested, totalTests,
						colorize(colorYellow, fmt.Sprintf("error requesting %s : %v", testURL, err)))
				} else {
					foundError, lenDiff, statusDiff := analyze(baseBody, baseStatus, body, status)
					if foundError != "" {
						msg := colorize(colorBold, colorize(colorRed, "[SQLi - ERROR]")) + " param=" + param + " payload=" + fmt.Sprintf("%q", payload)
						fmt.Printf("%s %s | %d/%d %s (%dms) => signature=%s\n", time.Now().Format("15:04:05"),
							colorize(colorCyan, "[progress]"), tested, totalTests, msg, lat.Milliseconds(), foundError)
						findings = append(findings, Finding{Type: "SQLi (error)", Param: param, Payload: payload, URL: testURL, When: time.Now(), Latency: lat, Detail: foundError})
						values.Set(param, original)
						break
					} else if statusDiff || abs(lenDiff) > 30 {
						msg := colorize(colorBold, colorize(colorYellow, "[SQLi - POSSIBLE]")) + " param=" + param + " payload=" + fmt.Sprintf("%q", payload)
						fmt.Printf("%s %s | %d/%d %s (%dms) => lenDiff=%d statusDiff=%v\n", time.Now().Format("15:04:05"),
							colorize(colorCyan, "[progress]"), tested, totalTests, msg, lat.Milliseconds(), lenDiff, statusDiff)
						findings = append(findings, Finding{Type: "SQLi (possible)", Param: param, Payload: payload, URL: testURL, When: time.Now(), Latency: lat, Detail: fmt.Sprintf("lenDiff=%d statusDiff=%v", lenDiff, statusDiff)})
					} else {
						fmt.Printf("%s %s | %d/%d %s (%dms)\n", time.Now().Format("15:04:05"),
							colorize(colorCyan, "[progress]"), tested, totalTests, fmt.Sprintf("ok GET payload=%q", payload), lat.Milliseconds())
					}
				}
				values.Set(param, original)

				for _, fields := range commonFields {
					form := url.Values{}
					if len(fields) >= 1 {
						form.Set(fields[0], payload)
					}
					if len(fields) >= 2 {
						form.Set(fields[1], "")
					}
					postURL := parsed.Scheme + "://" + parsed.Host + parsed.Path
					tested++
					body, status, lat, err := doPost(postURL, form)
					if err != nil {
						fmt.Printf("%s %s | %d/%d %s\n", time.Now().Format("15:04:05"), colorize(colorCyan, "[progress]"), tested, totalTests,
							colorize(colorYellow, fmt.Sprintf("error POST %s : %v", postURL, err)))
						continue
					}
					foundError, lenDiff, statusDiff := analyze(baseBody, baseStatus, body, status)
					if foundError != "" {
						msg := colorize(colorBold, colorize(colorRed, "[SQLi - ERROR]")) + " param=" + fields[0] + " payload=" + fmt.Sprintf("%q", payload)
						fmt.Printf("%s %s | %d/%d %s (%dms) => signature=%s\n", time.Now().Format("15:04:05"),
							colorize(colorCyan, "[progress]"), tested, totalTests, msg, lat.Milliseconds(), foundError)
						findings = append(findings, Finding{Type: "SQLi (error,POST)", Param: fields[0], Payload: payload, URL: postURL, When: time.Now(), Latency: lat, Detail: foundError})
					} else if statusDiff || abs(lenDiff) > 30 {
						msg := colorize(colorBold, colorize(colorYellow, "[SQLi - POSSIBLE]")) + " param=" + fields[0] + " payload=" + fmt.Sprintf("%q", payload)
						fmt.Printf("%s %s | %d/%d %s (%dms) => lenDiff=%d statusDiff=%v\n", time.Now().Format("15:04:05"),
							colorize(colorCyan, "[progress]"), tested, totalTests, msg, lat.Milliseconds(), lenDiff, statusDiff)
						findings = append(findings, Finding{Type: "SQLi (possible,POST)", Param: fields[0], Payload: payload, URL: postURL, When: time.Now(), Latency: lat, Detail: fmt.Sprintf("lenDiff=%d statusDiff=%v", lenDiff, statusDiff)})
					} else {
						fmt.Printf("%s %s | %d/%d %s (%dms)\n", time.Now().Format("15:04:05"),
							colorize(colorCyan, "[progress]"), tested, totalTests, fmt.Sprintf("ok POST %s=%q", fields[0], payload), lat.Milliseconds())
					}
				}
			}
		}
	} else {
		q := parsed.Query()
		q.Set("q", "")
		parsed.RawQuery = q.Encode()
		baseURL := parsed.String()
		baseBody, baseStatus, _, _ := doGet(baseURL)

		for _, payload := range payloads {
			q := parsed.Query()
			q.Set("q", payload)
			parsed.RawQuery = q.Encode()
			testURL := parsed.String()

			tested++
			body, status, lat, err := doGet(testURL)
			if err != nil {
				fmt.Printf("%s %s | %d/%d %s\n", time.Now().Format("15:04:05"), colorize(colorCyan, "[progress]"), tested, totalTests,
					colorize(colorYellow, fmt.Sprintf("error requesting %s : %v", testURL, err)))
				continue
			}
			foundError, lenDiff, statusDiff := analyze(baseBody, baseStatus, body, status)
			if foundError != "" {
				msg := colorize(colorBold, colorize(colorRed, "[SQLi - ERROR]")) + " param=q payload=" + fmt.Sprintf("%q", payload)
				fmt.Printf("%s %s | %d/%d %s (%dms) => signature=%s\n", time.Now().Format("15:04:05"),
					colorize(colorCyan, "[progress]"), tested, totalTests, msg, lat.Milliseconds(), foundError)
				findings = append(findings, Finding{Type: "SQLi (error)", Param: "q", Payload: payload, URL: testURL, When: time.Now(), Latency: lat, Detail: foundError})
			} else if statusDiff || abs(lenDiff) > 30 {
				msg := colorize(colorBold, colorize(colorYellow, "[SQLi - POSSIBLE]")) + " param=q payload=" + fmt.Sprintf("%q", payload)
				fmt.Printf("%s %s | %d/%d %s (%dms) => lenDiff=%d statusDiff=%v\n", time.Now().Format("15:04:05"),
					colorize(colorCyan, "[progress]"), tested, totalTests, msg, lat.Milliseconds(), lenDiff, statusDiff)
				findings = append(findings, Finding{Type: "SQLi (possible)", Param: "q", Payload: payload, URL: testURL, When: time.Now(), Latency: lat, Detail: fmt.Sprintf("lenDiff=%d statusDiff=%v", lenDiff, statusDiff)})
			} else {
				fmt.Printf("%s %s | %d/%d %s (%dms)\n", time.Now().Format("15:04:05"),
					colorize(colorCyan, "[progress]"), tested, totalTests, fmt.Sprintf("ok GET payload=%q", payload), lat.Milliseconds())
			}

			for _, fields := range commonFields {
				form := url.Values{}
				if len(fields) >= 1 {
					form.Set(fields[0], payload)
				}
				if len(fields) >= 2 {
					form.Set(fields[1], "")
				}
				postURL := parsed.Scheme + "://" + parsed.Host + parsed.Path
				tested++
				body, status, lat, err := doPost(postURL, form)
				if err != nil {
					fmt.Printf("%s %s | %d/%d %s\n", time.Now().Format("15:04:05"), colorize(colorCyan, "[progress]"), tested, totalTests,
						colorize(colorYellow, fmt.Sprintf("error POST %s : %v", postURL, err)))
					continue
				}
				foundError, lenDiff, statusDiff := analyze(baseBody, baseStatus, body, status)
				if foundError != "" {
					msg := colorize(colorBold, colorize(colorRed, "[SQLi - ERROR]")) + " param=" + fields[0] + " payload=" + fmt.Sprintf("%q", payload)
					fmt.Printf("%s %s | %d/%d %s (%dms) => signature=%s\n", time.Now().Format("15:04:05"),
						colorize(colorCyan, "[progress]"), tested, totalTests, msg, lat.Milliseconds(), foundError)
					findings = append(findings, Finding{Type: "SQLi (error,POST)", Param: fields[0], Payload: payload, URL: postURL, When: time.Now(), Latency: lat, Detail: foundError})
				} else if statusDiff || abs(lenDiff) > 30 {
					msg := colorize(colorBold, colorize(colorYellow, "[SQLi - POSSIBLE]")) + " param=" + fields[0] + " payload=" + fmt.Sprintf("%q", payload)
					fmt.Printf("%s %s | %d/%d %s (%dms) => lenDiff=%d statusDiff=%v\n", time.Now().Format("15:04:05"),
						colorize(colorCyan, "[progress]"), tested, totalTests, msg, lat.Milliseconds(), lenDiff, statusDiff)
					findings = append(findings, Finding{Type: "SQLi (possible,POST)", Param: fields[0], Payload: payload, URL: postURL, When: time.Now(), Latency: lat, Detail: fmt.Sprintf("lenDiff=%d statusDiff=%v", lenDiff, statusDiff)})
				} else {
					fmt.Printf("%s %s | %d/%d %s (%dms)\n", time.Now().Format("15:04:05"),
						colorize(colorCyan, "[progress]"), tested, totalTests, fmt.Sprintf("ok POST %s=%q", fields[0], payload), lat.Milliseconds())
				}
			}
		}
	}

	fmt.Println()
	fmt.Println(colorize(colorBold, "SQLi Scan summary"))
	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("Target: %s\n", colorize(colorBlue, target))
	fmt.Printf("Payloads tested: %d\n", totalTests)
	fmt.Printf("Findings: %d\n", len(findings))
	fmt.Println(strings.Repeat("-", 60))
	if len(findings) > 0 {
		for i, f := range findings {
			fmt.Printf("%d) [%s] param=%s payload=%s url=%s time=%dms detail=%s\n", i+1, f.Type, f.Param, f.Payload, f.URL, f.Latency.Milliseconds(), f.Detail)
		}
	} else {
		fmt.Println(colorize(colorGreen, "No SQLi signs found with given payload set."))
	}
	fmt.Println(colorize(colorCyan, "SQLi scan finished.\nOverall elapsed:"), time.Since(startAll).String())
}

// /////////////////////////////////////////////////////////////////////////////
// Helpers: loadPayloads, htmlEscapeSimple, abs
// /////////////////////////////////////////////////////////////////////////////
func loadPayloads(filename string) ([]string, error) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		fmt.Printf("'%s' not found — creating sample file with a few payloads.\n", filename)
		sample := []string{
			`' OR '1'='1`,
			`" OR "1"="1`,
			`' OR 1=1-- `,
			`" OR 1=1-- `,
			`' OR 'a'='a`,
			`' AND '1'='2`,
			`" AND "1"="2`,
			`' UNION SELECT NULL-- `,
			`' UNION SELECT 1,2,3-- `,
			`' AND SLEEP(5)-- `,
		}
		b, _ := json.MarshalIndent(sample, "", "  ")
		if writeErr := os.WriteFile(filename, b, 0644); writeErr != nil {
			return nil, writeErr
		}
		return sample, nil
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, errors.New("payload file is empty")
	}

	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		return arr, nil
	}

	var objWithPayloads struct {
		Payloads []string `json:"payloads"`
	}
	if err := json.Unmarshal(data, &objWithPayloads); err == nil && len(objWithPayloads.Payloads) > 0 {
		return objWithPayloads.Payloads, nil
	}

	var generic map[string]interface{}
	if err := json.Unmarshal(data, &generic); err == nil {
		var out []string
		if raw, ok := generic["payloads"]; ok {
			switch v := raw.(type) {
			case []interface{}:
				for _, it := range v {
					if s, ok := it.(string); ok {
						out = append(out, s)
					}
				}
				if len(out) > 0 {
					return out, nil
				}
			case string:
				return []string{v}, nil
			}
		}
		for _, val := range generic {
			switch v := val.(type) {
			case string:
				out = append(out, v)
			case []interface{}:
				for _, it := range v {
					if s, ok := it.(string); ok {
						out = append(out, s)
					}
				}
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}

	return nil, errors.New("unsupported payload JSON format (expected array of strings or object with payloads)")
}

func htmlEscapeSimple(s string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(s)
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func Whois() {
	startAll := time.Now()

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter domain or host (e.g. example.com): ")
	rawTarget, _ := reader.ReadString('\n')
	target := strings.TrimSpace(rawTarget)
	if target == "" {
		fmt.Println(colorize(colorRed, "No target provided."))
		return
	}

	fmt.Printf("\nStarting WHOIS lookup for %s\n\n", colorize(colorBold, target))

	primaryServers := []string{
		"whois.iana.org",
		"whois.verisign-grs.com",
		"whois.arin.net",
		"whois.ripe.net",
		"whois.nic.tr",
	}

	var lastResp string
	var err error
	tried := map[string]bool{}

	for _, srv := range primaryServers {
		if tried[srv] {
			continue
		}
		tried[srv] = true
		lastResp, err = whoisLookup(srv, target)
		if err != nil {
			fmt.Printf("%s querying %s : %v\n", colorize(colorYellow, "[!]"), srv, err)
			continue
		}
		fmt.Printf("=== response from %s ===\n", srv)
		fmt.Println(lastResp)

		ref := parseWhoisReferral(lastResp)
		if ref != "" && !tried[ref] {
			fmt.Printf("\nFound referral to %s — querying it...\n\n", ref)
			tried[ref] = true
			lastResp, err = whoisLookup(ref, target)
			if err != nil {
				fmt.Printf("%s querying %s : %v\n", colorize(colorYellow, "[!]"), ref, err)
			} else {
				fmt.Printf("=== response from %s ===\n", ref)
				fmt.Println(lastResp)
			}
		}
		break
	}

	if lastResp == "" && err != nil {
		fmt.Println(colorize(colorRed, "WHOIS lookup failed: "), err)
	}

	fmt.Println()
	fmt.Println(colorize(colorBold, "WHOIS summary"))
	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("Target: %s\n", colorize(colorBlue, target))
	fmt.Println(strings.Repeat("-", 60))
	fmt.Println(colorize(colorCyan, "WHOIS lookup finished.\nOverall elapsed:"), time.Since(startAll).String())
}

func whoisLookup(server string, query string) (string, error) {
	addr := server + ":43"
	dialTimeout := 8 * time.Second
	conn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	_, err = conn.Write([]byte(query + "\r\n"))
	if err != nil {
		return "", err
	}

	conn.SetReadDeadline(time.Now().Add(12 * time.Second))
	body, err := io.ReadAll(io.LimitReader(conn, 200<<10))
	if err != nil {
		if err == io.EOF {
		} else {
			return "", err
		}
	}

	return string(body), nil
}

func parseWhoisReferral(resp string) string {
	lower := strings.ToLower(resp)
	lines := strings.Split(lower, "\n")
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "refer:") {
			parts := strings.Fields(l)
			if len(parts) >= 2 {
				return strings.TrimSpace(parts[1])
			}
		}
		if strings.Contains(l, "whois server:") {
			parts := strings.SplitN(l, "whois server:", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
		if strings.HasPrefix(l, "whois:") {
			parts := strings.Fields(l)
			if len(parts) >= 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

// /////////////////////////////////////////////////////////////////////////////
// Port Scanner
// /////////////////////////////////////////////////////////////////////////////
func PortScan() {
	startAll := time.Now()

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the target host or IP (e.g., example.com or 192.168.1.1): ")
	rawTarget, _ := reader.ReadString('\n')
	target := strings.TrimSpace(rawTarget)
	if target == "" {
		fmt.Println(colorize(colorRed, "No target provided."))
		return
	}

	fmt.Print("Enter the ports to scan (comma-separated or range, e.g., 22,80,443 or 1-1024): ")
	rawPorts, _ := reader.ReadString('\n')
	portInput := strings.TrimSpace(rawPorts)
	if portInput == "" {
		portInput = "1-1024"
	}

	ports := parsePorts(portInput)
	if len(ports) == 0 {
		fmt.Println(colorize(colorRed, "No valid ports provided."))
		return
	}

	fmt.Print("How many ports should be scanned per second? (pps, e.g. 200) [default 200]: ")
	rawPps, _ := reader.ReadString('\n')
	rawPps = strings.TrimSpace(rawPps)
	pps := 200
	if rawPps != "" {
		if v, err := strconv.Atoi(rawPps); err == nil && v > 0 {
			pps = v
		} else {
			fmt.Println(colorize(colorYellow, "Invalid pps, using default 200."))
		}
	}

	interval := time.Second / time.Duration(pps)
	if interval <= 0 {
		interval = time.Millisecond
	}

	fmt.Printf("\n%s Starting port scan on %s — %d port(s) at %d pps\n\n",
		time.Now().Format("15:04:05"), colorize(colorBold, target), len(ports), pps)

	const maxConcurrency = 500
	sema := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup

	limiter := time.NewTicker(interval)
	defer limiter.Stop()

	openPortsCh := make(chan int, 16)

	clientTimeout := 700 * time.Millisecond

	go func() {
		for p := range openPortsCh {
			fmt.Printf("%s %s port %d %sOPEN%s\n", time.Now().Format("15:04:05"), colorize(colorCyan, "[open]"), p, colorRed, colorReset)
		}
	}()

	for _, port := range ports {
		<-limiter.C
		sema <- struct{}{}
		wg.Add(1)

		go func(p int) {
			defer wg.Done()
			defer func() { <-sema }()

			address := fmt.Sprintf("%s:%d", target, p)
			start := time.Now()
			conn, err := net.DialTimeout("tcp", address, clientTimeout)
			lat := time.Since(start)
			if err == nil {
				conn.Close()
				_ = lat
				openPortsCh <- p
			} else {
				_ = err
			}
		}(port)
	}

	wg.Wait()
	close(openPortsCh)

	fmt.Println()
	fmt.Println(colorize(colorBold, "Port Scan finished."))
	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("Target: %s\n", colorize(colorBlue, target))
	fmt.Printf("Requested rate: %d pps\n", pps)
	fmt.Println(strings.Repeat("-", 60))
	fmt.Println(colorize(colorCyan, "Overall elapsed:"), time.Since(startAll).String())
}

func parsePorts(input string) []int {
	var ports []int
	for _, part := range strings.Split(input, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			rangeParts := strings.SplitN(part, "-", 2)
			if len(rangeParts) != 2 {
				continue
			}
			var start, end int
			fmt.Sscanf(strings.TrimSpace(rangeParts[0]), "%d", &start)
			fmt.Sscanf(strings.TrimSpace(rangeParts[1]), "%d", &end)
			if start <= 0 {
				start = 1
			}
			if end < start {
				continue
			}
			for p := start; p <= end; p++ {
				ports = append(ports, p)
			}
		} else {
			var p int
			fmt.Sscanf(part, "%d", &p)
			if p > 0 {
				ports = append(ports, p)
			}
		}
	}
	return ports
}
