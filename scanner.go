package main

import (
	"fmt"
	"io" // เปลี่ยนจาก io/ioutil เป็น io
	"net/http"
	"net/url"
	"strings"
)

type Vulnerability struct {
	Type     string
	URL      string
	Param    string
	Severity string
	Evidence string
}

var sqlErrors = []string{
	"You have an error in your SQL syntax",
	"Warning: mysql_",
	"Unclosed quotation mark after the character string",
	"quoted string not properly terminated",
	"SQLSTATE[HY000]",
}

func ScanSQLInjection(targetURL string) []Vulnerability {
	var vulns []Vulnerability

	u, err := url.Parse(targetURL)
	if err != nil {
		return vulns
	}

	queryParams := u.Query()
	if len(queryParams) == 0 {
		return vulns
	}

	fmt.Printf("[*] Scanning SQLi: %s\n", targetURL)

	for param, values := range queryParams {
		originalValue := values[0]
		payload := originalValue + "'"

		newParams := url.Values{}
		for p, v := range queryParams {
			if p == param {
				newParams.Set(p, payload)
			} else {
				newParams.Set(p, v[0])
			}
		}

		u.RawQuery = newParams.Encode()
		attackURL := u.String()

		resp, err := http.Get(attackURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		bodyBytes, _ := io.ReadAll(resp.Body) // ใช้ io.ReadAll
		bodyString := string(bodyBytes)

		for _, errSig := range sqlErrors {
			if strings.Contains(bodyString, errSig) {
				v := Vulnerability{
					Type:     "SQL Injection (Error-Based)",
					URL:      targetURL,
					Param:    param,
					Severity: "High",
					Evidence: errSig,
				}
				vulns = append(vulns, v)
				fmt.Printf("🔥 FOUND SQLi on param '%s'! Evidence: %s\n", param, errSig)
				break
			}
		}
	}

	return vulns
}

func ScanXSS(targetURL string) []Vulnerability {
	var vulns []Vulnerability
	xssPayload := "<script>alert('OpenBurp')</script>"

	u, err := url.Parse(targetURL)
	if err != nil {
		return vulns
	}
	queryParams := u.Query()

	fmt.Printf("[*] Scanning XSS: %s\n", targetURL)

	for param, values := range queryParams {
		_ = values[0]

		newParams := url.Values{}
		for p, v := range queryParams {
			if p == param {
				newParams.Set(p, xssPayload)
			} else {
				newParams.Set(p, v[0])
			}
		}

		u.RawQuery = newParams.Encode()
		attackURL := u.String()

		resp, err := http.Get(attackURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		bodyBytes, _ := io.ReadAll(resp.Body) // ใช้ io.ReadAll
		bodyString := string(bodyBytes)

		if strings.Contains(bodyString, xssPayload) {
			v := Vulnerability{
				Type:     "Reflected XSS",
				URL:      targetURL,
				Param:    param,
				Severity: "Medium",
				Evidence: "Payload reflected in response body",
			}
			vulns = append(vulns, v)
			fmt.Printf("🤡 FOUND XSS on param '%s'!\n", param)
		}
	}
	return vulns
}
