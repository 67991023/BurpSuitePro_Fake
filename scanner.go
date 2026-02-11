// scanner.go
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

// 1. Definte Struct: รูปแบบรายงานผลช่องโหว่
type Vulnerability struct {
	Type     string // ชื่อช่องโหว่ เช่น "SQL Injection"
	URL      string // URL ที่เจอ
	Param    string // Parameter ที่มีปัญหา เช่น "id"
	Severity string // ระดับความรุนแรง: High, Medium, Low
	Evidence string // หลักฐาน (เช่น Error Message ที่เจอ)
}

// Global List สำหรับเก็บ Error Signatures ของ SQL (เอาไว้เทียบ)
var sqlErrors = []string{
	"You have an error in your SQL syntax",
	"Warning: mysql_",
	"Unclosed quotation mark after the character string",
	"quoted string not properly terminated",
	"SQLSTATE[HY000]",
}

// ฟังก์ชันสแกนหา SQL Injection
/*
รับ Request เข้ามา
วนลูปหาทุก Parameter (เช่น ?id=1&name=test)
Inject: ใส่ ' (Single Quote) ต่อท้ายค่าเดิม
Send: ส่ง Request ใหม่ไปหา Server
Analyze: อ่าน Response Body ว่ามีคำว่า "SQL syntax" หรือไม่
*/
func ScanSQLInjection(targetURL string) []Vulnerability {
	var vulns []Vulnerability

	// 1. Parse URL เพื่อแยก Parameter
	u, err := url.Parse(targetURL)
	if err != nil {
		return vulns
	}

	queryParams := u.Query()
	if len(queryParams) == 0 {
		return vulns // ไม่มี Parameter ให้ยิง
	}

	fmt.Printf("[*] Scanning SQLi: %s\n", targetURL)

	// 2. วนลูปทุก Parameter (เช่น id, page, search)
	for param, values := range queryParams {
		originalValue := values[0]

		// 3. สร้าง Payload: ใส่ ' ต่อท้าย (The Classic Test)
		payload := originalValue + "'"

		// สร้าง Query String ใหม่
		newParams := url.Values{}
		// Copy ค่าอื่นๆ มาให้เหมือนเดิม (กันเหนียว)
		for p, v := range queryParams {
			if p == param {
				newParams.Set(p, payload) // ใส่ยาพิษเฉพาะตัวนี้
			} else {
				newParams.Set(p, v[0])
			}
		}

		// สร้าง URL ใหม่ที่มียาพิษ
		u.RawQuery = newParams.Encode()
		attackURL := u.String()

		// 4. ส่ง Request ไปโจมตี
		resp, err := http.Get(attackURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// อ่าน Body กลับมาดูผล
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		bodyString := string(bodyBytes)

		// 5. ตรวจจับ Error (Signature Matching)
		for _, errSig := range sqlErrors {
			if strings.Contains(bodyString, errSig) {
				// 💥 BINGO! เจอช่องโหว่
				v := Vulnerability{
					Type:     "SQL Injection (Error-Based)",
					URL:      targetURL,
					Param:    param,
					Severity: "High",
					Evidence: errSig, // เช่น "You have an error..."
				}
				vulns = append(vulns, v)
				fmt.Printf("🔥 FOUND SQLi on param '%s'! Evidence: %s\n", param, errSig)
				break // เจอแล้วหยุด Loop error check
			}
		}
	}

	return vulns
}

// ฟังก์ชันสแกนหา XSS
/*
สร้าง Reflected XSS Module
Logic คล้าย SQLi แต่เปลี่ยน Payload และวิธีตรวจจับ:
    Inject: ใส่ <script>alert('XSS')</script>
    Analyze: ดูว่าใน Response Body มีคำนี้เด้งกลับมา เป๊ะๆ ไหม
*/
func ScanXSS(targetURL string) []Vulnerability {
	var vulns []Vulnerability

	// Payload มาตรฐาน
	xssPayload := "<script>alert('OpenBurp')</script>"

	u, err := url.Parse(targetURL)
	if err != nil {
		return vulns
	}
	queryParams := u.Query()

	fmt.Printf("[*] Scanning XSS: %s\n", targetURL)

	for param, values := range queryParams {
		// originalValue := values[0]
		_ = values[0]

		// Inject Payload
		newParams := url.Values{}
		for p, v := range queryParams {
			if p == param {
				newParams.Set(p, xssPayload) // ใส่ Script แทนค่าเดิม
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

		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		bodyString := string(bodyBytes)

		// Check: ถ้าเจอ Payload ของเราสะท้อนกลับมา แสดงว่าเสร็จแน่
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
