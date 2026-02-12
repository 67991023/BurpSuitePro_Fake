package main

import (
	"crypto/tls" // <--- ต้องใช้ package นี้
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// รับข้อมูลจากหน้าเว็บ
type RepeaterRequest struct {
	Method  string `json:"method"`
	URL     string `json:"url"`
	Headers string `json:"headers"`
	Body    string `json:"body"`
}

// ส่งผลลัพธ์กลับไปหน้าเว็บ
type RepeaterResponse struct {
	Status     string              `json:"status"`
	StatusCode int                 `json:"statusCode"`
	Body       string              `json:"body"`
	Headers    map[string][]string `json:"headers"`
	TimeTaken  string              `json:"timeTaken"`
}

func handleRepeaterAPI(w http.ResponseWriter, r *http.Request) {
	// 1. อ่าน JSON ที่ส่งมาจากหน้าเว็บ
	var reqPayload RepeaterRequest
	if err := json.NewDecoder(r.Body).Decode(&reqPayload); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// 2. สร้าง HTTP Client ใหม่
	client := &http.Client{
		Timeout: 10 * time.Second,
		// ไม่ตรวจสอบ SSL (Insecure) เพื่อความสะดวกในการ Hack
		Transport: &http.Transport{
			// ✅ แก้ไขตรงนี้: เปลี่ยนจาก http.Config เป็น tls.Config
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// 3. เตรียม Request
	req, err := http.NewRequest(reqPayload.Method, reqPayload.URL, strings.NewReader(reqPayload.Body))
	if err != nil {
		http.Error(w, "Error creating request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 4. Parse Headers (แบบบ้านๆ: แยกบรรทัด -> แยก :)
	if reqPayload.Headers != "" {
		lines := strings.Split(reqPayload.Headers, "\n")
		for _, line := range lines {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])

				// 🌟 [เพิ่มตรงนี้] ถ้าเจอ Accept-Encoding ให้ข้ามไปเลย (ให้ Go จัดการเอง)
				if strings.EqualFold(key, "Accept-Encoding") {
					continue
				}

				req.Header.Set(key, val)
			}
		}
	}

	// 5. จับเวลาและยิง!
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RepeaterResponse{
			Status: "Error: " + err.Error(),
		})
		return
	}
	defer resp.Body.Close()
	duration := time.Since(start)

	// 6. อ่าน Response Body
	bodyBytes, _ := io.ReadAll(resp.Body)

	// 7. ส่งผลลัพธ์กลับไปให้หน้าเว็บ
	result := RepeaterResponse{
		Status:     resp.Status,
		StatusCode: resp.StatusCode,
		Body:       string(bodyBytes),
		Headers:    resp.Header,
		TimeTaken:  duration.String(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleHistoryAPI(w http.ResponseWriter, r *http.Request) {
	history := GetTrafficHistory()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(history)
}
