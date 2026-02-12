// In-Memory Storage (เก็บใน RAM)
package main

import (
	"sync"
	"time"
)

// โครงสร้างข้อมูลที่จะเก็บ
type HistoryItem struct {
	ID        int       `json:"id"`
	Method    string    `json:"method"`
	URL       string    `json:"url"`
	Headers   string    `json:"headers"` // เก็บเป็น JSON string ง่ายๆ
	Body      string    `json:"body"`
	Timestamp time.Time `json:"timestamp"`
}

// Global Variable สำหรับเก็บข้อมูล
var (
	RequestHistory []HistoryItem
	historyMutex   sync.Mutex
	historyID      = 1
)

// ฟังก์ชันบันทึกข้อมูล
func SaveTraffic(method, urlStr, headers, body string) {
	historyMutex.Lock()
	defer historyMutex.Unlock()

	item := HistoryItem{
		ID:        historyID,
		Method:    method,
		URL:       urlStr,
		Headers:   headers,
		Body:      body,
		Timestamp: time.Now(),
	}

	// เพิ่มเข้า Array (และจำกัดไว้แค่ 1000 รายการล่าสุด กัน RAM เต็ม)
	RequestHistory = append(RequestHistory, item)
	if len(RequestHistory) > 1000 {
		RequestHistory = RequestHistory[1:]
	}
	historyID++
}

// ฟังก์ชันดึงข้อมูลทั้งหมด
func GetTrafficHistory() []HistoryItem {
	historyMutex.Lock()
	defer historyMutex.Unlock()

	// Copy เพื่อความปลอดภัยของ Thread
	copied := make([]HistoryItem, len(RequestHistory))
	copy(copied, RequestHistory)
	return copied
}
