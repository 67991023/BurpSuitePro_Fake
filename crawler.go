package main

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gocolly/colly/v2"
)

// 1. Structure สำหรับเก็บผลลัพธ์
type DiscoveryResult struct {
	URLs []string
}

// 2. Wordlist สำหรับ Fuzzer
var commonPaths = []string{
	"admin", "login", "backup", "config", ".git", ".env", "dashboard",
	"api", "uploads", "test", "db", "administrator",
}

// ==========================================
// 🕸️ PART A: THE CRAWLER (แมงมุม)
// ==========================================
func StartCrawler(targetURL string, allowedDomain string) []string {
	// 1. แจ้งสถานะ Scope ให้ผู้ใช้ทราบ
	fmt.Printf("\n🕷️ Starting Spider on: %s\n", targetURL)
	fmt.Printf("🚧 Scope restricted to: %s\n", allowedDomain)

	// เก็บ URL ที่เจอทั้งหมดไม่ให้ซ้ำกัน
	foundURLs := make(map[string]bool)
	var mu sync.Mutex

	// สร้าง Collector
	c := colly.NewCollector(
		colly.MaxDepth(2),
		colly.Async(true),
		// 2. หัวใจสำคัญ: อนุญาตเฉพาะ Domain นี้และ www. ของมันเท่านั้น
		colly.AllowedDomains(allowedDomain, "www."+allowedDomain),
	)

	// ตั้งค่า Delay ไม่ให้ยิงรัวเกินไป
	c.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: 2,
		Delay:       1 * time.Second,
	})

	// เมื่อเจอ Link <a>
	c.OnHTML("a[href]", func(e *colly.HTMLElement) {
		link := e.Attr("href")
		absoluteLink := e.Request.AbsoluteURL(link)

		// 3. กรองซ้ำด้วยตัวเองอีกชั้น (Double Safety)
		// เช็คว่า Link ที่จะไป มีชื่อโดเมนเป้าหมายผสมอยู่หรือไม่
		if !strings.Contains(absoluteLink, allowedDomain) {
			// ถ้าเป็นเว็บอื่น (เช่น twitter.com) ให้ข้ามทันที
			return
		}

		if strings.HasPrefix(absoluteLink, "http") {
			mu.Lock()
			if !foundURLs[absoluteLink] {
				foundURLs[absoluteLink] = true
				fmt.Printf("🕸️ [CRAWL] Found: %s\n", absoluteLink)
			}
			mu.Unlock()

			// สั่งให้เดินต่อ (Visit) เฉพาะถ้าผ่านเงื่อนไข Scope ด้านบน
			e.Request.Visit(link)
		}
	})

	// เริ่มต้นเดินจาก Target แรก
	c.Visit(targetURL)
	c.Wait()

	// แปลง Map เป็น Slice เพื่อส่งกลับ
	var results []string
	for u := range foundURLs {
		results = append(results, u)
	}
	return results
}

// ==========================================
// 💣 PART B: THE FUZZER (นักเดาใจ)
// ==========================================
func StartFuzzer(baseURL string) []string {
	fmt.Printf("\n💣 Starting Fuzzer on: %s\n", baseURL)

	var foundPaths []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	for _, path := range commonPaths {
		wg.Add(1)

		go func(p string) {
			defer wg.Done()

			target := baseURL + p
			resp, err := client.Get(target) // รองรับ HTTPS อัตโนมัติ
			if err != nil {
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != 404 {
				fmt.Printf("💣 [FUZZ] Found Hidden Path: %s (Status: %d)\n", target, resp.StatusCode)

				mu.Lock()
				foundPaths = append(foundPaths, target)
				mu.Unlock()
			}
		}(path)
	}

	wg.Wait()
	return foundPaths
}
