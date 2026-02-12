package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url" // ใช้สำหรับแกะ URL
	"strings" // ใช้สำหรับเช็ค Domain
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// --- 1. CONFIGURATION: SCOPE & FILTER ---
var (
	// 🎯 เป้าหมายหลัก (แก้ตรงนี้ตามหน้างาน)
	targetDomain = "vulnweb.com"

	// 🗑️ โดเมนขยะ (Noise) ที่จะไม่ Log และไม่ Scan
	ignoredDomains = []string{
		"mozilla.com", "firefox.com", "google.com", "gstatic.com",
		"googleapis.com", "digicert.com", "microsoft.com", "bing.com",
		"apple.com", "icloud.com",
	}
)

// ฟังก์ชันช่วยเช็คว่าเป็นโดเมนขยะไหม
func isIgnored(host string) bool {
	for _, d := range ignoredDomains {
		if strings.Contains(host, d) {
			return true
		}
	}
	return false
}

// --- WebSocket Setup ---
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

var broadcast = make(chan LogEntry)

type LogEntry struct {
	Method string `json:"method"`
	URL    string `json:"url"`
	Body   string `json:"body"`
}

// --- State Management ---
var (
	scannedHosts = make(map[string]bool)
	hostsMutex   sync.Mutex
)

var oastService *OASTService

// เช็คว่า Host นี้เคยรัน Nuclei ไปหรือยัง
func shouldScan(host string) bool {
	hostsMutex.Lock()
	defer hostsMutex.Unlock()

	if scannedHosts[host] {
		return false
	}
	scannedHosts[host] = true
	return true
}

// ==========================================
// 🚀 MAIN FUNCTION
// ==========================================
func main() {

	// 1. เริ่ม OAST Service
	var err error
	oastService, err = StartOAST()
	if err != nil {
		log.Println("⚠️ Failed to start OAST service:", err)
		log.Println("⚠️ Blind Scan will be disabled.")
	} else {
		defer oastService.Close()
		log.Println("✅ OAST Service Ready! Polling for callbacks...")
	}

	// 2. โหลด Certificate
	caCert, err := tls.LoadX509KeyPair("ca.crt", "ca.key")
	if err != nil {
		log.Fatal("❌ โหลด Cert ไม่ได้ (อย่าลืมสร้าง ca.crt/ca.key):", err)
	}

	// 3. เริ่ม Dashboard Server
	go startDashboardServer()

	// ==========================================
	// 🕸️ PHASE 6: AUTO-DISCOVERY MODULE
	// ==========================================
	go func() {
		// รอ 3 วินาทีให้ Proxy และ Dashboard พร้อมก่อน
		time.Sleep(3 * time.Second)

		target := "http://testphp.vulnweb.com" // 🎯 แก้เป้าหมายเริ่มต้นตรงนี้

		log.Printf("\n🚀 [PHASE 6] Auto-Discovery Module Started on: %s", target)
		log.Println("⏳ Crawling & Fuzzing in background...")

		parsedURL, err := url.Parse(target)
		if err != nil || parsedURL.Host == "" {
			log.Printf("⚠️ Invalid Target URL: %s", target)
			return
		}

		// อัปเดต Scope อัตโนมัติจาก Target ที่ใส่มา
		scopeDomain := parsedURL.Host
		targetDomain = scopeDomain // Override Global Variable
		log.Printf("🚧 Security Scope restricted to: %s", targetDomain)

		// A. เรียก Crawler (ต้องมีไฟล์ discovery.go)
		// ถ้ายังไม่มีไฟล์ discovery.go ให้ comment บรรทัดนี้ก่อน
		crawledURLs := StartCrawler(target, scopeDomain)

		// B. เรียก Fuzzer (ต้องมีไฟล์ discovery.go)
		// ถ้ายังไม่มีไฟล์ discovery.go ให้ comment บรรทัดนี้ก่อน
		fuzzedURLs := StartFuzzer(target)

		// C. รวมผลลัพธ์
		allTargets := append(crawledURLs, fuzzedURLs...)
		log.Printf("🎯 Discovery Finished! Found %d unique targets.", len(allTargets))

		// D. ส่งเข้า Scanner Engine
		for _, u := range allTargets {
			log.Printf("🔫 [AUTO-SCAN] Shooting payloads at: %s", u)

			go func(urlToScan string) {
				// สแกน SQLi
				vulnsSQL := ScanSQLInjection(urlToScan)
				broadcastToDashboard(vulnsSQL)

				// สแกน XSS
				vulnsXSS := ScanXSS(urlToScan)
				broadcastToDashboard(vulnsXSS)

				// สแกน Blind (OAST)
				if oastService != nil {
					RunOASTScan(urlToScan, oastService.InteractURL)
				}
			}(u)
		}
	}()
	// ==========================================

	// 4. เริ่ม Proxy Server
	server := &http.Server{
		Addr: ":8080",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleHTTPS(w, r, caCert)
			} else {
				handleHTTP(w, r)
			}
		}),
	}

	log.Println("🔥 OpenBurp Proxy: :8080 (With Dynamic Certs!)")
	log.Println("💻 Dashboard UI : http://localhost:8081/dashboard")
	log.Fatal(server.ListenAndServe())
}

// ==========================================
// 🛡️ PROXY HANDLERS (With Filter)
// ==========================================

func handleHTTPS(w http.ResponseWriter, r *http.Request, caCert tls.Certificate) {
	// 1. Hijack Connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	// บอก Client ว่าเชื่อมต่อสำเร็จ
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// 2. สร้าง Fake Cert
	host, _, _ := net.SplitHostPort(r.Host)
	fakeCert, err := genFakeCert(caCert, host)
	if err != nil {
		return
	}

	// 3. TLS Handshake กับ Client (Browser)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{fakeCert},
		MinVersion:   tls.VersionTLS12,
	}
	tlsClientConn := tls.Server(clientConn, tlsConfig)
	if err := tlsClientConn.Handshake(); err != nil {
		clientConn.Close()
		return
	}
	defer tlsClientConn.Close()

	// 4. เชื่อมต่อไปยัง Server จริง (Destination)
	destConn, err := tls.Dial("tcp", r.Host, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	defer destConn.Close()

	reader := bufio.NewReader(tlsClientConn)

	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			break
		}

		// --- 🛡️ SCOPE & FILTER LOGIC ---
		hostName := r.Host // เช่น testphp.vulnweb.com

		// A. NOISE FILTER: ข้าม Firefox/Google Traffic
		if isIgnored(hostName) {
			goto ForwardTraffic
		}

		// B. DASHBOARD LOG: เฉพาะที่ไม่ใช่ Noise
		go func() {
			broadcast <- LogEntry{
				Method: "🔒 " + req.Method,
				URL:    "https://" + hostName + req.URL.Path,
				Body:   "(Encrypted Traffic)",
			}
		}()

		// C. ACTIVE SCANNER: เฉพาะเว็บที่เป็น Target เท่านั้น
		if strings.Contains(hostName, targetDomain) && req.Method == "GET" && len(req.URL.Query()) > 0 {
			targetURL := "https://" + hostName + req.URL.Path + "?" + req.URL.RawQuery

			log.Printf("🚀 Scanning Target (In-Scope): %s", targetURL)
			go func(u string) {
				vulnsSQL := ScanSQLInjection(u)
				broadcastToDashboard(vulnsSQL)

				vulnsXSS := ScanXSS(u)
				broadcastToDashboard(vulnsXSS)

				if oastService != nil {
					RunOASTScan(u, oastService.InteractURL)
				}
			}(targetURL)
		}

		// Forward Traffic Logic
	ForwardTraffic:
		req.URL.Scheme = "https"
		req.URL.Host = r.Host

		if err := req.Write(destConn); err != nil {
			break
		}
		resp, err := http.ReadResponse(bufio.NewReader(destConn), req)
		if err != nil {
			break
		}
		if err := resp.Write(tlsClientConn); err != nil {
			break
		}
	}
}

func handleHTTP(w http.ResponseWriter, r *http.Request) {
	hostName := r.Host

	// A. NOISE FILTER
	if isIgnored(hostName) {
		// ส่งต่อ Request แบบปกติโดยไม่ Log
		forwardHTTP(w, r)
		return
	}

	// B. DASHBOARD LOG
	go func() {
		broadcast <- LogEntry{
			Method: r.Method,
			URL:    r.URL.String(),
			Body:   "",
		}
	}()

	// C. ACTIVE SCANNER (In-Scope Only)
	if strings.Contains(hostName, targetDomain) && r.Method == "GET" && len(r.URL.Query()) > 0 {
		targetURL := r.URL.String()
		if r.URL.Scheme == "" {
			targetURL = "http://" + r.Host + r.URL.Path + "?" + r.URL.RawQuery
		}

		log.Printf("🚀 Scanning HTTP (In-Scope): %s", targetURL)
		go func(u string) {
			vulnsSQL := ScanSQLInjection(u)
			broadcastToDashboard(vulnsSQL)

			vulnsXSS := ScanXSS(u)
			broadcastToDashboard(vulnsXSS)

			if oastService != nil {
				RunOASTScan(u, oastService.InteractURL)
			}
		}(targetURL)
	}

	// Forward Traffic
	forwardHTTP(w, r)
}

func forwardHTTP(w http.ResponseWriter, r *http.Request) {
	r.RequestURI = ""
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, "Error fetching: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// ==========================================
// 🛠️ HELPER FUNCTIONS
// ==========================================

func startDashboardServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "dashboard.html")
	})
	mux.HandleFunc("/ws", handleWebSocket)
	log.Fatal(http.ListenAndServe(":8081", mux))
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()

	for msg := range broadcast {
		ws.WriteJSON(msg)
	}
}

func broadcastToDashboard(vulns []Vulnerability) {
	for _, v := range vulns {
		alertMsg := fmt.Sprintf("ความรุนแรง: %s | หลักฐาน: %s", v.Severity, v.Evidence)
		broadcast <- LogEntry{
			Method: "🔥 " + v.Type,
			URL:    v.Param,
			Body:   alertMsg,
		}
	}
}

func genFakeCert(ca tls.Certificate, host string) (tls.Certificate, error) {
	x509CA, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return tls.Certificate{}, err
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
	}
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, x509CA, &certPrivKey.PublicKey, ca.PrivateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{certBytes}, PrivateKey: certPrivKey}, nil
}
