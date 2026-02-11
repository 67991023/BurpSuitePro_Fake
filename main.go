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
	"sync" // <--- เพิ่มตัวนี้
	"time"

	"github.com/gorilla/websocket"
)

// --- ส่วนของการตั้งค่า WebSocket ---
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

var broadcast = make(chan LogEntry)

type LogEntry struct {
	Method string `json:"method"`
	URL    string `json:"url"`
	Body   string `json:"body"`
}

// --- ส่วนจัดการ State (แก้เรื่อง Map Crash) ---
var (
	scannedHosts = make(map[string]bool)
	hostsMutex   sync.Mutex // <--- กุญแจล็อค Map
)

var oastService *OASTService

// ฟังก์ชันช่วยเช็คว่าสแกนไปหรือยัง (Thread-Safe)
func shouldScan(host string) bool {
	hostsMutex.Lock()
	defer hostsMutex.Unlock()

	if scannedHosts[host] {
		return false // สแกนไปแล้ว ไม่ต้องทำซ้ำ
	}
	scannedHosts[host] = true // จดว่ากำลังจะสแกน
	return true
}

// --- ฟังก์ชันหลัก ---
func main() {

	// 1. เริ่ม OAST Service ก่อนเลย
	var err error
	oastService, err = StartOAST()
	if err != nil {
		log.Println("⚠️ Failed to start OAST service:", err)
		log.Println("⚠️ Blind Scan will be disabled.")
	} else {
		defer oastService.Close()
		log.Println("✅ OAST Service Ready! Polling for callbacks...")
	}
	// 1. โหลดบัตรประชาชนเจ้าหน้าที่ (CA)
	caCert, err := tls.LoadX509KeyPair("ca.crt", "ca.key")
	if err != nil {
		log.Fatal("โหลด Cert ไม่ได้:", err)
	}

	// 2. เริ่ม Dashboard
	go startDashboardServer()

	// 3. เริ่ม Proxy
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

// --- Dashboard Server ---
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

// --- handleHTTPS ---
func handleHTTPS(w http.ResponseWriter, r *http.Request, caCert tls.Certificate) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	host, _, _ := net.SplitHostPort(r.Host)
	fakeCert, err := genFakeCert(caCert, host)
	if err != nil {
		return
	}

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

		targetURL := "https://" + r.Host + req.URL.Path
		if req.URL.RawQuery != "" {
			targetURL += "?" + req.URL.RawQuery
		}

		// --- TRIGGER SCANNER (SQLi/XSS) ---
		if req.Method == "GET" && len(req.URL.Query()) > 0 {
			log.Printf("🚀 Scanning HTTPS: %s", targetURL)
			go func(u string) {
				vulnsSQL := ScanSQLInjection(u)
				vulnsXSS := ScanXSS(u)
				broadcastToDashboard(vulnsSQL)
				broadcastToDashboard(vulnsXSS)

				// 🔥 เพิ่มตรงนี้: BLIND SCAN (OAST) 🔥
				if oastService != nil {
					RunOASTScan(u, oastService.InteractURL)
				}
			}(targetURL)
		}

		// --- TRIGGER NUCLEI (ใช้ฟังก์ชัน Safe Check) ---
		if shouldScan(r.Host) {
			go func(target string) {
				fullTarget := "https://" + target
				RunNucleiScan(fullTarget)
			}(r.Host)
		}

		go func() {
			broadcast <- LogEntry{
				Method: "🔒 " + req.Method,
				URL:    targetURL,
				Body:   "(Encrypted Payload Decoded)",
			}
		}()

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

// --- handleHTTP ---
func handleHTTP(w http.ResponseWriter, r *http.Request) {
	go func() {
		broadcast <- LogEntry{
			Method: r.Method,
			URL:    r.URL.String(),
			Body:   "",
		}
	}()

	if r.Method == "GET" && len(r.URL.Query()) > 0 {
		targetURL := r.URL.String()
		if r.URL.Scheme == "" {
			targetURL = "http://" + r.Host + r.URL.Path + "?" + r.URL.RawQuery
		}

		log.Printf("🚀 Scanning HTTP: %s", targetURL)

		go func(u string) {
			vulnsSQL := ScanSQLInjection(u)
			vulnsXSS := ScanXSS(u)
			broadcastToDashboard(vulnsSQL)
			broadcastToDashboard(vulnsXSS)

			// 🔥 เพิ่มตรงนี้: BLIND SCAN (OAST) 🔥
			if oastService != nil {
				RunOASTScan(u, oastService.InteractURL)
			}
		}(targetURL)
	}

	// --- TRIGGER NUCLEI (ใช้ฟังก์ชัน Safe Check) ---
	if shouldScan(r.Host) {
		go func(target string) {
			fullTarget := "http://" + target
			if r.TLS != nil {
				fullTarget = "https://" + target
			}
			RunNucleiScan(fullTarget)
		}(r.Host)
	}

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

func genFakeCert(ca tls.Certificate, host string) (tls.Certificate, error) {
	x509CA, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return tls.Certificate{}, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),

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

	return tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  certPrivKey,
	}, nil
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
