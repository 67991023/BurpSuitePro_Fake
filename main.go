/*
ห้ามเข้า http://localhost:8080 ตรงๆ:

	ถ้าคุณเอา Chrome ไปเข้าลิงก์นี้ มันจะขึ้น Error หรือหน้าขาวๆ
	เหตุผล: Port 8080 มันถูกออกแบบมาให้ โปรแกรม (Browser) คุยกัน ไม่ได้ออกแบบมาให้ คน ดูครับ
	มันรอรับคำสั่งเชื่อมต่อ (CONNECT) ไม่ใช่คำสั่งขอดูหน้าเว็บ (GET)
*/
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

// --- ฟังก์ชันหลัก ---
func main() {
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

// --- แก้ไข handleHTTPS แบบ "แกะอ่าน" ---
func handleHTTPS(w http.ResponseWriter, r *http.Request, caCert tls.Certificate) {
	// 1-4. (ส่วนเดิม: Hijack connection และ Handshake) ...
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

	// 5. เชื่อมต่อ Server จริง
	destConn, err := tls.Dial("tcp", r.Host, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	defer destConn.Close()

	// =========================================================
	// 🔥 จุดเปลี่ยนสำคัญ: ไม่ใช้ io.Copy ดื้อๆ แล้ว แต่เราจะ "อ่าน" Request
	// =========================================================

	// สร้างตัวอ่านจากท่อที่เข้ารหัสแล้ว
	reader := bufio.NewReader(tlsClientConn)

	// วนลูปอ่าน Request ทีละอัน (เพราะ 1 Connection อาจส่งหลาย Request)
	for {
		// A. แกะซองจดหมาย (Decrypt & Parse HTTP)
		req, err := http.ReadRequest(reader)
		if err != nil {
			break // จบการสนทนา หรือ Error
		}

		// B. 🔍 สแกนตรงนี้เลย!!! (Scan Here)
		// สร้าง URL แบบเต็มๆ (HTTPS)
		targetURL := "https://" + r.Host + req.URL.Path
		if req.URL.RawQuery != "" {
			targetURL += "?" + req.URL.RawQuery
		}

		// --- TRIGGER SCANNER ---
		if req.Method == "GET" && len(req.URL.Query()) > 0 {
			log.Printf("🚀 Scanning HTTPS: %s", targetURL)
			go func(u string) {
				vulnsSQL := ScanSQLInjection(u)
				vulnsXSS := ScanXSS(u)
				broadcastToDashboard(vulnsSQL)
				broadcastToDashboard(vulnsXSS)
			}(targetURL)
		}
		// -----------------------

		// C. ส่ง Log ไปหน้า Dashboard ว่า "ฉันเห็น Request นะ"
		go func() {
			broadcast <- LogEntry{
				Method: "🔒 " + req.Method,
				URL:    targetURL,
				Body:   "(Encrypted Payload Decoded)",
			}
		}()

		// D. ส่งจดหมายต่อไปให้ Server จริง (Re-issue Request)
		// ต้องแก้ Host นิดหน่อยไม่งั้นบางเว็บไม่ยอมรับ
		req.URL.Scheme = "https"
		req.URL.Host = r.Host

		// เขียน Request ลงไปในท่อที่ต่อไป Server
		if err := req.Write(destConn); err != nil {
			break
		}

		// E. อ่านคำตอบ (Response) จาก Server ส่งคืน Browser
		// (แบบง่าย: ใช้ ReadResponse หรือ Copy กลับ)
		resp, err := http.ReadResponse(bufio.NewReader(destConn), req)
		if err != nil {
			break
		}

		// ส่ง Response คืน Browser
		if err := resp.Write(tlsClientConn); err != nil {
			break
		}
	}
}

// --- HTTP Handler ---
// --- HTTP Handler (แก้ใหม่: เพิ่ม Scanner + Forwarding) ---
func handleHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. ส่ง Log ไป Dashboard (ว่ามีการเข้าเว็บ)
	go func() {
		broadcast <- LogEntry{
			Method: r.Method,
			URL:    r.URL.String(),
			Body:   "",
		}
	}()

	// 2. 🔥 จุดที่เพิ่ม: เรียก Scanner ทำงาน!
	if r.Method == "GET" && len(r.URL.Query()) > 0 {
		// สร้าง URL เต็มๆ สำหรับ Scanner
		// หมายเหตุ: ใน Proxy Request r.URL.String() มักจะมาเต็มอยู่แล้ว แต่กันเหนียวไว้ก่อน
		targetURL := r.URL.String()
		if r.URL.Scheme == "" {
			targetURL = "http://" + r.Host + r.URL.Path + "?" + r.URL.RawQuery
		}

		log.Printf("🚀 Scanning HTTP: %s", targetURL) // Log ดูใน Terminal

		go func(u string) {
			vulnsSQL := ScanSQLInjection(u)
			vulnsXSS := ScanXSS(u)
			broadcastToDashboard(vulnsSQL)
			broadcastToDashboard(vulnsXSS)
		}(targetURL)
	}

	// 3. 🔥 จุดที่เพิ่ม: ส่ง Request ต่อไปให้ Server จริง (Forwarding)
	// ถ้าไม่ทำตรงนี้ Browser จะหมุนติ้วๆ หรือหน้าขาว เพราะไม่ได้ข้อมูลเว็บกลับไป

	// ลบ Header ที่เกี่ยวกับ Proxy ออกก่อนส่งต่อ (กัน Server งง)
	r.RequestURI = ""

	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, "Error fetching: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	// Copy Header จาก Server จริง ส่งคืนให้ Browser
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	// ส่ง Status Code และ Body คืน Browser
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// --- Transfer ---
func transfer(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()
	io.Copy(dst, src)
}

// --- [ฟังก์ชันใหม่] เครื่องปั๊ม Cert ปลอม ---
func genFakeCert(ca tls.Certificate, host string) (tls.Certificate, error) {
	// 1. แกะ CA ออกมาเตรียมเซ็น
	x509CA, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return tls.Certificate{}, err
	}

	// 2. สร้างแม่พิมพ์ใบรับรองใหม่
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: host, // <--- จุดสำคัญ: ปลอมชื่อเป็นเว็บที่เหยื่อเข้า
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour), // อายุ 1 วัน

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host}, // <--- จุดสำคัญ: ระบุชื่อโดเมน
	}

	// 3. สร้างกุญแจลับ (Private Key) สำหรับ Cert ปลอมใบนี้
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	// 4. เซ็นรับรอง! (เอาแม่พิมพ์ + กุญแจ CA มาปั๊มออกมาเป็นไฟล์ Cert)
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, x509CA, &certPrivKey.PublicKey, ca.PrivateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	// 5. ประกอบร่างกลับเป็น tls.Certificate เพื่อเอาไปใช้
	return tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  certPrivKey,
	}, nil
}

// --- เพิ่มท้ายไฟล์ main.go ---

func broadcastToDashboard(vulns []Vulnerability) {
	for _, v := range vulns {
		// จัดรูปแบบข้อความแจ้งเตือน
		alertMsg := fmt.Sprintf("ความรุนแรง: %s | หลักฐาน: %s", v.Severity, v.Evidence)

		// ส่งเข้า WebSocket
		broadcast <- LogEntry{
			Method: "🔥 " + v.Type, // เช่น "🔥 SQL Injection"
			URL:    v.Param,       // แสดง Parameter ที่มีปัญหา
			Body:   alertMsg,
		}
	}
}
