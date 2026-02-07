// go mod init openburp => สร้างไฟล์ go.mod คอยบันทึกว่าเราใช้ Library อะไร
// สร้างด่านตรวจ

/*
Go cheatsheet
คำสั่ง,ความหมาย
"fmt.Println(""ข้อความ"")",พิมพ์ข้อความลงหน้าจอ (ทั่วไป)
"log.Println(""ข้อความ"")",พิมพ์ข้อความ + วันที่และเวลา (เหมาะทำ Log)
"log.Printf(""ไฟล์: %s"", name)","พิมพ์แบบแทรกตัวแปรได้ (%s=ข้อความ, %d=ตัวเลข, %v=อะไรก็ได้)"
"log.Fatal(""ข้อความ"")",พิมพ์ Error แล้วปิดโปรแกรมทันที (ใช้ตอนเริ่มรันแล้วพัง)
"panic(""ข้อความ"")",ตกใจสุดขีด! หยุดโปรแกรมทันที (ใช้ตอนเจอ Error ที่แก้ไม่ได้จริงๆ)

สัญลักษณ์,ความหมาย
:=,สร้างตัวแปรใหม่พร้อมกำหนดค่า (Short Declaration)
&,เอาที่อยู่ Memory (Address of)
*,ตัวแปรนี้เป็น Pointer (ชี้ไปที่ Address)
[]byte,ข้อมูลดิบ (Raw Data) ภาษาคอมพิวเตอร์ (ไม่ใช่ตัวหนังสือ)
nil,ว่างเปล่า / ไม่มีค่า / Null

คำสั่ง,ความหมาย
func,ประกาศฟังก์ชัน
return,ส่งค่ากลับออกจากฟังก์ชัน
defer,"""เอาไว้ทำตอนจบ"" (เช่น defer file.Close() = สั่งไว้ก่อนเลยว่า ถ้าจบฟังก์ชันนี้เมื่อไหร่ ให้ปิดไฟล์นี้ด้วยนะ กันลืม)"
go,สั่งให้ฟังก์ชันทำงานแยกออกไปเป็นอีก Thread นึง (Goroutine)
if err != nil,"ประโยคศักดิ์สิทธิ์: ""ถ้ามี Error..."""
*/
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"
)

// ตัวแปร Global เอาไว้เก็บตราประทับ (CA) ที่เราโหลดมา
var caCert *x509.Certificate
var caKey *rsa.PrivateKey

func main() {
	// --- STEP 1: โหลด CA เข้ามาในเมมโมรี่ ---
	// เราต้องโหลด ca.crt และ ca.key ที่สร้างไว้เมื่อกี้ เพื่อเตรียมเซ็นรับรองเว็บปลอม
	cert, err := tls.LoadX509KeyPair("ca.crt", "ca.key")
	if err != nil {
		log.Fatal("❌ ไม่เจอไฟล์ CA! รัน gencert.go หรือยังครับ?: ", err)
	}
	// แปลงให้อยู่ในรูปแบบที่ใช้งานง่าย (Parse)
	caCert, _ = x509.ParseCertificate(cert.Certificate[0])
	caKey = cert.PrivateKey.(*rsa.PrivateKey)

	// --- STEP 2: สร้าง Proxy Server ---
	server := &http.Server{
		Addr: ":8080", // เปิด Port 8080
		// Handler คือฟังก์ชันที่จะทำงานทุกครั้งที่มี Request เข้ามา
		Handler: http.HandlerFunc(handleProxy),
	}

	log.Println("OpenBurp Proxy Started on 127.0.0.1:8080")
	log.Fatal(server.ListenAndServe()) // รันยาวๆ จนกว่าจะกด Ctrl+C
}

// ฟังก์ชันแยกประเภท Request
func handleProxy(w http.ResponseWriter, r *http.Request) {
	// ถ้า Method เป็น CONNECT แปลว่า Browser ขอทำ Tunnel เพื่อเล่น HTTPS
	if r.Method == http.MethodConnect {
		handleHTTPS(w, r)
	} else {
		// ถ้าเป็น HTTP ธรรมดา (ไม่ค่อยเจอแล้วในโลกปัจจุบัน แต่ต้องมี)
		handleHTTP(w, r)
	}
}

// --- Logic จัดการ HTTP (แบบไม่เข้ารหัส) ---
func handleHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("[HTTP] %s %s", r.Method, r.URL)

	// ส่ง Request ต่อไปหา Server ปลายทาง
	r.RequestURI = "" // ต้องลบ URI ออก ไม่งั้น Go จะงงเวลาส่งต่อ
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()

	// ก๊อปปี้ Header จาก Server ปลายทาง ส่งคืน Browser
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body) // ส่งเนื้อหา Body กลับไป
}

// --- Logic จัดการ HTTPS (Man-In-The-Middle) - ยากและสำคัญที่สุด ---
func handleHTTPS(w http.ResponseWriter, r *http.Request) {
	log.Printf("[HTTPS Intercept] กำลังเจาะเข้า: %s", r.Host)

	// 1. Hijack: ยึดท่อ Connection มาจาก Go Library
	// ปกติ Go จะจัดการปิด Connection ให้ แต่เราบอกว่า "ไม่ต้อง เดี๋ยวเราคุยต่อเอง"
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}

	// 2. บอก Browser ว่า "โอเค เชื่อมต่อได้"
	// Browser จะนึกว่ามันต่อกับ Server ปลายทางสำเร็จแล้ว (แต่จริงๆ ต่อกับเรา)
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// 3. สร้าง Certificate ปลอม (On-the-fly)
	// เราดูว่า Browser ขอเข้าเว็บอะไร (r.Host) แล้วรีบสร้าง Cert ปลอมชื่อนั้นเดี๋ยวนั้นเลย
	host, _, _ := net.SplitHostPort(r.Host)
	fakeCert := generateFakeCert(host)

	// 4. แปลงร่างเป็น Server ปลอม (TLS Handshake)
	// เราเอา Cert ปลอมใส่ตัว แล้วเริ่มคุยภาษาเข้ารหัสกับ Browser
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{fakeCert}}
	tlsClientConn := tls.Server(clientConn, tlsConfig)

	// บังคับ Handshake ทันที ถ้าผ่านแปลว่า Browser เชื่อ Cert ปลอมเรา
	if err := tlsClientConn.Handshake(); err != nil {
		log.Printf("❌ Browser จับได้! Handshake ล้มเหลว: %v", err)
		clientConn.Close()
		return
	}

	// 5. เชื่อมต่อกับ Server ตัวจริง
	// InsecureSkipVerify: true คือบอกให้โปรแกรมเราไม่ต้องเช็ค Cert ของเว็บจริง
	// (เพื่อให้เราดักจับเว็บที่มีปัญหา Cert ได้เหมือน Burp)
	destConn, err := tls.Dial("tcp", r.Host, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		log.Printf("❌ ต่อเน็ตไม่ได้: %v", err)
		tlsClientConn.Close()
		return
	}

	// 6. ต่อท่อคู่ (Tunneling)
	// สร้าง Goroutine (Thread) เพื่อส่งข้อมูล 2 ทางพร้อมกัน
	go transfer(destConn, tlsClientConn) // ขาไป: Browser -> เรา -> Server
	go transfer(tlsClientConn, destConn) // ขากลับ: Server -> เรา -> Browser
}

// ฟังก์ชันส่งถ่ายข้อมูล (เหมือนคนส่งของ)
func transfer(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()
	// ในอนาคต เราจะเปลี่ยน io.Copy เป็นฟังก์ชันอ่านและแก้ไขข้อมูล (Scanner)
	io.Copy(dst, src)
}

// ฟังก์ชันผลิต Cert ปลอม (Helper Function)
func generateFakeCert(host string) tls.Certificate {
	// สร้าง Serial Number มั่วๆ
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	// กำหนดหน้าตา Cert ปลอม ให้ชื่อ (CommonName) ตรงกับเว็บที่ Browser ขอ
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{Organization: []string{"OpenBurp Fake Org"}, CommonName: host},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host}, // จุดสำคัญ! ต้องระบุ DNS Name ให้ตรง
	}

	// สร้างกุญแจสำหรับ Cert ปลอม
	certPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// **ไฮไลท์**: เซ็นรับรอง Cert ปลอมด้วย "caCert" และ "caKey" (ตราประทับแม่) ของเรา
	certBytes, _ := x509.CreateCertificate(rand.Reader, &template, caCert, &certPrivKey.PublicKey, caKey)

	// ห่อของขวัญส่งกลับไป
	return tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  certPrivKey,
	}
}

/*
ตั้งค่า Browser (Firefox)
    เปิด Firefox -> Settings
    ช่องค้นหาพิมพ์ "Proxy" -> กด Settings...
    เลือก Manual proxy configuration
    ช่อง HTTP Proxy: พิมพ์ 127.0.0.1 Port: 8080   เป็นการบังคับให้ส่งของทุกอย่างมาที่ 127.0.0.1 หรือก็คือ localhost
    ติ๊กถูก Also use this proxy for HTTPS
    สำคัญ: ลบข้อความในช่อง "No proxy for" ให้หมดเกลี้ยง
    กด OK
*/
