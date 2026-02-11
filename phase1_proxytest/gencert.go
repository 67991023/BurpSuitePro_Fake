/*
สาเหตุจำเป็นต้องเป็น CA เพื่อสร้าง certificate ปลอม สำหรับเข้าถึง https
รันเเค่ครั้งเเรกเพื่อสร้าง ca.key สำหรับประทับตราอนุมัติ" ลงบนบัตรประชาชน (Certificate) ของคนอื่น เพื่อยืนยันว่า "ฉันรับรองคนนี้
เเละสร้าง ca.crt เพื่อเป็นใบเซอร์เอาไว้แจกชาวบ้าน (Browser) เพื่อบอกว่า "ตราประทับหน้าตาแบบนี้ คือตราของฉันนะ ถ้าเห็นตรานี้บนบัตรใคร ให้เชื่อถือได้เลย
ในโปรเจกต์นี้: เราเอา ca.crt ไปติดตั้งใน Chrome/Firefox เพื่อบอก Browser ว่า "จงเชื่อถือตราประทับของ Burp_Project นะ"

สถานการณ์เมื่อใช้ Burp_Project (มี ca.crt/ca.key)

	Browser: "ขอคุยกับ Google หน่อย" (ส่งไปหา Proxy)
	Burp_Project (Proxy): "หยุดก่อน! Browser รอเดี๋ยว..."
	Burp_Project: (แอบสร้างบัตรประชาชนปลอม เขียนชื่อว่า google.com)
	Burp_Project: (ใช้ ca.key ประทับตราลงบนบัตรปลอมใบนั้น) ปึ้ง!
	Burp_Project: ส่งบัตรปลอมกลับไปให้ Browser -> "อ่ะ นี่ Google เองจ้ะ"
	Browser: (ตรวจสอบบัตร) "เอ๊ะ! บัตรนี้ถูกประทับตราโดย Burp_Project Root CA ... ฉันรู้จักไหมนะ?"
	    ถ้าคุณยังไม่ลง ca.crt: Browser จะตะโกนว่า "ไม่ปลอดภัย! (Certificate Error)" เพราะไม่รู้จักคนประทับตรา
	    ถ้าคุณลง ca.crt แล้ว: Browser จะบอกว่า "อ๋อ! ตราประทับของ Burp_Project นี่เอง ฉันถูกสั่งให้เชื่อถือเจ้านี้ งั้นคุยต่อได้เลย"
	ผลลัพธ์: Browser ยอมส่งข้อมูลให้คุณ (Proxy) -> คุณถอดรหัสอ่านได้ -> แล้วค่อยส่งต่อให้ Google จริงๆ
*/
package main

/*
import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"time"
)

func main() {
	// 1. สร้างกุญแจลับ (Private Key) ระดับ RSA 2048-bit
	// เปรียบเหมือน "แม่พิมพ์ตราประทับ" ที่มีแค่เราคนเดียวที่ถือได้ ห้ามทำหาย!
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	// 2. กำหนดรายละเอียดขององค์กร (ใบหน้าบัตร)
	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2024), // เลขซีเรียล
		Subject: pkix.Name{
			Organization: []string{"OpenBurp Architect CA"}, // ชื่อองค์กร (จะโชว์ใน Browser)
			CommonName:   "OpenBurp Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // อายุ 10 ปี
		IsCA:                  true,                         // **สำคัญที่สุด** บอกว่าใบนี้มีสิทธิ์ "ออกใบรับรองให้คนอื่นต่อได้"
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// 3. สร้างใบรับรองจริงๆ (Self-Signed)
	// คือการเอา Template มาเซ็นรับรองด้วย Key ของตัวเอง (เพราะเราเป็นใหญ่ที่สุด ไม่มีใครเซ็นให้เรา)
	caBytes, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		log.Fatal(err)
	}

	// 4. บันทึกไฟล์ ca.crt (Certificate - เอาไว้แจก Browser)
	caOut, _ := os.Create("ca.crt")
	pem.Encode(caOut, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	caOut.Close()

	// 5. บันทึกไฟล์ ca.key (Private Key - เก็บไว้ใช้รันโปรแกรม)
	keyOut, _ := os.Create("ca.key")
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey)})
	keyOut.Close()

	log.Println("✅ สร้างไฟล์ ca.crt และ ca.key เรียบร้อย!")
}

/*
หลังจากได้ ca.crt เเล้ว ต้อง ติดตั้ง CA ลงเครื่อง (Install Trust)
Firefox:
    Settings -> Search "Certificates" -> View Certificates
    Tab "Authorities" -> Import... -> เลือก ca.crt
    ติ๊กถูก "Trust this CA to identify websites" -> OK
*/
