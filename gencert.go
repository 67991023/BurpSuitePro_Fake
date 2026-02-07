/*
สาเหตุจำเป็นต้องเป็น CA เพื่อสร้าง certificate ปลอม สำหรับเข้าถึง https
*/
package main

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
