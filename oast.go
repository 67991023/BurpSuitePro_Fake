package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/interactsh/pkg/server"
)

type OASTService struct {
	Client      *client.Client
	InteractURL string
}

func StartOAST() (*OASTService, error) {
	// 🛠️ Config แบบ v1.1.8: เปิด DisableEncryption ได้แล้ว!
	opts := &client.Options{
		ServerURL: "https://interact.sh",
	}

	c, err := client.New(opts)
	if err != nil {
		fmt.Println("⚠️ interact.sh failed, trying fallback...")
		// Fallback
		opts.ServerURL = "https://oast.fun"
		c, err = client.New(opts)
		if err != nil {
			return nil, fmt.Errorf("OAST Connection Failed: %v", err)
		}
	}

	URL := c.URL()
	fmt.Printf("🕵️‍♂️ OAST Service Started! Trap URL: %s\n", URL)

	service := &OASTService{
		Client:      c,
		InteractURL: URL,
	}

	go service.pollInteractions()

	return service, nil
}

func (s *OASTService) pollInteractions() {
	s.Client.StartPolling(time.Duration(5)*time.Second, func(interaction *server.Interaction) {
		// ดึงข้อมูล
		protocol := interaction.Protocol
		remoteIP := interaction.RemoteAddress
		rawReq := interaction.RawRequest
		reqStr := string(rawReq)

		// กรองขยะ (Clean String)
		reqStr = strings.Map(func(r rune) rune {
			if r >= 32 && r <= 126 {
				return r
			}
			return '.'
		}, reqStr)

		if len(reqStr) > 200 {
			reqStr = reqStr[:200] + "..."
		}

		// 🚨 LOG เข้า Terminal
		fmt.Printf("\n🔥🔥🔥 BLIND VULN DETECTED! 🔥🔥🔥\n")
		fmt.Printf("🎯 Protocol: %s\n", protocol)
		fmt.Printf("🌍 Source IP: %s\n", remoteIP)
		fmt.Printf("📦 Data: %s\n", reqStr)
		fmt.Println("----------------------------------------")

		// 🚨 ยิงเข้า Dashboard
		broadcast <- LogEntry{
			Method: "💀 OAST HIT (" + protocol + ")",
			URL:    "Target contacted our Server!",
			Body:   fmt.Sprintf("Source: %s\nData: %s", remoteIP, reqStr),
		}
	})
}

func (s *OASTService) Close() {
	s.Client.Close()
}
