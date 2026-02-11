package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

type NucleiResult struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
	} `json:"info"`
	Type      string `json:"type"`
	Host      string `json:"host"`
	Matched   string `json:"matched-at"`
	IP        string `json:"ip"`
	Timestamp string `json:"timestamp"`
}

func RunNucleiScan(targetURL string) {
	fmt.Printf("☢️  Starting Nuclei Scan on: %s\n", targetURL)

	// แก้ตรงนี้: ใช้ -severity เพื่อดึงข้อมูลทุกระดับ (Info -> Critical)
	cmd := exec.Command("nuclei",
		"-u", targetURL,
		"-json",
		"-silent",
		"-severity", "info,low,medium,high,critical",
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Println("Error creating stdout pipe:", err)
		return
	}

	if err := cmd.Start(); err != nil {
		fmt.Println("Error starting Nuclei:", err)
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		var result NucleiResult
		if err := json.Unmarshal([]byte(line), &result); err == nil {
			reportToDashboard(result)
		}
	}

	cmd.Wait()
	fmt.Printf("✅ Nuclei Scan Finished: %s\n", targetURL)
}

func reportToDashboard(n NucleiResult) {
	evidence := fmt.Sprintf("Template: %s | Matched: %s", n.TemplateID, n.Matched)

	severityIcon := "ℹ️" // Default เป็น Info
	sev := strings.ToLower(n.Info.Severity)

	if sev == "critical" || sev == "high" {
		severityIcon = "🔥"
	} else if sev == "medium" {
		severityIcon = "🟠"
	} else if sev == "low" {
		severityIcon = "⚠️"
	}

	broadcast <- LogEntry{
		Method: severityIcon + " NUCLEI: " + n.Info.Name,
		URL:    n.Host,
		Body:   evidence + "\nSeverity: " + n.Info.Severity,
	}
}
