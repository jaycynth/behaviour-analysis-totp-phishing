package utils

import (
	"bytes"
	"fmt"
	"net/http"
	"net/smtp"
	"os"
)

func SendSlackAlert(message string) error {
	webhookURL := os.Getenv("SLACK_WEBHOOK_URL")
	if webhookURL == "" {
		return fmt.Errorf("SLACK_WEBHOOK_URL is not set")
	}

	jsonStr := `{"text":"` + message + `"}`
	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer([]byte(jsonStr)))
	if err != nil {
		return fmt.Errorf("failed to send Slack alert: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("Slack alert failed with status code: %d", resp.StatusCode)
	}

	fmt.Println("Slack alert sent successfully")
	return nil
}

func SendEmailAlert(to, message string) error {
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	smtpUser := os.Getenv("SMTP_USER")
	smtpPass := os.Getenv("SMTP_PASSWORD")

	if smtpHost == "" || smtpPort == "" || smtpUser == "" || smtpPass == "" {
		return fmt.Errorf("SMTP configuration is incomplete")
	}

	auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)
	msg := []byte("Subject: Phishing Alert!\n\n" + message)

	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, smtpUser, []string{to}, msg)
	if err != nil {
		return fmt.Errorf("failed to send email alert: %w", err)
	}

	fmt.Println("Email sent successfully to:", to)
	return nil
}
