package probe

import (
	"bufio"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

const winRMIdentifyRequest = `<?xml version="1.0" encoding="UTF-8"?>` +
	`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">` +
	`<s:Header/><s:Body><wsmid:Identify xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd"/>` +
	`</s:Body></s:Envelope>`

type winrmProbe struct{}

func (winrmProbe) Name() string { return "winrm" }

func (winrmProbe) Probe(_ context.Context, connection net.Conn, target Target) (string, error) {
	return probeWinRM(connection, target)
}

func probeWinRM(connection net.Conn, target Target) (string, error) {
	request, err := http.NewRequest(
		http.MethodPost,
		"http://"+net.JoinHostPort(target.Host, fmt.Sprint(target.Port))+"/wsman",
		strings.NewReader(winRMIdentifyRequest),
	)
	if err != nil {
		return "", fmt.Errorf("build WinRM Identify request: %w", err)
	}
	request.Header.Set("Connection", "close")
	request.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	request.Header.Set("User-Agent", "go-port-scanner")
	request.Header.Set("WSMANIDENTIFY", "unauthenticated")
	if err := request.Write(connection); err != nil {
		return "", fmt.Errorf("send WinRM Identify request: %w", err)
	}

	response, err := http.ReadResponse(bufio.NewReader(connection), request)
	if err != nil {
		return "", fmt.Errorf("read WinRM Identify response: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		return "", fmt.Errorf("read WinRM response body: %w", err)
	}

	var envelope struct {
		Body struct {
			Identify struct {
				ProtocolVersion string `xml:"ProtocolVersion"`
				ProductVendor   string `xml:"ProductVendor"`
				ProductVersion  string `xml:"ProductVersion"`
			} `xml:"IdentifyResponse"`
		} `xml:"Body"`
	}
	if xml.Unmarshal(body, &envelope) == nil && envelope.Body.Identify.ProtocolVersion != "" {
		detail := envelope.Body.Identify.ProductVendor
		if envelope.Body.Identify.ProductVersion != "" {
			detail += " " + envelope.Body.Identify.ProductVersion
		}
		if strings.TrimSpace(detail) == "" {
			detail = "WS-Management IdentifyResponse"
		}
		return cleanDetail(detail), nil
	}

	authentication := strings.Join(response.Header.Values("WWW-Authenticate"), ", ")
	if response.StatusCode == http.StatusUnauthorized && containsWindowsAuthentication(authentication) {
		return fmt.Sprintf("HTTP 401 authentication challenge (%s)", cleanDetail(authentication)), nil
	}
	return "", fmt.Errorf("response is not identified as WinRM (HTTP %d)", response.StatusCode)
}

func containsWindowsAuthentication(value string) bool {
	value = strings.ToLower(value)
	return strings.Contains(value, "negotiate") || strings.Contains(value, "ntlm") || strings.Contains(value, "kerberos")
}
