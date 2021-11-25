package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// Copy TCP data from `src` to `dst`, closing the respective read/write when done
func copyTcp(dst *net.TCPConn, src *net.TCPConn) {
	io.Copy(dst, src)
	dst.CloseWrite()
	src.CloseRead()
}

// Create a TCP connection to `host`
func dialTcp(host string) (*net.TCPConn, error) {
	conn, err := net.DialTimeout("tcp", host, 20*time.Second)
	if err != nil {
		return nil, fmt.Errorf("Dial %v: %w", host, err)
	}
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, errors.New("Dial did not return a TCPConn")
	}
	return tcp, nil
}

// Get the TCP connection from an HTTP connection
func tcpFromHttp(w http.ResponseWriter) (*net.TCPConn, error) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("No hijacker support (using HTTP/2?)")
	}

	conn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return nil, err
	}

	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		conn.Close()
		return nil, errors.New("Hijacker did not return a TCP stream")
	}

	return tcp, nil
}

// Handle an HTTP CONNECT method
func handleConnect(w http.ResponseWriter, r *http.Request) error {
	serverTcp, err := dialTcp(r.Host)
	if err != nil {
		http.Error(w, "", http.StatusBadGateway)
		return fmt.Errorf("dialTcp: %w", err)
	}

	clientTcp, err := tcpFromHttp(w)
	if err != nil {
		serverTcp.Close()
		return fmt.Errorf("tcpFromHttp: %w", err)
	}

	clientTcp.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	go copyTcp(serverTcp, clientTcp)
	go copyTcp(clientTcp, serverTcp)
	return nil
}

type Config struct {
	Hosts []string `json:"hosts"`
}

type handler struct {
	hosts map[string]bool
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "CONNECT" {
		parts := strings.Split(r.Host, ":")
		host := ""
		if len(parts) >= 1 {
			host = parts[0]
		}

		status := "OK"
		_, ok := h.hosts[host]
		if ok {
			err := handleConnect(w, r)
			if err != nil {
				status = err.Error()
			}
		} else {
			http.Error(w, "", http.StatusForbidden)
			status = "Forbidden"
		}

		log.Printf("%s %s -> %s\n", r.Method, r.Host, status)
	} else {
		http.Error(w, "Only CONNECT (HTTPS) is supported", http.StatusMethodNotAllowed)
	}
}

func loadConfig(path string) (Config, error) {
	var config Config
	data, err := ioutil.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(data, &config)
	}
	return config, err
}

func main() {
	config, err := loadConfig("config.json")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	log.Printf("Valid hosts: %v", config.Hosts)

	hosts := make(map[string]bool)
	for _, host := range config.Hosts {
		hosts[host] = true
	}

	h := &handler{
		hosts: hosts,
	}

	s := http.Server{
		Addr:              ":8080",
		Handler:           h,
		ReadTimeout:       120 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 120 * time.Second,
	}

	s.ListenAndServe()
}
