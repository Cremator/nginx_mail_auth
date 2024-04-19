package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/emersion/go-imap/client"
)

const (
	AuthMethodHeader    = "Auth-Method"
	AuthUserHeader      = "Auth-User"
	AuthPassHeader      = "Auth-Pass"
	AuthProtocolHeader  = "Auth-Protocol"
	AuthLoginAttempt    = "Auth-Login-Attempt"
	AuthStatusHeader    = "Auth-Status"
	AuthServerHeader    = "Auth-Server"
	AuthPortHeader      = "Auth-Port"
	AuthWaitHeader      = "Auth-Wait"
	AuthErrorCodeHeader = "Auth-Error-Code"
)

var (
	port                int
	maxLoginAttempts    int
	maxInvalidAttempts  int
	imapServerAddresses stringSlice
	smtpServerAddresses stringSlice
	invalidAttempts     = make(map[string]int)
)

type stringSlice []string

func (ss *stringSlice) String() string {
	return strings.Join(*ss, ", ")
}

func (ss *stringSlice) Set(value string) error {
	*ss = append(*ss, value)
	return nil
}

func init() {
	flag.IntVar(&port, "port", 9143, "Port to listen on")
	flag.IntVar(&maxLoginAttempts, "maxloginattempts", 20, "Max login attempts")
	flag.IntVar(&maxInvalidAttempts, "maxinvalidattempts", 10, "Max invalid attempts")
	flag.Var(&imapServerAddresses, "imap", "IMAP server addresses (format: host:port,host:port...)")
	flag.Var(&smtpServerAddresses, "smtp", "SMTP server addresses (format: host:port,host:port...)")
	flag.Parse()

	if len(imapServerAddresses) == 0 || len(smtpServerAddresses) == 0 {
		fmt.Println("Please provide at least one IMAP and SMTP server address")
		flag.PrintDefaults()
		os.Exit(1)
	}
	log.Printf("IMAP servers: %v", imapServerAddresses)
	log.Printf("SMTP servers: %v", smtpServerAddresses)
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go handleSignals(cancel)

	server := startServer(ctx)
	<-ctx.Done()
	server.Shutdown(ctx)
}

func startServer(ctx context.Context) *http.Server {
	server := &http.Server{
		Addr:    ":" + strconv.Itoa(port),
		Handler: http.HandlerFunc(authHandler),
	}

	go func() {
		log.Printf("Server listening on port %d...\n", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	go func() {
		<-ctx.Done()
		if err := server.Shutdown(context.Background()); err != nil {
			log.Fatalf("Failed to shutdown server: %v", err)
		}
		log.Println("Server shut down")
	}()

	return server
}

func handleSignals(cancel context.CancelFunc) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	log.Println("Received termination signal. Shutting down...")
	cancel()
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Request Header: %#v\n", r.Header)
	authMethod := r.Header.Get(AuthMethodHeader)
	if authMethod == "" || authMethod != "plain" {
		http.Error(w, "Invalid or missing Auth-Method", http.StatusBadRequest)
		return
	}

	authUser := r.Header.Get(AuthUserHeader)
	authPass := r.Header.Get(AuthPassHeader)
	authProtocol := r.Header.Get(AuthProtocolHeader)
	loginAttemptStr := r.Header.Get(AuthLoginAttempt)
	clientIP := r.Header.Get("Client-IP")

	loginAttempt, _ := strconv.Atoi(loginAttemptStr)
	if loginAttempt > maxLoginAttempts {
		http.Error(w, "Too many login attempts", http.StatusUnauthorized)
		log.Printf("Response Header: %#v\n", w.Header())
		return
	}

	invalidAttempts[clientIP]++
	if invalidAttempts[clientIP] > maxInvalidAttempts {
		http.Error(w, "Too many invalid attempts", http.StatusUnauthorized)
		log.Printf("Response Header: %#v\n", w.Header())
		return
	}

	var result authResult
	switch strings.ToLower(authProtocol) {
	case "imap":
		result = authenticateIMAP(authUser, authPass)
	case "smtp":
		result = authenticateSMTP(authUser, authPass)
	default:
		http.Error(w, "Unsupported Auth-Protocol", http.StatusBadRequest)
		return
	}

	if result.err != nil {
		errorMessage := result.err.Error()

		if strings.ToLower(authProtocol) == "smtp" {
			errorMessage = "Temporary server problem, try again later"
			w.Header().Add(AuthErrorCodeHeader, result.err.Error())
		}

		w.Header().Add(AuthStatusHeader, errorMessage)
		w.Header().Add(AuthWaitHeader, "3")

		w.WriteHeader(http.StatusOK)

		log.Printf("Response Header: %#v\n", w.Header())
		return
	}

	w.Header().Add(AuthStatusHeader, "OK")
	w.Header().Add(AuthServerHeader, result.serverAddr)
	w.Header().Add(AuthPortHeader, strconv.Itoa(result.serverPort))
	w.WriteHeader(http.StatusOK)
}

type authResult struct {
	serverAddr string
	serverPort int
	err        error
}

func authenticateIMAP(username, password string) authResult {
	for _, addr := range imapServerAddresses {
		c, err := client.Dial(addr)
		if err != nil {
			continue
		}
		defer c.Logout()

		if err := c.Login(username, password); err == nil {
			host, portStr, _ := net.SplitHostPort(addr)
			port, _ := strconv.Atoi(portStr)
			return authResult{serverAddr: host, serverPort: port}
		}
	}
	return authResult{err: fmt.Errorf("failed to authenticate with any IMAP server")}
}

func authenticateSMTP(username, password string) authResult {
	var res authResult
	for _, addr := range smtpServerAddresses {
		res = authenticateSMTPNet(username, password, addr)
		if res.err == nil {
			return res
		}
	}
	log.Printf("authenticateSMTPNet ERROR: %v\n", res.err)
	return authResult{err: fmt.Errorf("failed to authenticate with any SMTP server")}
}

func authenticateSMTPNet(username, password string, smtpServer string) authResult {
	host, portStr, err := net.SplitHostPort(smtpServer)
	if err != nil {
		return authResult{err: fmt.Errorf("invalid SMTP server address format: %v", err)}
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return authResult{err: fmt.Errorf("invalid SMTP server port: %v", err)}
	}

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return authResult{err: fmt.Errorf("failed to connect to SMTP server: %v", err)}
	}
	defer conn.Close()

	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil {
		return authResult{err: fmt.Errorf("failed to read response from SMTP server: %v", err)}
	}
	respStr := string(resp[:n])

	if !strings.HasPrefix(respStr, "220") {
		return authResult{err: fmt.Errorf("%s", respStr)}
	}

	if _, err := fmt.Fprintf(conn, "EHLO localhost\r\n"); err != nil {
		return authResult{err: fmt.Errorf("failed to send EHLO command: %v", err)}
	}

	n, err = conn.Read(resp)
	if err != nil {
		return authResult{err: fmt.Errorf("failed to read response after EHLO command: %v", err)}
	}
	respStr = string(resp[:n])

	if !strings.Contains(respStr, "AUTH LOGIN") {
		return authResult{err: fmt.Errorf("SMTP server does not support AUTH LOGIN")}
	}

	if _, err := fmt.Fprintf(conn, "AUTH LOGIN\r\n"); err != nil {
		return authResult{err: fmt.Errorf("failed to send AUTH LOGIN command: %v", err)}
	}

	n, err = conn.Read(resp)
	if err != nil {
		return authResult{err: fmt.Errorf("failed to read response after AUTH LOGIN command: %v", err)}
	}
	respStr = string(resp[:n])

	if !strings.HasPrefix(respStr, "334") {
		return authResult{err: fmt.Errorf("%s", respStr)}
	}

	if _, err := fmt.Fprintf(conn, "%s\r\n", base64.StdEncoding.EncodeToString([]byte(username))); err != nil {
		return authResult{err: fmt.Errorf("failed to send username: %v", err)}
	}

	n, err = conn.Read(resp)
	if err != nil {
		return authResult{err: fmt.Errorf("failed to read response after sending username: %v", err)}
	}
	respStr = string(resp[:n])

	if !strings.HasPrefix(respStr, "334") {
		return authResult{err: fmt.Errorf("%s", respStr)}
	}

	if _, err := fmt.Fprintf(conn, "%s\r\n", base64.StdEncoding.EncodeToString([]byte(password))); err != nil {
		return authResult{err: fmt.Errorf("failed to send password: %v", err)}
	}

	n, err = conn.Read(resp)
	if err != nil {
		return authResult{err: fmt.Errorf("failed to read final response after sending password: %v", err)}
	}
	respStr = string(resp[:n])

	if !strings.HasPrefix(respStr, "235") {
		return authResult{err: fmt.Errorf("%s", respStr)}
	}

	return authResult{serverAddr: host, serverPort: port}
}
