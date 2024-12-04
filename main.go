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
	"sync"
	"syscall"
	"time"

	"github.com/emersion/go-imap/client"
)

type stringSlice []string

func (ss *stringSlice) String() string {
	return strings.Join(*ss, ", ")
}

func (ss *stringSlice) Set(value string) error {
	*ss = append(*ss, value)
	return nil
}

// Attempts represents a count with TTL
type InvalidAttempts struct {
	Count      int
	Expiration time.Time
}

// Store struct using sync.Map
type InvalidStore struct {
	store sync.Map
}

// Set a value in the store
func (st *InvalidStore) Set(key string, value InvalidAttempts) {
	st.store.Store(key, value)
}

// Get a value by key from the store
func (st *InvalidStore) Get(key string) (InvalidAttempts, bool) {
	val, ok := st.store.Load(key)
	ival := InvalidAttempts{Count: 0, Expiration: time.Now()}
	if ok {
		InvalidAttemptsV := val.(InvalidAttempts)
		if InvalidAttemptsV.Expiration.IsZero() || time.Now().After(InvalidAttemptsV.Expiration) {
			st.Delete(key)
			ok = false
		}
		ival = InvalidAttemptsV
	}
	return ival, ok
}

// Delete a value by key from the store
func (st *InvalidStore) Delete(key string) {
	st.store.Delete(key)
}

// Walk the map and delete expired keys
func (st *InvalidStore) Expire() int {
	i := 0
	st.store.Range(func(k, v interface{}) bool {
		key := k.(string)
		if _, d := st.Get(key); !d {
			i++
		}
		return true
	})

	return i
}

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
	port                     int
	maxLoginAttempts         int
	maxInvalidAttempts       int
	useImapOnly              bool
	imapServerAddresses      stringSlice
	smtpServerAddresses      stringSlice
	invalidAttemptsStore     InvalidStore
	invalidMailAttemptsStore InvalidStore
	invalidDuration          time.Duration
)

func init() {
	flag.IntVar(&port, "port", 9143, "Port to listen on")
	flag.IntVar(&maxLoginAttempts, "maxloginattempts", 20, "Max login attempts")
	flag.IntVar(&maxInvalidAttempts, "maxinvalidattempts", 5, "Max invalid attempts")
	flag.BoolVar(&useImapOnly, "useimaponly", false, "Use only IMAP for authenticating both IMAP & SMTP")
	flag.DurationVar(&invalidDuration, "invalidduration", time.Minute*5, "Blocked IP addresses are cleaned up after this period")
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
	// log.Printf("Debug: %#v\n", invalidAttemptsStore.data)
	i := invalidAttemptsStore.Expire()
	if i > 0 {
		log.Printf("Successfully expired %d invalid IP record(s).\n", i)
	}
	m := invalidMailAttemptsStore.Expire()
	if m > 0 {
		log.Printf("Successfully expired %d invalid Mail record(s).\n", m)
	}
	log.Printf("Request Header: %#v\n", r.Header)
	authMethod := r.Header.Get(AuthMethodHeader)
	if authMethod == "" || authMethod != "plain" {
		http.Error(w, "Invalid or missing Auth-Method", http.StatusBadRequest)
		log.Printf("Response Header Auth-Method: %#v\n", w.Header())
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
		log.Printf("Response Header Login: %#v\n", w.Header())
		return
	}

	record, ok := invalidAttemptsStore.Get(clientIP)
	if ok {
		record.Expiration = time.Now().Add(invalidDuration)
		record.Count++
		log.Printf("Invalid auth attemp # %d for IP: %s\n", record.Count, clientIP)
	} else {
		record = InvalidAttempts{Count: 1, Expiration: time.Now().Add(invalidDuration)}
	}
	invalidAttemptsStore.Set(clientIP, record)

	if record.Count > maxInvalidAttempts {
		http.Error(w, "Too many invalid attempts", http.StatusUnauthorized)
		log.Printf("Response Header Invalid IP: %#v\n", w.Header())
		return
	}

	mrecord, mok := invalidMailAttemptsStore.Get(authUser)
	if mok {
		mrecord.Expiration = time.Now().Add(invalidDuration)
		mrecord.Count++
		log.Printf("Invalid auth attemp # %d for mail: %s\n", mrecord.Count, authUser)
	} else {
		mrecord = InvalidAttempts{Count: 1, Expiration: time.Now().Add(invalidDuration)}
	}
	invalidMailAttemptsStore.Set(authUser, mrecord)

	if mrecord.Count >= maxInvalidAttempts {
		http.Error(w, "Too many invalid attempts", http.StatusUnauthorized)
		log.Printf("Response Header Invalid Mail: %#v\n", w.Header())
		return
	}

	var result authResult
	if useImapOnly && authProtocol == "smtp" {
		authProtocol = "imap"
	}
	switch strings.ToLower(authProtocol) {
	case "imap":
		result = authenticateIMAP(authUser, authPass)
	case "smtp":
		result = authenticateSMTP(authUser, authPass)
	default:
		http.Error(w, "Unsupported Auth-Protocol", http.StatusBadRequest)
		log.Printf("Response Header Auth-Protocol: %#v\n", w.Header())
		return
	}

	if result.err != nil {
		errorMessage := result.err.Error()

		if strings.ToLower(authProtocol) == "smtp" {
			errorMessage = "Temporary server problem, try again later"
			w.Header().Add(AuthErrorCodeHeader, result.err.Error())
		}

		w.Header().Add(AuthStatusHeader, errorMessage)
		w.Header().Add(AuthWaitHeader, strconv.Itoa(record.Count*3))

		w.WriteHeader(http.StatusOK)

		log.Printf("Response Header Error: %#v\n", w.Header())
		return
	}
	invalidAttemptsStore.Delete(clientIP)
	w.Header().Add(AuthStatusHeader, "OK")
	w.Header().Add(AuthServerHeader, result.serverAddr)
	w.Header().Add(AuthPortHeader, strconv.Itoa(result.serverPort))
	w.WriteHeader(http.StatusOK)
	log.Printf("Response Header OK: %#v\n", w.Header())
}

type authResult struct {
	serverAddr string
	serverPort int
	serverType string
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
			return authResult{serverAddr: host, serverPort: port, serverType: "imap"}
		}
	}
	return authResult{err: fmt.Errorf("failed to authenticate")}
}

func authenticateSMTP(username, password string) authResult {
	var res authResult
	for _, addr := range smtpServerAddresses {
		res = authenticateSMTPNet(username, password, addr)
		if res.err == nil {
			res.serverType = "smtp"
			return res
		}
	}
	log.Printf("authenticateSMTPNet ERROR: %v\n", res.err)
	return authResult{err: fmt.Errorf("failed to authenticate")}
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
