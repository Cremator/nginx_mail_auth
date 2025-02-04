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
	"github.com/zeebo/blake3"
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

// Constants used for headers
const (
	AuthMethodHeader    = "Auth-Method"        // HTTP header to specify the authentication method
	AuthUserHeader      = "Auth-User"          // HTTP header to provide the username
	AuthPassHeader      = "Auth-Pass"          // HTTP header to provide the password
	AuthProtocolHeader  = "Auth-Protocol"      // HTTP header to specify the protocol (e.g., IMAP, SMTP)
	AuthLoginAttempt    = "Auth-Login-Attempt" // HTTP header indicating a login attempt
	AuthStatusHeader    = "Auth-Status"        // HTTP header to indicate success or failure of authentication
	AuthServerHeader    = "Auth-Server"        // HTTP header to specify the server for the protocol
	AuthPortHeader      = "Auth-Port"          // HTTP header to specify the port number
	AuthWaitHeader      = "Auth-Wait"          // HTTP header to indicate waiting period before next attempt
	AuthErrorCodeHeader = "Auth-Error-Code"    // HTTP header to return error codes
)

var (
	port                     int           // Port number on which the server listens for incoming connections
	maxLoginAttempts         int           // Maximum allowed login attempts per user or IP address
	maxInvalidAttempts       int           // Maximum number of invalid attempts before blocking
	useImapOnly              bool          // Whether to use IMAP only for authenticating both IMAP and SMTP protocols
	useImapOnlyPort          int           // Port number when using IMAP only, typically used for SMTP as well
	imapServerAddresses      stringSlice   // List of IMAP server addresses in host:port format
	smtpServerAddresses      stringSlice   // List of SMTP server addresses in host:port format
	invalidAttemptsStore     InvalidStore  // Store tracking invalid login attempts with their counts and expiration times
	invalidMailAttemptsStore InvalidStore  // Store tracking invalid mail-related attempts, similar to invalidAttemptsStore
	invalidDuration          time.Duration // Duration for which IP addresses are blocked after reaching maxInvalidAttempts
)

// Initialize variables from command-line flags or default values
func init() {
	flag.IntVar(&port, "port", 9143, "Port to listen on")                                                                         // Set default port and parse the --port flag
	flag.IntVar(&maxLoginAttempts, "maxloginattempts", 20, "Max login attempts allowed")                                          // Maximum number of allowed login attempts per user or IP
	flag.IntVar(&maxInvalidAttempts, "maxinvalidattempts", 5, "Max invalid attempts before blocking")                             // Threshold for blocking after too many failed attempts
	flag.IntVar(&useImapOnlyPort, "useimaponlyport", 25, "Use only IMAP for authenticating both IMAP & SMTP - SMTP port")         // Port when using IMAP-only authentication
	flag.BoolVar(&useImapOnly, "useimaponly", false, "Use only IMAP for authenticating both IMAP & SMTP")                         // Toggle to use IMAP for all authentication tasks
	flag.DurationVar(&invalidDuration, "invalidduration", time.Minute*5, "Blocked IP addresses are cleaned up after this period") // Time before blocked IPs are cleared
	flag.Var(&imapServerAddresses, "imap", "IMAP server addresses (format: host:port,host:port...)")                              // Collect IMAP server addresses from flags
	flag.Var(&smtpServerAddresses, "smtp", "SMTP server addresses (format: host:port,host:port...)")                              // Collect SMTP server addresses from flags

	flag.Parse() // Parse all command-line flags

	// Validate that at least one IMAP and SMTP server is provided
	if len(imapServerAddresses) == 0 || len(smtpServerAddresses) == 0 {
		fmt.Println("Please provide at least one IMAP and SMTP server address") // Error message if no servers are specified
		flag.PrintDefaults()                                                    // Print default help message showing all flags
		os.Exit(1)                                                              // Exit with error code 1 due to missing required parameters
	}

	// Log configuration details for verification
	log.Printf("IMAP servers: %v", imapServerAddresses)
	log.Printf("SMTP servers: %v", smtpServerAddresses)
	log.Printf("useImapOnly: %v", useImapOnly)
	log.Printf("invalidDuration: %v", invalidDuration)
	log.Printf("maxInvalidAttempts: %v", maxInvalidAttempts)
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

func hashBlake3(s string) string {
	hash_byte := blake3.Sum256([]byte(s))
	return fmt.Sprintf("%x", hash_byte[0:15])
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
	id := hashBlake3(fmt.Sprint(r.Header.Get(AuthUserHeader), r.Header.Get(AuthProtocolHeader), r.Header.Get("Client-IP")))
	log.Printf("%s|Request Header: %#v\n", id, r.Header)
	authMethod := r.Header.Get(AuthMethodHeader)
	if authMethod == "" || authMethod != "plain" {
		http.Error(w, "Invalid or missing Auth-Method", http.StatusBadRequest)
		log.Printf("%s|Response Header Auth-Method: %#v\n", id, w.Header())
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
		log.Printf("%s|Response Header Login: %#v\n", id, w.Header())
		return
	}

	record, ok := invalidAttemptsStore.Get(clientIP)
	if ok {
		record.Expiration = record.Expiration.Add(invalidDuration)
		record.Count++
		log.Printf("%s|Invalid auth attemp # %d for IP: %s\n", id, record.Count, clientIP)
	} else {
		record = InvalidAttempts{Count: 1, Expiration: time.Now().Add(invalidDuration)}
	}
	invalidAttemptsStore.Set(clientIP, record)

	if record.Count > maxInvalidAttempts {
		http.Error(w, "Too many invalid attempts", http.StatusUnauthorized)
		log.Printf("%s|Response Header Invalid IP: %#v\n", id, w.Header())
		return
	}

	mrecord, mok := invalidMailAttemptsStore.Get(authUser)
	if mok {
		mrecord.Expiration = mrecord.Expiration.Add(invalidDuration)
		mrecord.Count++
		log.Printf("%s|Invalid auth attemp # %d for mail: %s\n", id, mrecord.Count, authUser)
	} else {
		mrecord = InvalidAttempts{Count: 1, Expiration: time.Now().Add(invalidDuration)}
	}
	invalidMailAttemptsStore.Set(authUser, mrecord)

	if mrecord.Count >= maxInvalidAttempts {
		http.Error(w, "Too many invalid attempts", http.StatusUnauthorized)
		log.Printf("%s|Response Header Invalid Mail: %#v\n", id, w.Header())
		return
	}

	var result authResult
	if useImapOnly && authProtocol == "smtp" {
		result = authenticateIMAP(authUser, authPass)
		result.serverPort = useImapOnlyPort
	}
	switch strings.ToLower(authProtocol) {
	case "imap":
		result = authenticateIMAP(authUser, authPass)
	case "smtp":
		if useImapOnly {
			break
		}
		result = authenticateSMTP(authUser, authPass)
	default:
		http.Error(w, "Unsupported Auth-Protocol", http.StatusBadRequest)
		log.Printf("%s|Response Header Auth-Protocol: %#v\n", id, w.Header())
		return
	}

	if result.err != nil {
		errorMessage := result.err.Error()

		if strings.ToLower(authProtocol) == "smtp" {
			errorMessage = "Temporary server problem, try again later"
			w.Header().Add(AuthErrorCodeHeader, result.err.Error())
		}

		w.Header().Add(AuthStatusHeader, errorMessage)
		w.Header().Add(AuthWaitHeader, strconv.Itoa(max(record.Count, mrecord.Count)*3))

		w.WriteHeader(http.StatusOK)

		log.Printf("%s|Response Header Error: %#v\n", id, w.Header())
		return
	}
	invalidAttemptsStore.Delete(clientIP)
	invalidMailAttemptsStore.Delete(authUser)
	w.Header().Add(AuthStatusHeader, "OK")
	w.Header().Add(AuthServerHeader, result.serverAddr)
	w.Header().Add(AuthPortHeader, strconv.Itoa(result.serverPort))
	w.WriteHeader(http.StatusOK)
	log.Printf("%s|Response Header OK: %#v\n", id, w.Header())
}

type authResult struct {
	serverAddr string
	serverPort int
	serverType string
	err        error
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
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
