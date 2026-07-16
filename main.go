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

// attemptRecord tracks failed attempts for a single key.
type attemptRecord struct {
	mu         sync.Mutex
	count      int
	expiration time.Time
}

// Limiter is a thread-safe, per-key attempt counter with TTL-based lockout.
// A key is "blocked" once it accumulates `max` attempts within `window`.
// Each attempt refreshes the window (sliding lockout).
type Limiter struct {
	store  sync.Map // map[string]*attemptRecord
	max    int
	window time.Duration
}

func NewLimiter(max int, window time.Duration) *Limiter {
	return &Limiter{max: max, window: window}
}

// Register records a failed attempt for key and returns the new count
// plus whether the key is now blocked.
func (l *Limiter) Register(key string) int {
	if l == nil {
		return 0
	}
	actual, _ := l.store.LoadOrStore(key, &attemptRecord{})
	rec := actual.(*attemptRecord)

	rec.mu.Lock()
	defer rec.mu.Unlock()

	now := time.Now()
	if rec.expiration.IsZero() || now.After(rec.expiration) {
		rec.count = 0 // expired or brand new
	}
	rec.count++
	rec.expiration = now.Add(l.window)

	return rec.count
}

// Blocked checks status without registering a new attempt.
func (l *Limiter) Blocked(key string) (int, bool) {
	if l == nil {
		return 0, false
	}
	v, ok := l.store.Load(key)
	if !ok {
		return 0, false
	}
	rec := v.(*attemptRecord)

	rec.mu.Lock()
	defer rec.mu.Unlock()

	if rec.expiration.IsZero() || time.Now().After(rec.expiration) {
		return 0, false
	}
	return rec.count, rec.count >= l.max
}

// Reset clears a key's record, e.g. after a successful login.
func (l *Limiter) Reset(key ...string) {
	if l == nil {
		return
	}
	for _, k := range key {
		l.store.Delete(k)
	}
}

// Expire sweeps the store and deletes expired records. Call this
// periodically from a background goroutine.
func (l *Limiter) Expire() int {
	if l == nil {
		return 0
	}
	n := 0
	now := time.Now()
	l.store.Range(func(k, v any) bool {
		rec := v.(*attemptRecord)
		rec.mu.Lock()
		expired := rec.expiration.IsZero() || now.After(rec.expiration)
		rec.mu.Unlock()
		if expired {
			l.store.Delete(k)
			n++
		}
		return true
	})
	return n
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
	ClientIPHeader      = "Client-IP"          // HTTP header to provide the client's IP address
)

var (
	port                 int           // Port number on which the server listens for incoming connections
	maxLoginAttempts     int           // Maximum allowed login attempts per user or IP address
	maxInvalidAttempts   int           // Maximum number of invalid attempts before blocking
	useImapOnly          bool          // Whether to use IMAP only for authenticating both IMAP and SMTP protocols
	maskPass             bool          // Whether to mask password in logs
	useImapOnlyPort      int           // Port number when using IMAP only, typically used for SMTP as well
	imapServerAddresses  stringSlice   // List of IMAP server addresses in host:port format
	smtpServerAddresses  stringSlice   // List of SMTP server addresses in host:port format
	invalidAttemptsStore *Limiter      // Limiter tracking invalid login attempts with their counts and expiration times
	invalidDuration      time.Duration // Duration for which IP addresses are blocked after reaching maxInvalidAttempts
)

// Initialize variables from command-line flags or default values
func init() {
	flag.IntVar(&port, "port", 9143, "Port to listen on")                                                                         // Set default port and parse the --port flag
	flag.IntVar(&maxLoginAttempts, "maxloginattempts", 20, "Max login attempts allowed")                                          // Maximum number of allowed login attempts per user or IP
	flag.IntVar(&maxInvalidAttempts, "maxinvalidattempts", 5, "Max invalid attempts before blocking")                             // Threshold for blocking after too many failed attempts
	flag.IntVar(&useImapOnlyPort, "useimaponlyport", 25, "Use only IMAP for authenticating both IMAP & SMTP - SMTP port")         // Port when using IMAP-only authentication
	flag.BoolVar(&useImapOnly, "useimaponly", false, "Use only IMAP for authenticating both IMAP & SMTP")                         // Toggle to use IMAP for all authentication tasks
	flag.BoolVar(&maskPass, "maskpass", true, "Mask password in logs")                                                            // Toggle to mask password in logs
	flag.DurationVar(&invalidDuration, "invalidduration", time.Minute*5, "Blocked IP addresses are cleaned up after this period") // Time before blocked IPs are cleared
	flag.Var(&imapServerAddresses, "imap", "IMAP server addresses (format: host:port,host:port...)")                              // Collect IMAP server addresses from flags
	flag.Var(&smtpServerAddresses, "smtp", "SMTP server addresses (format: host:port,host:port...)")                              // Collect SMTP server addresses from flags
	invalidAttemptsStore = NewLimiter(maxInvalidAttempts, invalidDuration)                                                        // uses flag defaults at this point
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	flag.Parse()                                                           // Parse all command-line flags
	invalidAttemptsStore = NewLimiter(maxInvalidAttempts, invalidDuration) // Initialize the Limiter for tracking invalid attempts
	// Validate that at least one IMAP and SMTP server is provided
	if len(imapServerAddresses) == 0 || len(smtpServerAddresses) == 0 {
		fmt.Println("Please provide at least one IMAP and SMTP server address") // Error message if no servers are specified
		flag.PrintDefaults()                                                    // Print default help message showing all flags
		os.Exit(1)                                                              // Exit with error code 1 due to missing required parameters
	}

	// Log configuration details for verification
	log.Println("Configuration:")
	flag.VisitAll(func(f *flag.Flag) {
		log.Printf("  %s = %s", f.Name, f.Value.String())
	})

	go handleSignals(cancel)

	// periodic sweep, e.g. once a minute
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if n := invalidAttemptsStore.Expire(); n > 0 {
					log.Printf("Successfully expired %d record(s).\n", n)
				}
			}
		}
	}()

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
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
		log.Println("Server is up and running...")

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

func maskAuthPass(h http.Header) http.Header {
	if h == nil {
		return nil
	}
	c := h.Clone()
	c.Set(AuthPassHeader, "***MASKED***")
	return c
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	id := hashBlake3(fmt.Sprint(r.Header.Get(AuthUserHeader), r.Header.Get(AuthProtocolHeader), r.Header.Get(ClientIPHeader)))
	if maskPass {
		log.Printf("%s|Request Header: %#v\n", id, maskAuthPass(r.Header))
	} else {
		log.Printf("%s|Request Header: %#v\n", id, r.Header)
	}
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
	clientIP := r.Header.Get(ClientIPHeader)
	loginAttempt, _ := strconv.Atoi(loginAttemptStr)
	if loginAttempt > maxLoginAttempts {
		http.Error(w, "Too many login attempts", http.StatusUnauthorized)
		log.Printf("%s|Response Header Login: %#v\n", id, w.Header())
		return
	}

	count, blocked := invalidAttemptsStore.Blocked(clientIP)
	log.Printf("%s|Invalid auth attempt # %d for IP: %s\n", id, count, clientIP)
	if blocked {
		http.Error(w, "Too many invalid attempts", http.StatusUnauthorized)
		log.Printf("%s|Response Header Blocked IP: %#v\n", id, w.Header())
		return
	}

	mcount, mblocked := invalidAttemptsStore.Blocked(authUser)
	log.Printf("%s|Invalid auth attempt # %d for mail: %s\n", id, mcount, authUser)
	if mblocked {
		http.Error(w, "Too many invalid attempts", http.StatusUnauthorized)
		log.Printf("%s|Response Header Blocked Mail: %#v\n", id, w.Header())
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
		rcount := max(invalidAttemptsStore.Register(clientIP), invalidAttemptsStore.Register(authUser))
		if strings.ToLower(authProtocol) == "smtp" {
			errorMessage = "Temporary server problem, try again later"
			w.Header().Add(AuthErrorCodeHeader, result.err.Error())
		}

		w.Header().Add(AuthStatusHeader, errorMessage)
		w.Header().Add(AuthWaitHeader, strconv.Itoa(rcount*3))

		w.WriteHeader(http.StatusOK)

		log.Printf("%s|Response Header Error: %#v\n", id, w.Header())
		return
	}
	invalidAttemptsStore.Reset(clientIP, authUser)
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

	conn, err := net.Dial("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
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
