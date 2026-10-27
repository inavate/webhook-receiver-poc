package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// WebhookEventRecord represents a received webhook event with verification audit metadata
type WebhookEventRecord struct {
	ID                 string                 `json:"id"`
	ReceivedAt         string                 `json:"received_at"`
	TimestampHeader    string                 `json:"timestamp_header"`
	TimeDiffSeconds    int64                  `json:"time_diff_seconds"`
	SignatureHeader    string                 `json:"signature_header"`
	LegacySignature    string                 `json:"legacy_signature,omitempty"`
	ComputedSignature  string                 `json:"computed_signature"`
	IsSignatureValid   bool                   `json:"is_signature_valid"`
	IsLegacyValid      bool                   `json:"is_legacy_valid"`
	VerificationStatus string                 `json:"verification_status"` // "verified", "invalid_signature", "expired_timestamp", "missing_headers"
	VerificationError  string                 `json:"verification_error,omitempty"`
	EventType          string                 `json:"event_type"`
	TenantID           string                 `json:"tenant_id,omitempty"`
	Headers            map[string]string      `json:"headers"`
	RawPayload         string                 `json:"raw_payload"`
	ParsedPayload      map[string]interface{} `json:"parsed_payload,omitempty"`
}

var (
	configMutex   sync.RWMutex
	webhookSecret string

	eventMutex sync.RWMutex
	eventLog   = make([]*WebhookEventRecord, 0, 50)

	sseMutex   sync.Mutex
	sseClients = make(map[chan string]bool)
)

func main() {
	loadEnv(".env")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8003"
	}

	secret := os.Getenv("WEBHOOK_SECRET")
	if strings.TrimSpace(secret) == "" {
		log.Fatal("WEBHOOK_SECRET must be set")
	}
	webhookSecret = secret

	http.HandleFunc("/", serveStatic)
	http.HandleFunc("/webhook", handleWebhook)
	http.HandleFunc("/events", handleSSE)
	http.HandleFunc("/api/config", handleConfig)
	http.HandleFunc("/api/simulate", handleSimulate)

	log.Println("==================================================================")
	log.Printf(" Inavate Webhook Receiver (Go Edition) running at http://localhost:%s\n", port)
	log.Printf(" Webhook Receiver URL: POST http://localhost:%s/webhook\n", port)
	log.Println(" Open your browser to http://localhost:" + port + " to inspect live events")
	log.Println("==================================================================")

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Server failed to start: %v\n", err)
	}
}

func getSecret() string {
	configMutex.RLock()
	defer configMutex.RUnlock()
	return webhookSecret
}

func setSecret(s string) {
	configMutex.Lock()
	webhookSecret = s
	configMutex.Unlock()
	broadcastSSE("secret_updated", map[string]interface{}{"secret": s})
}

// handleWebhook is the primary destination endpoint for Inavate platform webhook dispatches
func handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed, must be POST"}`, http.StatusMethodNotAllowed)
		return
	}

	// 1. Capture RAW request body bytes (Critical: must NOT be modified or pre-parsed)
	// Protect against memory exhaustion / Denial of Service by limiting payload to 1MB
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	rawBodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"Request body exceeds 1MB limit or unreadable"}`, http.StatusRequestEntityTooLarge)
		return
	}
	rawBody := string(rawBodyBytes)

	// 2. Extract Inavate headers
	timestampStr := r.Header.Get("X-Inavate-Timestamp")
	signature := r.Header.Get("X-Inavate-Signature")
	legacySignature := r.Header.Get("X-Inavate-Signature-Legacy")

	headersMap := make(map[string]string)
	for k, v := range r.Header {
		if len(v) > 0 {
			headersMap[k] = v[0]
		}
	}

	activeSecret := getSecret()

	record := &WebhookEventRecord{
		ID:              fmt.Sprintf("evt_%d", time.Now().UnixNano()),
		ReceivedAt:      time.Now().UTC().Format(time.RFC3339),
		TimestampHeader: timestampStr,
		SignatureHeader: signature,
		LegacySignature: legacySignature,
		Headers:         headersMap,
		RawPayload:      rawBody,
	}

	// Try parsing JSON payload
	var parsed map[string]interface{}
	if err := json.Unmarshal(rawBodyBytes, &parsed); err == nil {
		record.ParsedPayload = parsed
		if evtType, ok := parsed["event"].(string); ok {
			record.EventType = evtType
		} else if evtType, ok := parsed["event_type"].(string); ok {
			record.EventType = evtType
		}
		if tID, ok := parsed["tenant_id"].(string); ok {
			record.TenantID = tID
		}
		if pID, ok := parsed["id"].(string); ok && pID != "" {
			record.ID = pID
		}
	}
	if record.EventType == "" {
		record.EventType = "unknown.event"
	}

	// 3. Cryptographic Verification & Replay Protection
	if timestampStr == "" || signature == "" {
		record.VerificationStatus = "missing_headers"
		record.VerificationError = "Missing X-Inavate-Timestamp or X-Inavate-Signature header"
		record.IsSignatureValid = false
	} else {
		// Timestamp freshness check (drift <= 300 seconds)
		tsInt, tsErr := strconv.ParseInt(timestampStr, 10, 64)
		if tsErr != nil {
			record.VerificationStatus = "invalid_timestamp"
			record.VerificationError = "Header X-Inavate-Timestamp is not a valid integer"
		} else {
			nowSec := time.Now().Unix()
			diff := int64(math.Abs(float64(nowSec - tsInt)))
			record.TimeDiffSeconds = diff

			if diff > 300 {
				record.VerificationStatus = "expired_timestamp"
				record.VerificationError = fmt.Sprintf("Timestamp drift is %ds (exceeds max 300s replay window)", diff)
			}
		}

		// Compute expected HMAC-SHA256 signature
		// Protocol: sigPayload = timestamp + "." + rawBody
		sigPayload := timestampStr + "." + rawBody
		computed := computeHMACSHA256(sigPayload, activeSecret)
		record.ComputedSignature = computed

		// Constant-time string comparison to prevent timing side-channel attacks
		record.IsSignatureValid = (subtle.ConstantTimeCompare([]byte(signature), []byte(computed)) == 1)

		if record.IsSignatureValid {
			if record.VerificationStatus == "" {
				record.VerificationStatus = "verified"
			}
		} else {
			// Check legacy signature if present
			if legacySignature != "" {
				record.IsLegacyValid = (subtle.ConstantTimeCompare([]byte(legacySignature), []byte(computed)) == 1)
			}
			if record.VerificationStatus == "" {
				record.VerificationStatus = "invalid_signature"
				record.VerificationError = "Computed HMAC-SHA256 signature does not match X-Inavate-Signature header"
			}
		}
	}

	// Store in memory log
	saveEvent(record)

	// Broadcast to all connected web dashboard clients via SSE
	broadcastSSE("new_event", record)

	log.Printf("[Webhook Ingest] Received event: id=%s type=%s status=%s (valid_sig=%t diff=%ds)\n",
		record.ID, record.EventType, record.VerificationStatus, record.IsSignatureValid, record.TimeDiffSeconds)

	// 4. Return Prompt HTTP 200 OK Acknowledgment
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":          "acknowledged",
		"event_id":        record.ID,
		"signature_valid": record.IsSignatureValid,
		"status_detail":   record.VerificationStatus,
		"received_at":     record.ReceivedAt,
	})
}

// computeHMACSHA256 calculates hex-encoded HMAC-SHA256 of payload with secret
func computeHMACSHA256(payload, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyInavateWebhook encapsulates the full cryptographic check, header validation,
// and replay window protection for an incoming webhook.
func VerifyInavateWebhook(rawBody []byte, headers http.Header, secret string) (isValid bool, statusDetail string, errDetail string) {
	timestampStr := headers.Get("X-Inavate-Timestamp")
	signature := headers.Get("X-Inavate-Signature")
	legacySignature := headers.Get("X-Inavate-Signature-Legacy")

	if timestampStr == "" || signature == "" {
		return false, "missing_headers", "Missing X-Inavate-Timestamp or X-Inavate-Signature header"
	}

	tsInt, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return false, "invalid_timestamp", "Header X-Inavate-Timestamp is not a valid integer"
	}

	diff := int64(math.Abs(float64(time.Now().Unix() - tsInt)))
	if diff > 300 {
		return false, "expired_timestamp", fmt.Sprintf("Timestamp drift is %ds (exceeds max 300s replay window)", diff)
	}

	sigPayload := timestampStr + "." + string(rawBody)
	computed := computeHMACSHA256(sigPayload, secret)

	if subtle.ConstantTimeCompare([]byte(signature), []byte(computed)) == 1 {
		return true, "verified", ""
	}
	if legacySignature != "" && subtle.ConstantTimeCompare([]byte(legacySignature), []byte(computed)) == 1 {
		return true, "verified_legacy", ""
	}

	return false, "invalid_signature", "Computed HMAC-SHA256 signature does not match X-Inavate-Signature header"
}

// SecureProductionHandler returns a hardened production HTTP handler.
// When an invalid or forged signature arrives, it DROPS and IGNORES the event,
// responds with 401 Unauthorized, and guarantees business logic is NEVER executed.
func SecureProductionHandler(secret string, onVerified func(event map[string]interface{}) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"Method not allowed, must be POST"}`, http.StatusMethodNotAllowed)
			return
		}

		// 1. Defend against DoS / Memory exhaustion attacks (Max 1MB)
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		rawBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, `{"error":"Payload too large or unreadable"}`, http.StatusRequestEntityTooLarge)
			return
		}

		// 2. Cryptographic Security Gate: Verify signature and timestamp
		valid, statusDetail, errDetail := VerifyInavateWebhook(rawBytes, r.Header, secret)
		if !valid {
			// CRITICAL: Reject & ignore! Do NOT invoke onVerified business logic!
			log.Printf("[SECURITY DEFENSE] Ignored untrusted webhook: %s (%s)\n", statusDetail, errDetail)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "rejected",
				"error":   "Unauthorized: Invalid webhook signature or expired timestamp",
				"details": statusDetail,
			})
			return
		}

		// 3. Parse JSON only AFTER verification passes
		var parsed map[string]interface{}
		if err := json.Unmarshal(rawBytes, &parsed); err != nil {
			http.Error(w, `{"error":"Invalid JSON payload"}`, http.StatusBadRequest)
			return
		}

		// 4. Safe to execute downstream business logic (e.g. fulfill order, credit ledger)
		if onVerified != nil {
			if err := onVerified(parsed); err != nil {
				log.Printf("[Webhook Handler] Business logic failure: %v\n", err)
				http.Error(w, `{"error":"Internal processing error"}`, http.StatusInternalServerError)
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "acknowledged",
		})
	}
}

func saveEvent(record *WebhookEventRecord) {
	eventMutex.Lock()
	defer eventMutex.Unlock()

	// Prepend to array
	eventLog = append([]*WebhookEventRecord{record}, eventLog...)
	if len(eventLog) > 50 {
		eventLog = eventLog[:50]
	}
}

func getEvents() []*WebhookEventRecord {
	eventMutex.RLock()
	defer eventMutex.RUnlock()
	res := make([]*WebhookEventRecord, len(eventLog))
	copy(res, eventLog)
	return res
}

// handleSSE handles real-time Server-Sent Events to push updates to the browser UI
func handleSSE(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	messageChan := make(chan string, 10)

	sseMutex.Lock()
	sseClients[messageChan] = true
	sseMutex.Unlock()

	defer func() {
		sseMutex.Lock()
		delete(sseClients, messageChan)
		sseMutex.Unlock()
	}()

	// Send initial state on connect
	initData, _ := json.Marshal(map[string]interface{}{
		"type":   "init",
		"secret": getSecret(),
		"logs":   getEvents(),
	})
	fmt.Fprintf(w, "data: %s\n\n", initData)
	flusher.Flush()

	notify := r.Context().Done()
	for {
		select {
		case <-notify:
			return
		case msg := <-messageChan:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		}
	}
}

func broadcastSSE(eventType string, payload interface{}) {
	data, err := json.Marshal(map[string]interface{}{
		"type": eventType,
		"data": payload,
	})
	if err != nil {
		return
	}
	msg := string(data)

	sseMutex.Lock()
	defer sseMutex.Unlock()
	for ch := range sseClients {
		select {
		case ch <- msg:
		default:
		}
	}
}

// handleConfig allows updating the shared secret dynamically from the UI
func handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Secret) == "" {
		http.Error(w, `{"error":"Valid secret string required"}`, http.StatusBadRequest)
		return
	}

	setSecret(strings.TrimSpace(req.Secret))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"secret":  getSecret(),
	})
}

// handleSimulate emits a realistic simulated Inavate webhook event locally
func handleSimulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		EventType string `json:"event_type"`
		TamperSig bool   `json:"tamper_signature"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	if req.EventType == "" {
		req.EventType = "transaction.status_changed"
	}

	now := time.Now().UTC()
	evtID := fmt.Sprintf("evt_sim_%d", now.UnixNano())

	var dataPayload interface{}
	switch req.EventType {
	case "transaction.status_changed":
		dataPayload = map[string]interface{}{
			"transaction_id":     "tx_9988223344",
			"transaction_number": "ACH-2026-98124",
			"status":             "completed",
			"previous_status":    "pending",
			"payment_method":     "ACH",
			"operation_type":     "sale",
			"amount":             1450.00,
			"merchant_id":        "merch_eastbay_hardware",
			"merchant_name":      "Eastbay Hardware Supply",
			"is_same_day":        true,
			"sec_code":           "CCD",
			"effective_date":     now.Format("2006-01-02"),
		}
	case "transaction.created":
		dataPayload = map[string]interface{}{
			"transaction_id":     "tx_5544332211",
			"transaction_number": "ACH-2026-11204",
			"status":             "pending",
			"payment_method":     "ACH",
			"operation_type":     "sale",
			"amount":             325.50,
			"merchant_id":        "merch_solis_auto",
			"merchant_name":      "Solis Automotive Group",
			"is_same_day":        false,
			"sec_code":           "WEB",
		}
	case "transaction.returned_nsf":
		req.EventType = "transaction.status_changed"
		dataPayload = map[string]interface{}{
			"transaction_id":     "tx_7744119900",
			"transaction_number": "ACH-2026-44391",
			"status":             "returned",
			"previous_status":    "pending",
			"payment_method":     "ACH",
			"operation_type":     "sale",
			"amount":             780.00,
			"return_code":        "R01",
			"return_reason":      "Insufficient Funds",
			"merchant_id":        "merch_alpha_health",
			"merchant_name":      "Alpha Health Clinic",
		}
	default:
		dataPayload = map[string]interface{}{
			"batch_id":     "batch_20261025_01",
			"status":       "completed",
			"total_count":  45,
			"total_amount": 28450.00,
			"completed_at": now.Format(time.RFC3339),
		}
	}

	payloadMap := map[string]interface{}{
		"id":         evtID,
		"event":      req.EventType,
		"event_type": req.EventType,
		"tenant_id":  "tenant_inavate_demo",
		"created_at": now.Format(time.RFC3339),
		"data":       dataPayload,
	}

	bodyBytes, _ := json.Marshal(payloadMap)
	timestampStr := strconv.FormatInt(now.Unix(), 10)
	sigPayload := timestampStr + "." + string(bodyBytes)

	secret := getSecret()
	signature := computeHMACSHA256(sigPayload, secret)
	if req.TamperSig {
		signature = "invalid_" + signature[:len(signature)-8] + "deadbeef"
	}

	// Dispatch request to internal handler
	reqURL := "http://localhost/webhook"
	simReq, _ := http.NewRequest(http.MethodPost, reqURL, bytes.NewReader(bodyBytes))
	simReq.Header.Set("Content-Type", "application/json")
	simReq.Header.Set("X-Inavate-Timestamp", timestampStr)
	simReq.Header.Set("X-Inavate-Signature", signature)
	simReq.Header.Set("User-Agent", "Inavate-Webhook-Worker/2.0")

	// Call handleWebhook directly
	rec := &responseRecorder{header: make(http.Header)}
	handleWebhook(rec, simReq)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"event_id": evtID,
		"type":     req.EventType,
		"tampered": req.TamperSig,
	})
}

type responseRecorder struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (r *responseRecorder) Header() http.Header         { return r.header }
func (r *responseRecorder) Write(b []byte) (int, error) { return r.body.Write(b) }
func (r *responseRecorder) WriteHeader(status int)      { r.status = status }

func serveStatic(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/styles.css" {
		http.ServeFile(w, r, "styles.css")
		return
	}
	if r.URL.Path == "/app.js" {
		http.ServeFile(w, r, "app.js")
		return
	}
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, "index.html")
}

func loadEnv(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			v = strings.Trim(v, `"'`)
			if os.Getenv(k) == "" {
				_ = os.Setenv(k, v)
			}
		}
	}
}
