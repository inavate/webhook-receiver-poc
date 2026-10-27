# Inavate Webhook Receiver POC (Go Edition)

A production-ready, zero-dependency reference implementation written in **Golang** demonstrating how integrators and merchants can securely receive, verify, and process real-time event webhooks from the **Inavate Payments Platform**.

Includes a real-time developer dashboard (powered by Server-Sent Events) to inspect incoming payloads, delivery headers, and cryptographic verification status.

---

## 1. Integration Information Provided by Inavate

When integrating with Inavate webhooks, the Inavate platform sends an HTTP `POST` request with a JSON payload whenever an event occurs (e.g., `transaction.status_changed`, `transaction.created`, `batch.completed`).

### A. Delivery Endpoint Requirements
* The destination URL **must use HTTPS** (TLS 1.3 enforced in production) to protect data in transit.
* For local development, use a tunneling tool such as [ngrok](https://ngrok.com/) or Cloudflare Tunnels (see [Section 4](#4-testing-with-the-inavate-platform-using-ngrok)).

### B. Custom HTTP Headers
Every webhook dispatch from Inavate includes the following headers:

| Header Name | Description |
|---|---|
| `X-Inavate-Timestamp` | Unix epoch timestamp (seconds) when the event was dispatched. Used for replay attack prevention. |
| `X-Inavate-Signature` | Hexadecimal HMAC-SHA256 signature generated using your webhook secret. |
| `X-Inavate-Signature-Legacy` | *(Optional)* Secondary signature sent during secret rotation grace periods (allows zero-downtime key rotation). |
| `Content-Type` | `application/json` |

### C. Cryptographic Signature Verification Protocol
To ensure the payload is authentic and has not been tampered with:

1. **Capture the RAW request body**:
   * **Critical Requirement**: Preserve the exact raw bytes received over the wire (`io.ReadAll(r.Body)`). Do **not** parse into a JSON object first, as JSON unmarshaling alters whitespace, key ordering, and character escapes, which will break the HMAC calculation.
2. **Enforce Replay Attack Protection**:
   * Extract `X-Inavate-Timestamp`.
   * Compare against the current server time: `drift = |now - timestamp|`.
   * If `drift > 300` seconds (5 minutes), reject the request with `400 Bad Request`.
3. **Construct the Signature Payload**:
   * Concatenate the timestamp string, a dot (`.`), and the raw body string:
     ```
     sigPayload = timestamp + "." + rawBody
     ```
4. **Compute Expected HMAC-SHA256**:
   * Compute the HMAC-SHA256 hash of `sigPayload` using your **Shared Secret Key**.
   * Hex-encode the resulting digest.
5. **Constant-Time Comparison**:
   * Compare your computed signature against the `X-Inavate-Signature` header using `crypto/subtle.ConstantTimeCompare` (to prevent side-channel timing attacks).
6. **Acknowledge with HTTP 200 OK**:
   * Return `HTTP 200` within 3–5 seconds.
   * If background processing is slow (e.g. database syncing, sending emails), enqueue the event onto an internal worker queue and return `200 OK` immediately.

---

## 2. Quickstart: Running the Go Application

### Prerequisites
* [Go 1.20+](https://go.dev/dl/) installed.

### Setup and Start
1. Open your terminal in this directory:
   ```bash
   cd webhook-receiver-poc
   ```
2. Start the server (pure standard library, no external packages required):
   ```bash
   go run main.go
   ```
3. Open your browser and navigate to:
   👉 **`http://localhost:8004`**

---

## 3. Testing Locally (Zero Setup)

You can test without any external tools directly in the browser UI or via `curl`:

### Option A: Via the Web Dashboard
1. Open `http://localhost:8004`.
2. Click **"Send Valid Event"** to simulate an Inavate `transaction.status_changed` event.
3. Click **"Test Tampered Sig"** to observe how the receiver catches and flags an invalid signature.
4. Click on any event card to view the verification breakdown, raw headers, and formatted JSON payload.

### Option B: Via `curl`
```bash
# 1. Prepare raw payload
PAYLOAD='{"id":"evt_test_123","event":"transaction.status_changed","tenant_id":"t_demo","data":{"status":"completed","amount":250.00}}'
TIMESTAMP=$(date +%s)
SECRET="my-hmac-signing-secret-1234"

# 2. Compute HMAC-SHA256
SIG_PAYLOAD="${TIMESTAMP}.${PAYLOAD}"
SIGNATURE=$(echo -n "$SIG_PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" | sed 's/^.* //')

# 3. Dispatch to local receiver
curl -i -X POST http://localhost:8004/webhook \
  -H "Content-Type: application/json" \
  -H "X-Inavate-Timestamp: $TIMESTAMP" \
  -H "X-Inavate-Signature: $SIGNATURE" \
  -d "$PAYLOAD"
```

---

## 4. Testing with the Inavate Platform using ngrok

To receive live webhook dispatches from an Inavate environment:

1. **Start an ngrok tunnel to port 8004**:
   ```bash
   ngrok http 8004
   ```
2. Copy the generated HTTPS forwarding URL (e.g., `https://a1b2-c3d4.ngrok-free.app`).
3. **Register the Webhook in Inavate**:
   * Log into the Inavate Portal as an Admin or Super Admin.
   * Go to **Webhooks** in the sidebar.
   * Click **New Subscription**.
   * Enter your ngrok URL with `/webhook` appended:
     ```
     https://a1b2-c3d4.ngrok-free.app/webhook
     ```
   * Set the shared secret (e.g. `my-hmac-signing-secret-1234`).
   * Select events: `transaction.status_changed`, `transaction.created`.
   * Click **Save Webhook**.
4. **Trigger Events**:
   * Execute a payment transaction in Inavate.
   * Watch the event appear in real-time on your dashboard at `http://localhost:8004` with a green **Verified** status badge!

---

## 5. Copy-Paste Go Reference Code

```go
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"math"
	"net/http"
	"strconv"
	"time"
)

func InavateWebhookHandler(webhookSecret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// 1. Read raw body bytes
		rawBody, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}

		// 2. Extract Inavate headers
		timestamp := r.Header.Get("X-Inavate-Timestamp")
		signature := r.Header.Get("X-Inavate-Signature")

		if timestamp == "" || signature == "" {
			http.Error(w, "Missing Inavate signature headers", http.StatusBadRequest)
			return
		}

		// 3. Replay attack check (drift <= 300 seconds)
		tsInt, err := strconv.ParseInt(timestamp, 10, 64)
		if err != nil || math.Abs(float64(time.Now().Unix()-tsInt)) > 300 {
			http.Error(w, "Timestamp drift exceeds 300 seconds", http.StatusBadRequest)
			return
		}

		// 4. Compute expected HMAC-SHA256 signature
		sigPayload := timestamp + "." + string(rawBody)
		mac := hmac.New(sha256.New, []byte(webhookSecret))
		mac.Write([]byte(sigPayload))
		expectedSig := hex.EncodeToString(mac.Sum(nil))

		// 5. Constant-time comparison
		if subtle.ConstantTimeCompare([]byte(signature), []byte(expectedSig)) != 1 {
			http.Error(w, "Unauthorized: Signature mismatch", http.StatusUnauthorized)
			return
		}

		// 6. Process business logic (or enqueue asynchronously)
		// ... your code here ...

		// 7. Acknowledge with 200 OK
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"acknowledged"}`))
	}
}
```

---

## 6. Security & Attack Defenses

When implementing a webhook receiver, your service is exposed to the public Internet. You must defend against the following common attack vectors:

| Attack Vector | Threat | Defense Implementation | Automated Test in `main_test.go` |
|---|---|---|---|
| **Signature Forgery / Spoofing** | Attacker sends a fake event (e.g. marking an invoice as paid) without knowing your secret. | Verify HMAC-SHA256 signature against your secret. **Reject with 401 Unauthorized and drop the event immediately** before calling any business logic. | `TestAttack_ForgedSignature_RejectedAndIgnored` |
| **Payload Tampering** | Attacker intercepts transit data and alters fields (e.g. changing an amount from $10 to $9,999). | HMAC is calculated over `${timestamp}.${raw_body}`. Even modifying a single byte causes verification to fail. | `TestAttack_PayloadTampering_BitFlip` |
| **Replay Attacks** | Attacker intercepts an old valid request and re-transmits it days later to trigger duplicate fulfillment. | Check `X-Inavate-Timestamp`. If the difference between `time.Now().Unix()` and the header exceeds **300 seconds (5 minutes)**, reject with 401. | `TestAttack_ReplayAttack_Past` & `TestAttack_ReplayAttack_Future` |
| **Timing Side-Channel Attacks** | Attacker measures nanoseconds response latency to brute-force matching bytes. | Never use standard `==` string equality. Strictly use `crypto/subtle.ConstantTimeCompare`. | `TestSecurity_TimingAttackResistance` |
| **Denial of Service (DoS / OOM Crash)** | Malicious actor sends a 100MB body to exhaust server RAM and crash the app. | Wrap `r.Body` with `http.MaxBytesReader(w, r.Body, 1<<20)` (1 MB limit). Rejects oversized payloads with 413. | `TestAttack_OversizedPayload_DoS` |
| **Duplicate Delivery (Retries)** | Inavate retries events upon temporary network drops, potentially causing duplicate actions. | Track processed `event_id`s in a database or cache. If already processed, acknowledge with 200 OK but do not re-run side effects. | `TestSecurity_IdempotencyDeduplication` |

### Running the Attack Defense Test Suite
```bash
go test -v .
```

---

## 7. License
MIT License. Free for all Inavate partners, integrators, and merchants.

