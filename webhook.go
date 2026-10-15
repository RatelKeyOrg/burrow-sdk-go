package burrow

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"time"
)

const (
	// SignatureHeader carries the HMAC-SHA256 of a webhook delivery's body, as lowercase hex.
	SignatureHeader = "X-Burrow-Signature"
	// DeliveryIDHeader carries a delivery's id, the same value as the event's ID. A retry of the same event carries the
	// same one.
	DeliveryIDHeader = "X-Burrow-Delivery-Id"
)

// WebhookEvent is a verified delivery from a Burrow's Signed webhook.
type WebhookEvent struct {
	// ID is unique to this event and this webhook. A retry of the same event carries the same ID.
	ID string
	// Event is the event code, such as "secret.delete".
	Event string
	// Severity is "info", "notice", "warning", "high" or "critical".
	Severity string
	// Timestamp is when the event happened.
	Timestamp time.Time
	// Source is the Burrow's name.
	Source string
	Data   WebhookData
}

// WebhookData is what a webhook event is about. Fields the event doesn't carry are empty.
type WebhookData struct {
	// Actor is who acted; nil when the event names no one.
	Actor *WebhookActor
	// Target is what the event was about, such as a secret, a project or a machine; nil when it names nothing.
	Target   *WebhookTarget
	Summary  string
	Detail   string
	SourceIP string
	Fields   map[string]string
}

// WebhookActor is who acted. Type is "user", "machine" or "system".
type WebhookActor struct {
	Type string
	Name string
	ID   string
}

// WebhookTarget is what an event was about: a secret, a project, a machine.
type WebhookTarget struct {
	Type string
	ID   string
	Name string
}

// VerifyWebhook verifies a delivery from a Burrow's Signed webhook and returns its event. It needs only the webhook's
// signing secret, and no Burrow connection or machine identity.
//
// Pass the body exactly as it arrived, before any JSON parsing: re-encoding it changes the bytes, and the signature no
// longer matches. A missing or wrong signature, or a body that isn't a Burrow event, returns a *WebhookError.
//
//	body, _ := io.ReadAll(r.Body)
//	event, err := burrow.VerifyWebhook(body, r.Header, os.Getenv("BURROW_WEBHOOK_SECRET"))
func VerifyWebhook(body []byte, header http.Header, secret string) (*WebhookEvent, error) {
	if secret == "" {
		return nil, &WebhookError{Reason: "no signing secret given"}
	}
	signature := headerValue(header, SignatureHeader)
	if signature == "" {
		return nil, &WebhookError{Reason: "missing " + SignatureHeader + " header"}
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	given := strings.ToLower(strings.TrimSpace(signature))
	if !hmac.Equal([]byte(expected), []byte(given)) {
		return nil, &WebhookError{Reason: "signature does not match"}
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var raw map[string]any
	if err := decoder.Decode(&raw); err != nil {
		return nil, &WebhookError{Reason: "body is not JSON", Err: err}
	}
	return toWebhookEvent(raw)
}

// headerValue is a header's first value, looked up without regard to case, so a header map built by hand works as well
// as one from net/http.
func headerValue(header http.Header, name string) string {
	if v := header.Get(name); v != "" {
		return v
	}
	for key, values := range header {
		if strings.EqualFold(key, name) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

func toWebhookEvent(raw map[string]any) (*WebhookEvent, error) {
	notEvent := &WebhookError{Reason: "body is not a Burrow webhook event"}
	id, okID := raw["id"].(string)
	event, okEvent := raw["event"].(string)
	severity, okSeverity := raw["severity"].(string)
	timestamp, okTimestamp := raw["timestamp"].(json.Number)
	data, okData := raw["data"].(map[string]any)
	if !okID || !okEvent || !okSeverity || !okTimestamp || !okData {
		return nil, notEvent
	}
	millis, err := timestamp.Int64()
	if err != nil {
		f, ferr := timestamp.Float64()
		if ferr != nil || math.IsInf(f, 0) || math.IsNaN(f) {
			return nil, notEvent
		}
		millis = int64(f)
	}
	out := &WebhookEvent{
		ID:        id,
		Event:     event,
		Severity:  severity,
		Timestamp: time.UnixMilli(millis),
		Source:    stringOf(raw["source"]),
		Data: WebhookData{
			Summary:  stringOf(data["summary"]),
			Detail:   stringOf(data["detail"]),
			SourceIP: stringOf(data["sourceIp"]),
			Fields:   map[string]string{},
		},
	}
	if actor, ok := data["actor"].(map[string]any); ok {
		out.Data.Actor = &WebhookActor{Type: stringOf(actor["type"]), Name: stringOf(actor["name"]), ID: stringOf(actor["id"])}
	}
	if target, ok := data["target"].(map[string]any); ok {
		out.Data.Target = &WebhookTarget{Type: stringOf(target["type"]), ID: stringOf(target["id"]), Name: stringOf(target["name"])}
	}
	if fields, ok := data["fields"].(map[string]any); ok {
		for k, v := range fields {
			if s, ok := v.(string); ok {
				out.Data.Fields[k] = s
			}
		}
	}
	return out, nil
}

func stringOf(v any) string {
	s, _ := v.(string)
	return s
}
