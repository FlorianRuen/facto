package record_test

import (
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/clock"
	"github.com/FlorianRuen/facto/internal/har"
	"github.com/FlorianRuen/facto/internal/record"
)

// FuzzRecorder_OutputPassesCheck (J2, Wecasa "redaction check failed"):
// whatever the browser reports, the file the recorder returns passes
// har.Check, so facto record never refuses a real recording.
func FuzzRecorder_OutputPassesCheck(f *testing.F) {
	f.Add("https://www.example.test/sessions/12?ref=abc&token=zz", "X-Csrf-Token", "abcdefgh12", "text/html",
		`<script>var c={token:"abcdefgh12"}</script>`, "application/x-www-form-urlencoded", "email=a%40b.c&passwd=xyz12345", "sid=abcdefgh12; lang=fr")
	f.Add("https://a.test/x", "Location", "/y?code=123456", "application/json",
		`{"user":{"session_id":"zzzzzzzz"},"list":[1,2]}`, "application/json", `{"login":"me","password":"pw123456"}`, "")
	f.Add("https://a.test/%zz?a=%", "Set-Cookie", "a=b; Path=/", "text/javascript",
		`x = "token": "abcdefgh"`, "text/plain", "Bearer abcdefghijkl", "a")
	f.Fuzz(func(t *testing.T, u, hName, hValue, mime, body, postType, post, cookie string) {
		tap := newFakeTap()
		tap.emit(t, "Network.requestWillBeSent", map[string]any{
			"requestId": "1", "type": "XHR",
			"request": map[string]any{
				"url": u, "method": "POST", "postData": post, "hasPostData": post != "",
				"headers": map[string]any{hName: hValue, "Content-Type": postType, "Cookie": cookie},
			},
		})
		tap.emit(t, "Network.responseReceived", map[string]any{
			"requestId": "1",
			"response": map[string]any{
				"url": u, "status": 200, "mimeType": mime,
				"headers": map[string]any{hName: hValue, "Set-Cookie": cookie, "Content-Type": mime},
			},
		})
		tap.setBody("1", body, false)
		tap.emit(t, "Network.loadingFinished", map[string]any{"requestId": "1"})
		close(tap.ch)
		out := record.New(record.Options{Clock: clock.NewFake(time.Unix(0, 0))}).Run(t.Context(), tap)
		if got := har.Check(out); len(got) != 0 {
			t.Fatalf("recorder output fails Check: %q", got)
		}
	})
}
