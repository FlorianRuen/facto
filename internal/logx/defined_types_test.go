// Tests for defined types whose underlying type is a sensitive stdlib
// struct ("type myURL url.URL", "type myReq http.Request"): such a type has
// none of the original methods and lives outside the sensitive packages, but
// it holds the same state, so the walker treats it like the original type
// (reflect ConvertibleTo): URLs are redacted, userinfo masked, cookies keep
// only their name, and every other sensitive struct renders as
// "<TypeName>", unwalked.
package logx_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/logx"
)

type (
	myURL      url.URL
	myUserinfo url.Userinfo
	myCookie   http.Cookie
	myReq      http.Request
	myResp     http.Response
	myClient   http.Client
	myTLS      tls.Config
	myCert     tls.Certificate
	myKey      ecdsa.PrivateKey
	myJar      cookiejar.Jar
)

func TestHandler_DefinedTypesOfSensitiveStdlibStructs(t *testing.T) {
	t.Parallel()
	u := mustURL(t, ftpURLRaw)
	urlNo := []string{pwMarker, queryMarker, "alice"}

	page := mustURL(t, "https://h.example/p?q="+queryMarker)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, page.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Form = url.Values{"note": {bodyMarker}}
	req.Header.Set("X-Note", bodyMarker)
	req.AddCookie(cookie("pref", hexCookie))
	resp := http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"X-Note": {bodyMarker}},
		Request:    req,
		Body:       io.NopCloser(strings.NewReader(bodyMarker)),
	}
	httpNo := []string{hexCookie, bodyMarker, queryMarker, sniMarker}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(page, []*http.Cookie{cookie("pref", hexCookie)})

	scalar := make([]byte, 32)
	for i := range scalar {
		scalar[i] = byte(i + 1)
	}
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar)
	if err != nil {
		t.Fatal(err)
	}
	keyNo := []string{new(big.Int).SetBytes(scalar).String(), fmt.Sprintf("%x", scalar)}
	tlsCfg := tls.Config{ServerName: sniMarker, MinVersion: tls.VersionTLS13}

	runStdCases(t, []stdCase{
		{name: "myURL by value", value: myURL(*u), forbidden: urlNo, kept: []string{"h.example/p?" + logx.Mask}},
		{name: "*myURL", value: (*myURL)(u), forbidden: urlNo, kept: []string{"h.example/p?" + logx.Mask}},
		{name: "myURL in a struct field", value: struct{ Link myURL }{myURL(*u)}, forbidden: urlNo, kept: []string{"h.example/p?" + logx.Mask}},
		{name: "myURL in an unexported field", value: struct{ link *myURL }{(*myURL)(u)}, forbidden: urlNo, kept: []string{"h.example/p?" + logx.Mask}},
		{name: "myUserinfo", value: myUserinfo(*url.UserPassword("alice", pwMarker)), forbidden: []string{pwMarker, "alice"}, exact: logx.Mask},
		{name: "*myUserinfo", value: (*myUserinfo)(url.UserPassword("alice", pwMarker)), forbidden: []string{pwMarker, "alice"}, exact: logx.Mask},
		{name: "myCookie", value: myCookie(*cookie("pref", hexCookie)), forbidden: []string{hexCookie}, exact: "pref=" + logx.Mask},
		{name: "*myCookie", value: (*myCookie)(cookie("pref", hexCookie)), forbidden: []string{hexCookie}, exact: "pref=" + logx.Mask},
		{name: "myReq", value: myReq(*req), forbidden: httpNo, opaque: "myReq"},
		{name: "*myReq", value: (*myReq)(req), forbidden: httpNo, opaque: "myReq"},
		{name: "myReq in a slice", value: []any{(*myReq)(req)}, forbidden: httpNo, kept: []string{"myReq>"}},
		{name: "myResp", value: myResp(resp), forbidden: httpNo, opaque: "myResp"},
		{name: "*myClient", value: &myClient{Transport: &http.Transport{TLSClientConfig: &tlsCfg}}, forbidden: httpNo, opaque: "myClient"},
		{name: "*myTLS", value: (*myTLS)(&tlsCfg), forbidden: httpNo, opaque: "myTLS"},
		{name: "myCert", value: myCert(tls.Certificate{PrivateKey: key}), forbidden: keyNo, opaque: "myCert"},
		{name: "*myKey", value: (*myKey)(key), forbidden: keyNo, opaque: "myKey"},
		{name: "myKey by value", value: myKey(*key), forbidden: keyNo, opaque: "myKey"},
		{name: "*myJar (unexported net/http/cookiejar fields)", value: (*myJar)(jar), forbidden: httpNo, opaque: "myJar"},
	})
}
