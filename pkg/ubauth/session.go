package ubauth

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// GetSession melakukan GET ke portal brone.ub.ac.id untuk mendapatkan
// cookies dan parameter session yang dibutuhkan untuk proses login SSO.

func GetSession() (*Session, error) {
	session := new(Session)

	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			for k, v := range GetHeaders() {
				req.Header.Set(k, v)
			}
			return nil
		},
	}

	req, err := http.NewRequest("GET", BronesURL, nil)
	if err != nil {
		return session, &AuthError{
			Code:    ErrNetworkError,
			Message: fmt.Sprintf("failed to create GET request: %v", err),
		}
	}

	for k, v := range GetHeaders() {
		req.Header.Set(k, v)
	}
	req.Header.Set("referer", BronesReferer)

	resp, err := client.Do(req)
	if err != nil {
		return session, &AuthError{
			Code:    ErrNetworkError,
			Message: fmt.Sprintf("failed to perform GET request: %v", err),
		}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return session, &AuthError{
			Code:    ErrNetworkError,
			Message: fmt.Sprintf("failed to read response body: %v", err),
		}
	}

	body := string(respBody)
	cookieHeader := fmt.Sprintf("%s", resp.Header["Set-Cookie"])

	// --- Extract cookies ---
	authSessionID, err := GetSubstringBetween("AUTH_SESSION_ID=", ";", cookieHeader)
	if err != nil {
		return session, &AuthError{Code: ErrSessionFailed, Message: "failed to get AUTH_SESSION_ID from cookie"}
	}

	authSessionIDLegacy, err := GetSubstringBetween("AUTH_SESSION_ID_LEGACY=", ";", cookieHeader)
	if err != nil {
		return session, &AuthError{Code: ErrSessionFailed, Message: "failed to get AUTH_SESSION_ID_LEGACY from cookie"}
	}

	kcRestart, err := GetSubstringBetween("KC_RESTART=", ";", cookieHeader)
	if err != nil {
		return session, &AuthError{Code: ErrSessionFailed, Message: "failed to get KC_RESTART from cookie"}
	}

	// --- Extract parameter form dari HTML ---
	fullURL, err := GetSubstringBetween(`action="`, `" `, body)
	if err != nil {
		return session, &AuthError{Code: ErrSessionFailed, Message: "failed to get form action URL from HTML"}
	}

	sessionCode, err := GetSubstringBetween("session_code=", "&amp", fullURL)
	if err != nil {
		return session, &AuthError{Code: ErrSessionFailed, Message: "failed to get session_code from URL"}
	}

	execution, err := GetSubstringBetween("execution=", "&amp", fullURL)
	if err != nil {
		return session, &AuthError{Code: ErrSessionFailed, Message: "failed to get execution from URL"}
	}

	tabIDSlice := strings.Split(fullURL, "tab_id=")
	if len(tabIDSlice) < 2 {
		return session, &AuthError{Code: ErrSessionFailed, Message: "failed to get tab_id from URL"}
	}

	session.Client = client
	session.AuthSessionID = authSessionID
	session.AuthSessionIDLegacy = authSessionIDLegacy
	session.KCRestart = kcRestart
	session.SessionCode = sessionCode
	session.Execution = execution
	session.TabID = tabIDSlice[1]

	return session, nil
}
