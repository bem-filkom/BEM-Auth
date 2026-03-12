package ubauth

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Auth melakukan autentikasi SSO UB dengan username dan password.

// Return:
//   - *StudentDetails: data mahasiswa jika login berhasil
//   - error: nil jika sukses, atau *AuthError dengan kode error spesifik

// Kode error yang mungkin:
//   - ErrInvalidCredentials : username/password salah
//   - ErrSessionFailed      : gagal mendapatkan session awal
//   - ErrNetworkError       : masalah koneksi jaringan
//   - ErrSAMLParseFailed    : gagal memproses SAML response
//   - ErrUnexpected         : error tidak dikenali

func Auth(username, password string) (*StudentDetails, error) {
	studentDetails := new(StudentDetails)

	// cookie dan form parse
	session, err := GetSession()
	if err != nil {
		return studentDetails, err
	}

	//post ke iam.ub.ac.id
	formData := url.Values{}
	formData.Set("username", username)
	formData.Set("password", password)
	formData.Set("credentialId", "")

	loginURL := fmt.Sprintf(IAMAuthURL, session.SessionCode, session.Execution, session.TabID)

	req, err := http.NewRequest("POST", loginURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return studentDetails, &AuthError{
			Code:    ErrNetworkError,
			Message: fmt.Sprintf("failed to create POST request: %v", err),
		}
	}

	for k, v := range GetHeaders() {
		req.Header.Set(k, v)
	}
	req.Header.Set("origin", "null")
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.Header.Set("cookie", fmt.Sprintf(
		"AUTH_SESSION_ID=%s; AUTH_SESSION_ID_LEGACY=%s; KC_RESTART=%s",
		session.AuthSessionID,
		session.AuthSessionIDLegacy,
		session.KCRestart,
	))

	resp, err := session.Client.Do(req)
	if err != nil {
		return studentDetails, &AuthError{
			Code:    ErrNetworkError,
			Message: fmt.Sprintf("failed to perform POST request: %v", err),
		}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return studentDetails, &AuthError{
			Code:    ErrNetworkError,
			Message: fmt.Sprintf("failed to read response body: %v", err),
		}
	}

	body := string(respBody)

	// Step 3: Cek SAML
	if !strings.Contains(body, "SAMLResponse") {
		if strings.Contains(body, "Invalid username or password.") {
			return studentDetails, &AuthError{
				Code:    ErrInvalidCredentials,
				Message: "invalid username or password",
			}
		}
		return studentDetails, &AuthError{
			Code:    ErrUnexpected,
			Message: "unexpected error: no SAMLResponse in response body",
		}
	}

	// Step 4: Extract Parse SAML
	samlResponse, err := GetSubstringBetween(`name="SAMLResponse" value="`, `"/>`, body)
	if err != nil {
		return studentDetails, &AuthError{
			Code:    ErrSAMLParseFailed,
			Message: "failed to extract SAMLResponse value from HTML",
		}
	}

	studentDetails, err = ParseSAMLResponse(samlResponse)
	if err != nil {
		return studentDetails, err
	}

	return studentDetails, nil
}
