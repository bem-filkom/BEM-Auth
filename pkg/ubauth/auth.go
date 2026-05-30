package ubauth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Auth melakukan autentikasi SSO UB dengan username dan password.
// Fungsi ini akan mencoba metode Brone terlebih dahulu. Jika gagal, akan fallback ke metode Siam (OIDC).
//
// Return:
//   - *StudentDetails: data mahasiswa jika login berhasil
//   - error: nil jika sukses, atau *AuthError dengan kode error spesifik
func Auth(username, password string) (*StudentDetails, error) {
	// 1. Coba metode Brone (SAML)
	details, err := AuthBrone(username, password)
	if err == nil {
		return details, nil
	}

	// Jika Brone error (misal server down, timeout, dsb), fallback ke Siam
	// Catatan: Anda bisa menambahkan log di sini jika ingin tahu kapan fallback terjadi
	// log.Printf("Brone failed: %v. Fallback to Siam...", err)

	// 2. Fallback ke metode Siam (OIDC) tanpa getProfil
	return AuthSiam(username, password)
}

// AuthBrone melakukan autentikasi menggunakan portal brone.ub.ac.id (SAML).
// Metode ini lebih disukai karena mengembalikan data Fakultas & Prodi langsung dari response XML.
func AuthBrone(username, password string) (*StudentDetails, error) {
	studentDetails := new(StudentDetails)

	// Dapatkan session Brone
	session, err := GetSessionBrone()
	if err != nil {
		return studentDetails, err
	}

	// POST ke iam.ub.ac.id menggunakan parameter brone
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

	// Cek SAML
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

	// Extract SAML
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

// AuthSiam melakukan autentikasi menggunakan portal siam.ub.ac.id (OIDC).
// Metode ini digunakan sebagai fallback jika Brone gagal.
// Untuk menghindari Cloudflare 403, metode ini TIDAK memanggil API getProfil.
// Hanya mengembalikan NIM (dari username) dan Email (dari JWT token).
func AuthSiam(username, password string) (*StudentDetails, error) {
	studentDetails := new(StudentDetails)

	// Dapatkan session Siam
	session, err := GetSessionSiam()
	if err != nil {
		return studentDetails, err
	}

	// POST ke iam.ub.ac.id menggunakan session siam
	formData := url.Values{}
	formData.Set("username", username)
	formData.Set("password", password)
	formData.Set("credentialId", "")

	loginURL := session.LoginActionURL

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

	// Stop following redirects to catch the 302 location
	session.Client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err := session.Client.Do(req)
	if err != nil {
		return studentDetails, &AuthError{
			Code:    ErrNetworkError,
			Message: fmt.Sprintf("failed to perform POST request: %v", err),
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		respBody, err := io.ReadAll(resp.Body)
		if err == nil {
			body := string(respBody)
			if strings.Contains(body, "Invalid username or password.") {
				return studentDetails, &AuthError{
					Code:    ErrInvalidCredentials,
					Message: "invalid username or password",
				}
			}
		}
		return studentDetails, &AuthError{
			Code:    ErrUnexpected,
			Message: "unexpected error: login failed but no invalid credentials message found",
		}
	}

	if resp.StatusCode != 302 && resp.StatusCode != 303 {
		return studentDetails, &AuthError{
			Code:    ErrUnexpected,
			Message: fmt.Sprintf("unexpected status code %d", resp.StatusCode),
		}
	}

	location := resp.Header.Get("Location")
	parsedLoc, err := url.Parse(location)
	if err != nil {
		return studentDetails, &AuthError{
			Code:    ErrOIDCParseFailed,
			Message: "failed to parse redirect location",
		}
	}

	fragmentValues, _ := url.ParseQuery(parsedLoc.Fragment)
	code := fragmentValues.Get("code")
	if code == "" {
		code = parsedLoc.Query().Get("code")
	}

	if code == "" {
		return studentDetails, &AuthError{
			Code:    ErrOIDCParseFailed,
			Message: "failed to get authorization code from redirect",
		}
	}

	// Step 3: Exchange code for token
	tokenFormData := url.Values{}
	tokenFormData.Set("grant_type", "authorization_code")
	tokenFormData.Set("client_id", "siam")
	tokenFormData.Set("code", code)
	tokenFormData.Set("redirect_uri", "https://siam.ub.ac.id/mahasiswa")

	tokenReq, err := http.NewRequest("POST", IAMTokenURL, strings.NewReader(tokenFormData.Encode()))
	if err != nil {
		return studentDetails, &AuthError{Code: ErrNetworkError, Message: "failed to create token request"}
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Restore check redirect just in case
	session.Client.CheckRedirect = nil
	tokenResp, err := session.Client.Do(tokenReq)
	if err != nil {
		return studentDetails, &AuthError{Code: ErrNetworkError, Message: "failed to perform token request"}
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != 200 {
		body, _ := io.ReadAll(tokenResp.Body)
		return studentDetails, &AuthError{
			Code:    ErrOIDCParseFailed,
			Message: fmt.Sprintf("failed to get token, status %d: %s", tokenResp.StatusCode, string(body)),
		}
	}

	var tokenData struct {
		IdToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenData); err != nil {
		return studentDetails, &AuthError{Code: ErrOIDCParseFailed, Message: "failed to parse token response"}
	}

	// Kita HAPUS pemanggilan getProfil di sini untuk menghindari 403 Cloudflare.

	// Parse JWT Token terlebih dahulu untuk mengambil Email, NIM (preferred_username), dan Nama
	parts := strings.Split(tokenData.IdToken, ".")
	if len(parts) >= 2 {
		payload := parts[1]
		if l := len(payload) % 4; l > 0 {
			payload += strings.Repeat("=", 4-l)
		}
		if payloadBytes, err := base64.URLEncoding.DecodeString(payload); err == nil {
			var claims map[string]interface{}
			if json.Unmarshal(payloadBytes, &claims) == nil {
				if email, ok := claims["email"].(string); ok {
					studentDetails.Email = email
				}
				if pref, ok := claims["preferred_username"].(string); ok {
					if !strings.Contains(pref, "@") {
						studentDetails.NIM = pref
					}
				}
				if name, ok := claims["name"].(string); ok {
					studentDetails.FullName = PascalCase(name)
				}
			}
		}
	}

	// Jika masih kosong, asumsikan dari input username pengguna
	if studentDetails.NIM == "" && !strings.Contains(username, "@") {
		studentDetails.NIM = username
	}
	if studentDetails.Email == "" && strings.Contains(username, "@") {
		studentDetails.Email = username
	}

	// Buat URL Foto dan cari Angkatan jika NIM berhasil didapatkan
	if studentDetails.NIM != "" && len(studentDetails.NIM) >= 2 {
		angkatanStr := studentDetails.NIM[:2]
		studentDetails.FileFILKOMPhotoURL = fmt.Sprintf(FileFILKOMPhotoURL, angkatanStr, studentDetails.NIM)
		
		if angkatanInt, err := strconv.Atoi(angkatanStr); err == nil {
			studentDetails.ANGKATAN = 2000 + angkatanInt
		}
	}

	return studentDetails, nil
}
