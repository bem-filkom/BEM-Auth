package ubauth

import (
	"encoding/base64"
	"encoding/json"
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
//   - ErrOIDCParseFailed    : gagal memproses OIDC token
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

	// Step 4: Fetch Profile from API UB
	reqProfil, err := http.NewRequest("GET", "https://api.ub.ac.id/siam/mahasiswa/getProfil", nil)
	if err != nil {
		return studentDetails, &AuthError{Code: ErrNetworkError, Message: "failed to create getProfil request"}
	}
	for k, v := range GetHeaders() {
		reqProfil.Header.Set(k, v)
	}
	reqProfil.Header.Set("Authorization", "Bearer "+tokenData.AccessToken)
	reqProfil.Header.Set("Accept", "application/json")

	respProfil, err := session.Client.Do(reqProfil)
	if err != nil {
		return studentDetails, &AuthError{Code: ErrNetworkError, Message: "failed to perform getProfil request"}
	}
	defer respProfil.Body.Close()

	if respProfil.StatusCode != 200 {
		body, _ := io.ReadAll(respProfil.Body)
		return studentDetails, &AuthError{
			Code:    ErrOIDCParseFailed,
			Message: fmt.Sprintf("failed to get profil, status %d: %s", respProfil.StatusCode, string(body)),
		}
	}

	bodyBytes, err := io.ReadAll(respProfil.Body)
	if err != nil {
		return studentDetails, &AuthError{Code: ErrNetworkError, Message: "failed to read profil response body"}
	}

	var profilArray []map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &profilArray); err != nil {
		return studentDetails, &AuthError{
			Code:    ErrOIDCParseFailed,
			Message: fmt.Sprintf("failed to parse profil response, err: %v, body: %s", err, string(bodyBytes)),
		}
	}

	// // Tampilkan raw JSON untuk debug di console (bisa dihapus nanti jika sudah stabil)
	// profilJSON, _ := json.MarshalIndent(profilArray, "", "  ")
	// fmt.Println("=== DEBUG PROFIL API ===")
	// fmt.Println(string(profilJSON))
	// fmt.Println("========================")

	if len(profilArray) > 0 {
		data := profilArray[0]

		if nim, ok := data["NIM"].(string); ok {
			studentDetails.NIM = nim
		}
		if nama, ok := data["NAMA"].(string); ok {
			studentDetails.FullName = nama
		}
		if fakultas, ok := data["FAKULTAS"].(string); ok {
			studentDetails.Faculty = fakultas
		}
		if prodi, ok := data["PROGRAM"].(string); ok {
			studentDetails.StudyProgram = prodi
		}
		if angkatan, ok := data["ANGKATAN"].(float64); ok {
			studentDetails.ANGKATAN = int(angkatan)
		}

		// Email tidak ada di getProfil, kita ambil dari id_token
		parts := strings.Split(tokenData.IdToken, ".")
		if len(parts) >= 2 {
			if payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
				var claims map[string]interface{}
				if json.Unmarshal(payloadBytes, &claims) == nil {
					if email, ok := claims["email"].(string); ok {
						studentDetails.Email = email
					}
				}
			}
		}

		// Fill photo URL (tetap gunakan pola lama FILKOM atau dari API SIAM)
		if studentDetails.NIM != "" && len(studentDetails.NIM) >= 2 {
			angkatanStr := studentDetails.NIM[:2]
			studentDetails.FileFILKOMPhotoURL = fmt.Sprintf(FileFILKOMPhotoURL, angkatanStr, studentDetails.NIM)
		}
	}

	return studentDetails, nil
}
