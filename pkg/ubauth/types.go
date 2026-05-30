package ubauth

import (
	"net/http"
)

// Session menyimpan state HTTP session untuk proses autentikasi SSO
type Session struct {
	Client              *http.Client
	AuthSessionID       string
	AuthSessionIDLegacy string
	KCRestart           string
	LoginActionURL      string
}

// StudentDetails berisi informasi mahasiswa yang didapat dari SAML response
type StudentDetails struct {
	NIM                string
	FullName           string
	Email              string
	Faculty            string
	StudyProgram       string
	FileFILKOMPhotoURL string
	ANGKATAN           int    // tahun angkatan, misal 2024
}


// AuthError adalah custom error type untuk membedakan jenis kesalahan auth
type AuthError struct {
	Code    AuthErrorCode
	Message string
}

func (e *AuthError) Error() string {
	return e.Message
}

// AuthErrorCode mendefinisikan jenis-jenis error yang mungkin terjadi
type AuthErrorCode int

const (
	ErrInvalidCredentials AuthErrorCode = iota // username/password salah
	ErrSessionFailed                           // gagal mendapatkan session
	ErrNetworkError                            // error jaringan
	ErrOIDCParseFailed                         // gagal parse OIDC
	ErrUnexpected                              // error tak terduga
)
