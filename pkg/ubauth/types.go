package ubauth

import (
	"encoding/xml"
	"net/http"
)

// Session menyimpan state HTTP session untuk proses autentikasi SSO
type Session struct {
	Client              *http.Client
	AuthSessionID       string
	AuthSessionIDLegacy string
	KCRestart           string
	SessionCode         string
	Execution           string
	TabID               string
}

// StudentDetails berisi informasi mahasiswa yang didapat dari SAML response
type StudentDetails struct {
	NIM                string
	FullName           string
	Email              string
	Faculty            string
	StudyProgram       string
	FileFILKOMPhotoURL string
}

// SAMLResponse adalah root element dari XML SAML
type SAMLResponse struct {
	XMLName   xml.Name  `xml:"Response"`
	Assertion Assertion `xml:"Assertion"`
}

// Assertion adalah bagian Assertion dari SAML XML
type Assertion struct {
	XMLName            xml.Name           `xml:"Assertion"`
	AttributeStatement AttributeStatement `xml:"AttributeStatement"`
}

// AttributeStatement menampung daftar atribut dalam SAML
type AttributeStatement struct {
	XMLName    xml.Name    `xml:"AttributeStatement"`
	Attributes []Attribute `xml:"Attribute"`
}

// Attribute merepresentasikan satu atribut SAML (nama + nilai)
type Attribute struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:"AttributeValue"`
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
	ErrSAMLParseFailed                         // gagal parse SAML
	ErrUnexpected                              // error tak terduga
)
