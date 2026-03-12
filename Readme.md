# ubauth

Library Go untuk autentikasi SSO (Single Sign-On) Universitas Brawijaya menggunakan protokol SAML via IAM UB (Keycloak).

```
go get github.com/bem-ub/bem-auth
```

---

## Cara Pakai

```go
import "github.com/bem-filkom/bem-auth/pkg/ubauth"

details, err := ubauth.Auth("215150700111001", "password123")
if err != nil {
    log.Fatal(err)
}

fmt.Println(details.FullName)    // Budi Santoso
fmt.Println(details.NIM)         // 215150700111001
fmt.Println(details.Email)       // budi.santoso@student.ub.ac.id
fmt.Println(details.Faculty)     // Fakultas Ilmu Komputer
fmt.Println(details.StudyProgram) // Teknik Informatika
```

---

## Instalasi

### Via GitHub
```bash
go get github.com/bem-ub/bem-auth
go mod tidy
```

---

## Contoh di HTTP Handler

```go
func LoginHandler(c *gin.Context) {
    var req struct {
        Username string `json:"username"`
        Password string `json:"password"`
    }
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": "invalid request body"})
        return
    }

    details, err := ubauth.Auth(req.Username, req.Password)
    if err != nil {
        var authErr *ubauth.AuthError
        if errors.As(err, &authErr) {
            switch authErr.Code {
            case ubauth.ErrInvalidCredentials:
                c.JSON(401, gin.H{"error": "username atau password salah"})
            case ubauth.ErrNetworkError, ubauth.ErrSessionFailed:
                c.JSON(503, gin.H{"error": "server UB tidak dapat dihubungi"})
            default:
                c.JSON(500, gin.H{"error": "terjadi kesalahan"})
            }
        }
        return
    }

    c.JSON(200, gin.H{
        "nim":           details.NIM,
        "full_name":     details.FullName,
        "email":         details.Email,
        "faculty":       details.Faculty,
        "study_program": details.StudyProgram,
        "photo_url":     details.FileFILKOMPhotoURL,
    })
}
```

---

## API Reference

### `Auth(username, password string) (*StudentDetails, error)`

Melakukan autentikasi SSO UB. `username` bisa berupa NIM atau email mahasiswa.

### Struct `StudentDetails`

| Field | Tipe | Contoh |
|---|---|---|
| `NIM` | string | `215150700111001` |
| `FullName` | string | `Budi Santoso` |
| `Email` | string | `budi.santoso@student.ub.ac.id` |
| `Faculty` | string | `Fakultas Ilmu Komputer` |
| `StudyProgram` | string | `Teknik Informatika` |
| `FileFILKOMPhotoURL` | string | `https://file-filkom.ub.ac.id/...` |

---

## Error Handling

Library menggunakan `*AuthError` dengan kode error spesifik:

| Kode | Penyebab | HTTP Status |
|---|---|---|
| `ErrInvalidCredentials` | Username atau password salah | 401 |
| `ErrSessionFailed` | Gagal mendapat session dari server UB | 503 |
| `ErrNetworkError` | Masalah koneksi jaringan | 503 |
| `ErrSAMLParseFailed` | Gagal memproses token SAML | 500 |
| `ErrUnexpected` | Error tidak dikenali dari server | 500 |

```go
details, err := ubauth.Auth(username, password)
if err != nil {
    var authErr *ubauth.AuthError
    if errors.As(err, &authErr) {
        switch authErr.Code {
        case ubauth.ErrInvalidCredentials:
            // → 401
        case ubauth.ErrSessionFailed, ubauth.ErrNetworkError:
            // → 503
        case ubauth.ErrSAMLParseFailed, ubauth.ErrUnexpected:
            // → 500
        }
    }
}
```

---

## Struktur File

```
bem-auth/
├── go.mod
├── examples/
│   └── login_example.go       # Contoh penggunaan standalone
└── pkg/ubauth/
    ├── auth.go                # Fungsi Auth() — entry point utama
    ├── config.go              # Konstanta URL (brone, IAM, SIAKAD, FILKOM)
    ├── headers.go             # HTTP headers browser-like
    ├── session.go             # GetSession() — ambil cookies & form params
    ├── saml.go                # ParseSAMLResponse() — decode & parse SAML XML
    ├── types.go               # Struct: Session, StudentDetails, AuthError
    └── util.go                # Helper: GetSubstringBetween, PascalCase
```

---

Referensi: [ahmdyaasiin/ub-auth-without-notification](https://github.com/ahmdyaasiin/ub-auth-without-notification)  
