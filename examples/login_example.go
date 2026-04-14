package main

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"

	"github.com/bem-filkom/bem-auth/pkg/ubauth"
)

func main() {
	// Load .env jika ada (untuk development)
	_ = godotenv.Load()

	username := os.Getenv("EMAIL_OR_NIM")
	password := os.Getenv("PASSWORD")

	if username == "" || password == "" {
		log.Fatal("Set EMAIL_OR_NIM dan PASSWORD di environment atau file .env")
	}

	fmt.Println(" Mencoba login ke SSO UB...")

	details, err := ubauth.Auth(username, password)
	if err != nil {
		var authErr *ubauth.AuthError
		if errors.As(err, &authErr) {
			switch authErr.Code {
			case ubauth.ErrInvalidCredentials:
				log.Fatal("Username atau password salah")
			case ubauth.ErrSessionFailed:
				log.Fatal("Gagal mendapatkan session dari server UB")
			case ubauth.ErrNetworkError:
				log.Fatal("Gagal terhubung ke server — cek koneksi internet")
			case ubauth.ErrSAMLParseFailed:
				log.Fatal("Gagal memproses token autentikasi")
			default:
				log.Fatalf("Error tak dikenal: %v", err)
			}
		}
		log.Fatalf("Login gagal: %v", err)
	}

	fmt.Println("Login berhasil!")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("  Nama        : %s\n", details.FullName)
	fmt.Printf("  NIM         : %s\n", details.NIM)
	fmt.Printf("  Angkatan    : %d\n", details.Angkatan)
	fmt.Printf("  Email       : %s\n", details.Email)
	fmt.Printf("  Fakultas    : %s\n", details.Faculty)
	fmt.Printf("  Prodi       : %s\n", details.StudyProgram)
	fmt.Printf("  Foto FILKOM : %s\n", details.FileFILKOMPhotoURL)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

}
