package ubauth

import (
	"crypto/rand"
	"fmt"
	"strings"
	"unicode"
)

// GenerateUUID membuat UUID v4-like string random
func GenerateUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// GetSubstringBetween mengambil substring di antara prefix dan suffix
func GetSubstringBetween(prefix, suffix, input string) (string, error) {
	firstPart := strings.Split(input, prefix)
	if len(firstPart) < 2 {
		return "", fmt.Errorf("failed to find prefix: %s", prefix)
	}
	secondPart := strings.Split(firstPart[1], suffix)
	if len(secondPart) < 2 {
		return "", fmt.Errorf("failed to find suffix: %s", suffix)
	}
	return secondPart[0], nil
}

// PascalCase mengubah string menjadi format Title Case (tiap kata diawali huruf besar).
func PascalCase(input string) string {
	words := strings.Fields(input)
	result := make([]string, 0, len(words))
	for _, word := range words {
		if len(word) == 0 {
			continue
		}
		runes := []rune(word)
		runes[0] = unicode.ToUpper(runes[0])
		for i := 1; i < len(runes); i++ {
			runes[i] = unicode.ToLower(runes[i])
		}
		result = append(result, string(runes))
	}
	return strings.Join(result, " ")
}
