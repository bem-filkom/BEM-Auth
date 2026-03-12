package ubauth

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
)

// ParseSAMLResponse men-decode dan mem-parse SAML response base64 dari IAM UB,
func ParseSAMLResponse(samlBase64 string) (*StudentDetails, error) {
	studentDetails := new(StudentDetails)

	decoded, err := base64.StdEncoding.DecodeString(samlBase64)
	if err != nil {
		return studentDetails, &AuthError{
			Code:    ErrSAMLParseFailed,
			Message: fmt.Sprintf("failed to decode SAML response: %v", err),
		}
	}

	var response SAMLResponse
	if err := xml.Unmarshal(decoded, &response); err != nil {
		return studentDetails, &AuthError{
			Code:    ErrSAMLParseFailed,
			Message: fmt.Sprintf("failed to parse SAML XML: %v", err),
		}
	}

	for _, attr := range response.Assertion.AttributeStatement.Attributes {
		switch attr.Name {
		case "nim":
			studentDetails.NIM = attr.Value
		case "email":
			studentDetails.Email = attr.Value
		case "fullName":
			studentDetails.FullName = PascalCase(attr.Value)
		case "fakultas":
			studentDetails.Faculty = fmt.Sprintf("Fakultas %s", attr.Value)
		case "prodi":
			studentDetails.StudyProgram = attr.Value
		}
	}

	// Generate URL foto dari NIM (2 digit pertama = angkatan)
	if len(studentDetails.NIM) >= 2 {
		yearPrefix := studentDetails.NIM[:2]
		nim := studentDetails.NIM
		studentDetails.FileFILKOMPhotoURL = fmt.Sprintf(FileFILKOMPhotoURL, yearPrefix, nim)
	}

	return studentDetails, nil
}
