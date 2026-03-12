package ubauth

// URL endpoint IAM dan portal UB
const (
	BronesURL = "https://brone.ub.ac.id/my/"

	BronesReferer = "https://brone.ub.ac.id/"

	// login IAM UB (Keycloak)
	// Format: session_code, execution, tab_id
	IAMAuthURL = "https://iam.ub.ac.id/auth/realms/ub/login-actions/authenticate?session_code=%s&execution=%s&client_id=brone.ub.ac.id&tab_id=%s"

	FileFILKOMPhotoURL = "https://file-filkom.ub.ac.id/fileupload/assets/foto/20%s/%s.png"
)
