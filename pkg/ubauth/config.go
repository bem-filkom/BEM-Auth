package ubauth

// URL endpoint IAM dan portal UB
const (
	// Brone endpoints
	BronesURL     = "https://brone.ub.ac.id/my/"
	BronesReferer = "https://brone.ub.ac.id/"
	IAMAuthURL    = "https://iam.ub.ac.id/auth/realms/ub/login-actions/authenticate?session_code=%s&execution=%s&client_id=brone.ub.ac.id&tab_id=%s"

	// Siam endpoints
	SiamURL     = "https://iam.ub.ac.id/auth/realms/ub/protocol/openid-connect/auth?client_id=siam&redirect_uri=https%%3A%%2F%%2Fsiam.ub.ac.id%%2Fmahasiswa&state=%s&response_mode=fragment&response_type=code&scope=openid&nonce=%s"
	SiamReferer = "https://siam.ub.ac.id/"
	IAMTokenURL = "https://iam.ub.ac.id/auth/realms/ub/protocol/openid-connect/token"

	FileFILKOMPhotoURL = "https://file-filkom.ub.ac.id/fileupload/assets/foto/20%s/%s.png"
)
