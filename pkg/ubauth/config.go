package ubauth

// URL endpoint IAM dan portal UB
const (
	BronesURL = "https://iam.ub.ac.id/auth/realms/ub/protocol/openid-connect/auth?client_id=siam&redirect_uri=https%3A%2F%2Fsiam.ub.ac.id%2Fmahasiswa&state=a2c37656-94e8-4f96-9777-a7e358ca118a&response_mode=fragment&response_type=code&scope=openid&nonce=3625d9cd-68d7-4b8c-8af2-860868b92963"

	BronesReferer = "https://siam.ub.ac.id/"

	IAMTokenURL = "https://iam.ub.ac.id/auth/realms/ub/protocol/openid-connect/token"

	FileFILKOMPhotoURL = "https://file-filkom.ub.ac.id/fileupload/assets/foto/20%s/%s.png"
)
