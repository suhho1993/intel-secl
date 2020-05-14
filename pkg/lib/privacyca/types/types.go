package types

type Tpm2Credential struct {
	CredentialBlob []byte
	Secret         []byte
	HeaderBlob     []byte
}
