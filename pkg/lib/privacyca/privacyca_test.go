package privacyca_test

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	privacyca "github.com/intel-secl/intel-secl/v3/pkg/lib/privacyca"
	consts "github.com/intel-secl/intel-secl/v3/pkg/lib/privacyca/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/privacyca/tpm2utils"
	"github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestProcessMakeCredential(t *testing.T) {
	privKey, certStr, err := crypt.CreateSelfSignedCertAndRSAPrivKeys(2048)
	assert.NoError(t, err)
	block, _ := pem.Decode([]byte(certStr))
	cert, err := x509.ParseCertificate(block.Bytes)
	assert.NoError(t, err)

	rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)

	//Generate identityChallengeNonce
	identityChallengeNonce, _ := crypt.GetRandomBytes(32)
	identityRequest := model.IdentityRequest{
		TpmVersion: "2.0",
		AikName: []byte{0, 11, 63, 66, 56, 152, 253, 128, 164, 49, 231, 162, 169, 14, 118, 72, 248, 151, 117, 166, 215,
			235, 210, 181, 92, 167, 94, 113, 24, 131, 10, 5, 12, 85, 252},
	}

	privacycaTpm2, err := privacyca.NewPrivacyCA(identityRequest)

	tpm2IdentityProofReq, err := privacycaTpm2.ProcessIdentityRequest(identityRequest, rsaPublicKey, identityChallengeNonce)
	assert.NoError(t, err)
	indentityBuf := new(bytes.Buffer)
	binary.Write(indentityBuf, binary.BigEndian, []byte(consts.IDENTITY))
	binary.Write(indentityBuf, binary.BigEndian, byte(0))

	//Get the seed using asymmetric decryption
	var encryptedSecretLength int16
	buf := bytes.NewBuffer(tpm2IdentityProofReq.Secret)
	binary.Read(buf, binary.BigEndian, &encryptedSecretLength)
	assert.Equal(t, 256, int(encryptedSecretLength))
	secret := buf.Next(int(encryptedSecretLength))
	assert.Equal(t, 256, len(secret))

	seed, err := tpm2utils.Tpm2DecryptAsym(secret, privKey, consts.TPM_ALG_ID_SHA256, indentityBuf.Bytes())
	assert.NoError(t, err)

	//Derive the symmetric key using seed
	symKey, err := tpm2utils.KDFa(crypto.SHA256, seed, consts.STORAGE, identityRequest.AikName, nil, 128)

	var encryptedCredentialLength int16
	var integrityLength int16
	buf = bytes.NewBuffer(tpm2IdentityProofReq.Credential)
	binary.Read(buf, binary.BigEndian, &encryptedCredentialLength)
	binary.Read(buf, binary.BigEndian, &integrityLength)
	buf.Next(int(integrityLength))
	encryptedCredential := buf.Next(int(encryptedCredentialLength) - int(integrityLength) - consts.SHORT_BYTES)
	iv := make([]byte, aes.BlockSize)

	//Decrypt the encryptedCredential for getting the symmetric key from which the symmetric key for decrypting the identityChallengeNonce can be decrypted
	key, err := tpm2utils.DecryptSym(encryptedCredential, symKey, iv,"CBF", consts.TPM2AlgorithmSymmetricAES)
	assert.NoError(t, err)
	buf = bytes.NewBuffer(key)
	binary.Read(buf, binary.BigEndian, &encryptedCredentialLength)
	key = buf.Next(int(encryptedCredentialLength))
	symmetricBlob := tpm2IdentityProofReq.SymmetricBlob
	buf = bytes.NewBuffer(symmetricBlob)
	iv = buf.Next(int(16))
	secret = buf.Next(len(symmetricBlob) - 16)

	//Decrypt the credential secret to retrive identityChallengeNonce
	dataBlob, err := tpm2utils.DecryptSym(secret, key, iv,"CBC", consts.TPM2AlgorithmSymmetricAES)
	assert.NoError(t, err)
	assert.Equal(t, dataBlob, identityChallengeNonce)
}