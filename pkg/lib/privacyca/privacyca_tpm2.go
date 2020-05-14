package privacyca

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	consts "github.com/intel-secl/intel-secl/v3/pkg/lib/privacyca/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/privacyca/tpm2utils"
	model "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/pkg/errors"
)

//-------------------------------------------------------------------------------------------------
// Implementation
//-------------------------------------------------------------------------------------------------

// PrivacyCATpm2 will be having ProcessIdentityRequest method for Baremetal with tpm version 2.0
type PrivacyCATpm2 struct {
}

/**
 * <p>Process an IdentityRequest Object returned from a TPM.
 * This function will encrypt an blob of data using the public portion of a key found inside the IdentityRequest object.
 * If a TPM can decrypt the blob of data, that serves as a proof of ownership over the private portion of that key.
 * </p>
 * @param request object from IdentityRequest
 * @param pubEk public portion of the Tpm Endorsement Certificate
 * @param identityChallenge arbitrary data the PrivacyCA wishes to encrypt. Can be a random challenge or an AIKCert, etc.
 * @return IdentityProofRequest.
 */
func (privacycatpm2 *PrivacyCATpm2) ProcessIdentityRequest(request model.IdentityRequest, pubEk crypto.PublicKey, identityChallenge []byte) (model.IdentityProofRequest, error) {
	log.Trace("privacyca:ProcessIdentityRequest() Entering")
	defer log.Trace("privacyca:ProcessIdentityRequest() Leaving")

	key, err := crypt.GetRandomBytes(16)
	if err != nil {
		return model.IdentityProofRequest{}, errors.Wrap(err, "privacyca:ProcessIdentityRequest() Unable to generate Random Bytes for key")
	}

	iv, err := crypt.GetRandomBytes(16)
	if err != nil {
		return model.IdentityProofRequest{}, errors.Wrap(err, "privacyca:ProcessIdentityRequest() Unable to generate Random Bytes for iv")
	}

	encryptedIdentityChallenge, err := tpm2utils.EncryptSym(identityChallenge, key, iv, "CBC", "AES")
	if err != nil {
		return model.IdentityProofRequest{}, errors.Wrap(err, "privacyca:ProcessIdentityRequest() Error while performing EncryptSym")
	}
	encryptedIdentityChallengeBlob := new(bytes.Buffer)
	binary.Write(encryptedIdentityChallengeBlob, binary.BigEndian, iv)
	binary.Write(encryptedIdentityChallengeBlob, binary.BigEndian, encryptedIdentityChallenge)
	credential, err := tpm2utils.MakeCredential(pubEk, consts.TPM2AlgorithmSymmetricAES, consts.SymmetricKeyBits128, crypto.SHA256, key, request.AikName)
	if err != nil {
		return model.IdentityProofRequest{}, errors.Errorf("privacyca:ProcessIdentityRequest() Error while performing MakeCredential %+v", err)
	}

	symmetricKeyParams := model.TpmSymmetricKeyParams{
		TpmAlgId: consts.TPM_ALG_AES,
		TpmAlgEncScheme: consts.TPM_ES_NONE,
		TpmAlgSignatureScheme: 0,
	}

	identityProofRequest := model.IdentityProofRequest{
		Secret:       credential.Secret,
		Credential:   credential.CredentialBlob,
		TpmSymmetricKeyParams: symmetricKeyParams,
		SymmetricBlob: encryptedIdentityChallengeBlob.Bytes(),
	}

	return identityProofRequest, nil
}