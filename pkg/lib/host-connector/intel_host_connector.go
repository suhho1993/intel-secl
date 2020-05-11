/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package host_connector

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"github.com/pkg/errors"
	client "github.com/intel-secl/intel-secl/v3/pkg/clients/ta"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/util"
	taModel "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
)

type IntelConnector struct {
	client client.TAClient
}

func (ic *IntelConnector) GetHostDetails() (taModel.HostInfo, error) {

	log.Trace("intel_host_connector:GetHostDetails() Entering")
	defer log.Trace("host_connector_factory:GetHostDetails() Leaving")
	hostInfo, err := ic.client.GetHostInfo()
	return hostInfo, err
}


func (ic *IntelConnector) GetHostManifest(nonce string, pcrList []int, pcrBankList []string) (types.HostManifest, error) {

	log.Trace("intel_host_connector:GetHostManifest() Entering")
	defer log.Trace("host_connector_factory:GetHostManifest() Leaving")
	var verificationNonce string
	var hostManifest types.HostManifest
	//check if AIK Certificate is present on host before getting host manifest
	aikInDER, err := ic.client.GetAIK()
	if err != nil || len(aikInDER) == 0 {
		return types.HostManifest{}, errors.Wrap(err, "intel_host_connector:GetHostManifest() Invalid AIK" +
			"certificate returned by TA")
	}
	secLog.Debug("intel_host_connector:GetHostManifest() Successfully received AIK certificate in DER format")

	tpmQuoteResponse, err := ic.client.GetTPMQuote(nonce, pcrList, pcrBankList)
	if err != nil  {
		return types.HostManifest{}, errors.Wrap(err, "intel_host_connector:GetHostManifest() Error getting TPM " +
			"quote response")
	}

	nonceInBytes, err := base64.StdEncoding.DecodeString(nonce)
	verificationNonce, err = util.GetVerificationNonce(nonceInBytes, ic.client.GetBaseURL().Host, tpmQuoteResponse)
	if err != nil {
		return types.HostManifest{}, err
	}
	secLog.Debug("intel_host_connector:GetHostManifest() Updated Verification nonce is : ", verificationNonce)

	aikCertInBytes, err := base64.StdEncoding.DecodeString(tpmQuoteResponse.Aik)
	if err != nil {
		return types.HostManifest{}, errors.Wrap(err, "intel_host_connector:GetHostManifest() Error decoding" +
			"AIK certificate to bytes")
	}

	//Convert base64 encoded AIK to Pem format
	aikPem, _ := pem.Decode(aikCertInBytes)
	aikCertificate, err := x509.ParseCertificate(aikPem.Bytes)

	if err != nil {
		return types.HostManifest{}, errors.Wrap(err, "intel_host_connector:GetHostManifest() Error parsing " +
			"AIK certicate")
	}

	eventLogBytes, err := base64.StdEncoding.DecodeString(tpmQuoteResponse.EventLog)
	if err != nil {
		return types.HostManifest{}, errors.Wrap(err, "intel_host_connector:GetHostManifest() Error converting " +
			"event log to bytes")
	}
	decodedEventLog := string(eventLogBytes)
	log.Info("intel_host_connector:GetHostManifest() Retrieved event log from TPM quote response")

	tpmQuoteInBytes , err := base64.StdEncoding.DecodeString(tpmQuoteResponse.Quote)
	if err != nil {
		return types.HostManifest{}, errors.Wrap(err, "intel_host_connector:GetHostManifest() Error converting "+
			"tpm quote to bytes")
	}

	verificationNonceInBytes, err :=base64.StdEncoding.DecodeString(verificationNonce)
	if err != nil {
		return types.HostManifest{}, errors.Wrap(err, "intel_host_connector:GetHostManifest() Error converting " +
			"nonce to bytes")
	}
	log.Info("intel_host_connector:GetHostManifest() Verifying quote and retrieving PCR manifest from TPM quote " +
		"response ...")
	pcrManifest, err := util.VerifyQuoteAndGetPCRManifest(decodedEventLog, verificationNonceInBytes,
		tpmQuoteInBytes, aikCertificate)
	if err != nil {
		return types.HostManifest{}, errors.Wrap(err, "intel_host_connector:GetHostManifest() Error verifying " +
			"TPM Quote")
	}
	log.Info("intel_host_connector:GetHostManifest() Successfully retrieved PCR manifest from quote")

	bindingKeyBytes, err := ic.client.GetBindingKeyCertificate()
	if err !=  nil {
		return types.HostManifest{}, errors.Wrap(err, "intel_host_connector:GetHostManifest() Error getting " +
			"binding key certificate from TA")
	}

	// The bindingkey certificate may not always be returned by the trust-agent,
	// it will only be there if workload-agent is installed.
	bindingKeyCertificateBase64 := ""
	if bindingKeyBytes != nil && len(bindingKeyBytes) > 0{
		bindingKeyCertificate, _ := pem.Decode(bindingKeyBytes)
		bindingKeyCertificateBase64 = base64.StdEncoding.EncodeToString(bindingKeyCertificate.Bytes)
	} 
	
	aikCertificateBase64 := base64.StdEncoding.EncodeToString(aikPem.Bytes)

	hostManifest.HostInfo, err = ic.client.GetHostInfo()
	if err !=  nil {
		return types.HostManifest{}, errors.Wrap(err, "intel_host_connector:GetHostManifest() Error getting " +
			"host details from TA")
	}
	hostManifest.PcrManifest = pcrManifest
	hostManifest.AIKCertificate = aikCertificateBase64
	hostManifest.AssetTagDigest = tpmQuoteResponse.AssetTag
	hostManifest.BindingKeyCertificate = bindingKeyCertificateBase64
	hostManifest.MeasurementXmls = tpmQuoteResponse.TcbMeasurements.TcbMeasurements

	hostManifestJson, err := json.Marshal(hostManifest)
	if err != nil {
		return types.HostManifest{}, errors.Wrap(err, "intel_host_connector:GetHostManifest() Error " +
			"marshalling host manifest to JSON")
	}
	log.Debugf("intel_host_connector:GetHostManifest() Host Manifest : %s", string(hostManifestJson))
	log.Info("intel_host_connector:GetHostManifest() Host manifest created successfully")
	return hostManifest, err
}

func (ic *IntelConnector) DeployAssetTag(hardwareUUID, tag string) error {

	log.Trace("intel_host_connector:DeployAssetTag() Entering")
	defer log.Trace("host_connector_factory:DeployAssetTag() Leaving")
	err := ic.client.DeployAssetTag(hardwareUUID, tag)
	return err
}

func (ic *IntelConnector) DeploySoftwareManifest(manifest taModel.Manifest) error {

	log.Trace("intel_host_connector:DeploySoftwareManifest() Entering")
	defer log.Trace("host_connector_factory:DeploySoftwareManifest() Leaving")
	err := ic.client.DeploySoftwareManifest(manifest)
	return err
}

func (ic *IntelConnector) GetMeasurementFromManifest(manifest taModel.Manifest) (taModel.Measurement, error) {

	log.Trace("intel_host_connector:GetMeasurementFromManifest() Entering")
	defer log.Trace("host_connector_factory:GetMeasurementFromManifest() Leaving")
	measurement, err := ic.client.GetMeasurementFromManifest(manifest)
	return measurement, err
}
