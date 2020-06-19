/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package rules

const (
	FaultPrefix                                     = "com.intel.mtwilson.core.verifier.policy.fault."
	FaultAikCertificateExpired                      = FaultPrefix + "AikCertificateExpired"
	FaultAikCertificateMissing                      = FaultPrefix + "AikCertificateMissing"
	FaultAikCertificateNotTrusted                   = FaultPrefix + "AikCertificateNotTrusted"
	FaultAikCertificateNotYetValid                  = FaultPrefix + "AikCertificateNotYetValid"
	FaultAssetTagMismatch                           = FaultPrefix + "AssetTagMismatch"
	FaultAssetTagMissing                            = FaultPrefix + "AssetTagMissing"
	FaultAssetTagNotProvisioned                     = FaultPrefix + "AssetTagNotProvisioned"
	FaultFlavorSignatureMissing                     = FaultPrefix + "FlavorSignatureMissing"
	FaultFlavorSignatureNotTrusted                  = FaultPrefix + "FlavorSignatureNotTrusted"
	FaultFlavorSignatureVerificationFailed          = FaultPrefix + "FlavorSignatureVerificationFailed"
	FaultPcrEventLogContainsUnexpectedEntries       = FaultPrefix + "PcrEventLogContainsUnexpectedEntries"
	FaultPcrEventLogInvalid                         = FaultPrefix + "PcrEventLogInvalid"
	FaultPcrEventLogMissing                         = FaultPrefix + "PcrEventLogMissing"
	FaultPcrEventLogMissingExpectedEntries          = FaultPrefix + "PcrEventLogMissingExpectedEntries"
	FaultPcrManifestMissing                         = FaultPrefix + "PcrManifestMissing"
	FaultPcrValueMismatch                           = FaultPrefix + "PcrValueMismatch"
	FaultPcrValueMismatchSHA1                       = FaultPcrValueMismatch + "SHA1"
	FaultPcrValueMismatchSHA256                     = FaultPcrValueMismatch + "SHA256"
	FaultPcrValueMissing                            = FaultPrefix + "PcrValueMissing"
	FaultTagCertificateExpired                      = FaultPrefix + "TagCertificateExpired"
	FaultTagCertificateMissing                      = FaultPrefix + "TagCertificateMissing"
	FaultTagCertificateNotTrusted                   = FaultPrefix + "TagCertificateNotTrusted"
	FaultTagCertificateNotYetValid                  = FaultPrefix + "TagCertificateNotYetValid"
	FaultXmlMeasurementLogContainsUnexpectedEntries = FaultPrefix + "XmlMeasurementLogContainsUnexpectedEntries"
	FaultXmlMeasurementLogInvalid                   = FaultPrefix + "XmlMeasurementLogInvalid"
	FaultXmlMeasurementLogMissing                   = FaultPrefix + "XmlMeasurementLogMissing"
	FaultXmlMeasurementLogMissingExpectedEntries    = FaultPrefix + "XmlMeasurementLogMissingExpectedEntries"
	FaultXmlMeasurementLogValueMismatchEntries384   = FaultPrefix + "XmlMeasurementLogValueMismatchEntriesSha384"
	FaultXmlMeasurementsDigestValueMismatch         = FaultPrefix + "XmlMeasurementsDigestValueMismatch"
	FaultXmlMeasurementValueMismatch                = FaultPrefix + "XmlMeasurementValueMismatch"
)
