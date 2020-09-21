/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package utils

import (
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/intel-secl/intel-secl/v3/pkg/hvs/utils"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/validation"
	"github.com/pkg/errors"
)

var defaultLog = log.GetDefaultLogger()
var secLog = log.GetSecurityLogger()

var certificateSearchParams = map[string]bool{"subjectEqualTo": true, "subjectContains": true, "issuerEqualTo": true, "issuerContains": true,
	"validOn": true, "validBefore": true, "validAfter": true}

//  GetCertificate checks for pem formatted certificate in the Import request and returns a valid Certificate
func GetCertificate(request *http.Request) ([]byte, int, error) {
	defaultLog.Trace("utils/certificate:GetCertificate() Entering")
	defer defaultLog.Trace("utils/certificate:GetCertificate() Leaving")

	if request.Header.Get("Content-Type") != constants.HTTPMediaTypePemFile {
		return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
	}

	if request.ContentLength == 0 {
		secLog.Error("utils/certificate:GetCertificate() The request body was not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body was not provided"}
	}

	bytes, err := ioutil.ReadAll(request.Body)
	if err != nil {
		secLog.WithError(err).Errorf("utils/certificate:GetCertificate() %s : Unable to read request body", commLogMsg.InvalidInputBadEncoding)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to read request body"}
	}

	_, err = crypt.GetCertFromPem(bytes)
	if err != nil {
		secLog.WithError(err).Errorf("utils/certificate:GetCertificate() %s : Validation failed for certificate", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	return bytes, http.StatusOK, nil
}

//  GetCertificateFilterCriteria checks for set filter params in the Search request and returns a valid CertificateFilterCriteria
func GetCertificateFilterCriteria(params url.Values) (*models.CertificateFilterCriteria, error) {
	defaultLog.Trace("utils/certificate:GetCertificateFilterCriteria() Entering")
	defer defaultLog.Trace("utils/certificate:GetCertificateFilterCriteria() Leaving")

	criteria := models.CertificateFilterCriteria{}
	if err := utils.ValidateQueryParams(params, certificateSearchParams); err != nil {
		return nil, err
	}

	// subjectEqualTo
	if param := strings.TrimSpace(params.Get("subjectEqualTo")); param != "" {
		if err := validation.ValidateStrings([]string{param}); err != nil {
			return nil, errors.New("Valid contents for subjectEqualTo must be specified")
		}
		criteria.SubjectEqualTo = param
	}

	// subjectContains
	if param := strings.TrimSpace(params.Get("subjectContains")); param != "" {
		if err := validation.ValidateStrings([]string{param}); err != nil {
			return nil, errors.New("Valid contents for subjectContains must be specified")
		}
		criteria.SubjectContains = param
	}

	// issuerEqualTo
	if param := strings.TrimSpace(params.Get("issuerEqualTo")); param != "" {
		if err := validation.ValidateIssuer(param); err == nil {
			criteria.IssuerEqualTo = param
		} else {
			return nil, errors.New("Valid contents for issuerEqualTo must be specified")
		}
	}

	// issuerContains
	if param := strings.TrimSpace(params.Get("issuerContains")); param != "" {
		if err := validation.ValidateIssuer(param); err == nil {
			criteria.IssuerContains = param
		} else {
			return nil, errors.New("Valid contents for issuerContains must be specified")
		}
	}

	// validOn
	if param := strings.TrimSpace(params.Get("validOn")); param != "" {
		pTime, err := time.Parse(time.RFC3339, param)
		if err != nil {
			return nil, errors.Wrap(err, "Valid date (YYYY-MM-DDThh:mm:ssZ) for validOn must be specified")
		}
		criteria.ValidOn = pTime
	}

	// validBefore
	if param := strings.TrimSpace(params.Get("validBefore")); param != "" {
		pTime, err := time.Parse(time.RFC3339, param)
		if err != nil {
			return nil, errors.Wrap(err, "Valid date (YYYY-MM-DDThh:mm:ssZ) for validBefore must be specified")
		}
		criteria.ValidBefore = pTime
	}

	// validAfter
	if param := strings.TrimSpace(params.Get("validAfter")); param != "" {
		pTime, err := time.Parse(time.RFC3339, param)
		if err != nil {
			return nil, errors.Wrap(err, "Valid date (YYYY-MM-DDThh:mm:ssZ) for validAfter must be specified")
		}
		criteria.ValidAfter = pTime
	}

	return &criteria, nil
}
