/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/config"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
)

var defaultLog = log.GetDefaultLogger()

// default list in case HVS_TLS_POLICY_ALLOW is not configured
var DefaultAllowed = []string {"certificate"}

const (
	TrustFirstCertificate = "TRUST_FIRST_CERTIFICATE"
)

type TlsPolicyFilter struct {

}

func (t TlsPolicyFilter) IsTlsPolicyAllowed(tlsPolicyId string) bool {
	defaultLog.Trace("tls_policy_filter:isTlsPolicyAllowed() Entering")
	defer defaultLog.Trace("tls_policy_filter:isTlsPolicyAllowed() Leaving")

	tlsAllowed := config.Global().TlsPolicy.Allow
	if len(tlsAllowed) == 0 {
		tlsAllowed = DefaultAllowed
	}

	//for debugging purpose
	for _, item := range tlsAllowed {
		defaultLog.Debugf("tls_policy_filter:isTlsPolicyAllowed() Allowed tls policy in configuration: %s", item)
		if item == tlsPolicyId {
			return true
		}
	}
	return false
}

func (t TlsPolicyFilter) GetDefaultTlsPolicyType() string {
	defaultLog.Trace("tls_policy_filter:getDefaultTlsPolicyType() Entering")
	defer defaultLog.Trace("tls_policy_filter:getDefaultTlsPolicyType() Leaving")

	tlsPolicyDefault := config.Global().TlsPolicy.Default
	// set to TRUST_FIRST_CERTIFICATE in case the default is not set in the configuration
	if tlsPolicyDefault == "" {
		tlsPolicyDefault = TrustFirstCertificate
	}
	return tlsPolicyDefault
}
