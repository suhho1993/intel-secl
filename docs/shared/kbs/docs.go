// Key Broker Service
//
// The Key Broker Service (KBS) is a component of Intel® Security Libraries (ISecL).
// It interfaces with a backend key management system to create, delete and retrieve
// keys, while providing a user defined policy for key retrieval based on Intel® hardware
// root of trust.
// During installation, a backend key server (KMIP, Barbican, etc.) can be associated with
// this service. If no backend key server is associated with this service, all generated keys are
// stored as files on the local disk.
//
//  License: Copyright (C) 2020 Intel Corporation. SPDX-License-Identifier: BSD-3-Clause
//
//  Version: 3.2.0
//  Host: kbs.com:9443
//  BasePath: /kbs/v1/
//
//  Schemes: https
//
//  SecurityDefinitions:
//   bearerAuth:
//     type: apiKey
//     in: header
//     name: Authorization
//     description: Enter your bearer token in the format **Bearer &lt;token&gt;**
//
// swagger:meta
package kbs
