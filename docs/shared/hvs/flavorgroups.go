/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import "github.com/intel-secl/intel-secl/v3/pkg/model/hvs"

// FlavorGroup response payload
// swagger:response FlavorGroup
type FlavorGroup struct {
	// in:body
	Body hvs.FlavorGroup
}

// FlavorgroupCollection response payload
// swagger:response FlavorgroupCollection
type FlavorgroupCollection struct {
	// in:body
	Body hvs.FlavorgroupCollection
}


// ---
//
// swagger:operation GET /flavorgroups Flavorgroups Search
// ---
//
// description: |
//
//   <b>Flavor Group</b>: A flavor group represents a collection of flavors that has a specified policy, which is used
//   to verify host against those flavors. Flavors can be added to a flavor group, and hosts can be associated with a
//   flavor group.
//
//   The flavor group policy lists the individual flavor parts and the match policy rules associated with each one.
//
//   <b>Flavor Part</b>: The type or classification of the flavor. For more information on flavor parts, see the
//   product guide.
//       - PLATFORM
//       - OS
//       - ASSET_TAG
//       - HOST_UNIQUE
//       - SOFTWARE
//
//   <b>Match Policy</b>: The policy which defines how the host is verified against the flavors in the flavor group for
//   the specified flavor part.
//
//     <u>Match Type</u>: An enum whose value identifies how the policy is evaluated for the specified flavor part.
//
//      | Match Type | Description |
//      |------------|-------------|
//      |  ANY_OF    | The host can match any of the flavors of this type (flavor part) in the flavor group, but it <br> must match at least one. |
//      |  ALL_OF    | The host must match each and every one of the flavors of this type (flavor part) in <br> the flavor group. |
//      |  LATEST    | The host must match latest of the flavors of this type (flavor part) in the flavor group. |
//
//
//     <u>Required</u>: An enum whose value determines whether the flavor part needs to be evaluated.
//
//      | Required            | Description |
//      |---------------------|-------------|
//      | REQUIRED            | A flavor of this type (flavor part) must exist in the flavor group in order for the <br> host to be trusted. |
//      | REQUIRED_IF_DEFINED | If a flavor of this type(flavor part) exists in the flavorgroup, then the corresponding <br> flavor is required/mandatory. If the flavor of this type is not present in the flavorgroup,<br> then flavor part will be ignored and host will still be trusted |
//
//
//   <b>Default Flavor Groups</b>: Four flavor groups exist by default.
//
//      | Flavorgroup         | Description |
//      |---------------------|-------------|
//      |  automatic          | Default flavor group for flavor verification. |
//      |  host_unique        | Default flavor group for host unique flavor parts. All host unique flavor parts are <br> associated with this flavor group regardless of user settings. This flavor group’s <br> policy is null, and the match policy for its flavor parts are defined in each <br> individual separate flavor group. This separation is required for backend processing <br> and handling of the host unique flavors. Host Unique Flavor Parts: ASSET_TAG, HOST_UNIQUE |
//      |  platform_software  | Default flavor group for default platform software flavors for application integrity <br> of Trust Agent | 
//      |  workload_software  | Default flavor group for default platform software flavors for application integrity <br> of Workload Agent |
//
//   <b>Searches for flavor groups</b>
//   Only one identifying parameter can be specified to search flavorgroups which will return flavorgroup collection as
//   a result.
//
// x-permissions: flavorgroups:search
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: id
//   description: Flavor group ID
//   in: query
//   type: string
//   format: uuid
//   required: false
// - name: nameEqualTo
//   description: Flavor group name.
//   in: query
//   type: string
//   required: false
// - name: nameContains
//   description: Substring of flavor group name.
//   in: query
//   type: string
//   required: false
// - name: hostId
//   description: Host ID.
//   in: query
//   type: string
//   format: uuid
//   required: false
// - name: includeFlavorContent
//   description: Boolean value to indicate whether the content of the flavors contained within the <br> specified flavor group should be included in the response body. Default value is false.
//   in: query
//   type: boolean
//   required: false
// responses:
//   '200':
//     description: Successfully retrieved the flavorgroups.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/FlavorgroupCollection"
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/flavorgroups
// x-sample-call-output: |
//    {
//        "flavorgroups": [
//            {
//                "id": "826501bd-3c75-4839-a08f-db5f744f8498",
//                "name": "automatic",
//                "flavor_match_policy_collection": {
//                    "flavor_match_policies": [
//                        {
//                            "flavor_part": "PLATFORM",
//                            "match_policy": {
//                                "match_type": "ANY_OF",
//                                "required": "REQUIRED"
//                            }
//                        },
//                        {
//                            "flavor_part": "OS",
//                            "match_policy": {
//                                "match_type": "ANY_OF",
//                                "required": "REQUIRED"
//                            }
//                        },
//                        {
//                            "flavor_part": "ASSET_TAG",
//                            "match_policy": {
//                                "match_type": "ANY_OF",
//                                "required": "REQUIRED_IF_DEFINED"
//                            }
//                        },
//                        {
//                            "flavor_part": "HOST_UNIQUE",
//                            "match_policy": {
//                                "match_type": "ANY_OF",
//                                "required": "REQUIRED_IF_DEFINED"
//                            }
//                        }
//                    ]
//                },
//                "flavor_ids": [
//                    "b37580dd-f300-4229-8358-2640936c3841"
//                ]
//            }
//        ]
//    }

// ---

// swagger:operation POST /flavorgroups Flavorgroups Create
// ---
//
// description: |
//   Creates a flavor group.
//
//   The serialized Flavorgroup Go struct object represents the content of the request body.
//
//    | Attribute                      | Description|
//    |--------------------------------|------------|
//    | name                           | Name of the flavorgroup to be created. |
//    | flavor_match_policy_collection | Collection of flavor match policies. Each flavor match policy contains two <br> parts: <br><b>flavor_part</b>:The type or classification of the flavor.<br> <b>match_policy</b>:The policy which defines how the host is verified against the <br> flavors in the flavor group for the specified flavor part. |
//
// x-permissions: flavorgroups:create
// security:
//  - bearerAuth: []
// produces:
// - application/json
// consumes:
// - application/json
// parameters:
// - name: request body
//   required: true
//   in: body
//   schema:
//    "$ref": "#/definitions/FlavorGroup"
// responses:
//   '201':
//     description: Successfully created the flavorgroup.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/FlavorGroup"
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/flavorgroups
// x-sample-call-input: |
//    {
//        "name":"CustomerX",
//        "flavor_match_policy_collection": {
//            "flavor_match_policies": [
//               {
//                   "flavor_part": "PLATFORM",
//                   "match_policy": {
//                       "match_type": "ANY_OF",
//                       "required": "REQUIRED"
//                   }
//               },
//               {
//                   "flavor_part": "OS",
//                   "match_policy": {
//                       "match_type": "ANY_OF",
//                       "required": "REQUIRED"
//                   }
//               },
//               {
//                   "flavor_part": "ASSET_TAG",
//                   "match_policy": {
//                        "match_type": "ANY_OF",
//                        "required": "REQUIRED_IF_DEFINED"
//                    }
//               },
//               {
//                   "flavor_part": "HOST_UNIQUE",
//                   "match_policy": {
//                       "match_type": "ANY_OF",
//                       "required": "REQUIRED_IF_DEFINED"
//                   }
//               }
//           ]
//        }
//    }
// x-sample-call-output: |
//    {
//        "id": "1fdb39de-7bf4-440e-ad05-286eca933f78",
//        "name":"CustomerX",
//        "flavor_match_policy_collection":{
//            "flavor_match_policies": [
//               {
//                   "flavor_part": "PLATFORM",
//                   "match_policy": {
//                       "match_type": "ANY_OF",
//                       "required": "REQUIRED"
//                   }
//               },
//               {
//                   "flavor_part": "OS",
//                   "match_policy": {
//                       "match_type": "ANY_OF",
//                       "required": "REQUIRED"
//                   }
//               },
//               {
//                   "flavor_part": "ASSET_TAG",
//                   "match_policy": {
//                        "match_type": "ANY_OF",
//                        "required": "REQUIRED_IF_DEFINED"
//                    }
//               },
//               {
//                   "flavor_part": "HOST_UNIQUE",
//                   "match_policy": {
//                       "match_type": "ANY_OF",
//                       "required": "REQUIRED_IF_DEFINED"
//                   }
//               }
//           ]
//        }
//    }

// ---

// swagger:operation GET /flavorgroups/{flavorgroup_id} Flavorgroups Retrieve
// ---
//
// description: |
//   Retrieves a flavor group.
//   Returns - The serialized Flavorgroup Go struct object that was retrieved and a list of associated flavor IDs
// x-permissions: flavorgroups:retrieve
// security:
//  - bearerAuth: []
// produces:
// - application/json
// parameters:
// - name: flavorgroup_id
//   description: Unique ID of the flavorgroup.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '200':
//     description: Successfully retrieved the flavorgroup.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/FlavorGroup"
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/flavorgroups/826501bd-3c75-4839-a08f-db5f744f8498
// x-sample-call-output: |
//    {
//        "id": "826501bd-3c75-4839-a08f-db5f744f8498",
//        "name": "automatic",
//        "flavor_match_policy_collection": {
//            "flavor_match_policies": [
//                {
//                    "flavor_part": "PLATFORM",
//                    "match_policy": {
//                        "match_type": "ANY_OF",
//                        "required": "REQUIRED"
//                    }
//                },
//                {
//                    "flavor_part": "OS",
//                    "match_policy": {
//                        "match_type": "ANY_OF",
//                        "required": "REQUIRED"
//                    }
//                },
//                {
//                    "flavor_part": "ASSET_TAG",
//                    "match_policy": {
//                        "match_type": "ANY_OF",
//                        "required": "REQUIRED_IF_DEFINED"
//                    }
//                },
//                {
//                    "flavor_part": "HOST_UNIQUE",
//                    "match_policy": {
//                        "match_type": "ANY_OF",
//                        "required": "REQUIRED_IF_DEFINED"
//                    }
//                }
//            ]
//        },
//        "flavor_ids": [
//            "b37580dd-f300-4229-8358-2640936c3841"
//        ]
//    }

// ---

// swagger:operation DELETE /flavorgroups/{flavorgroup_id} Flavorgroups Delete
// ---
//
// description: |
//   Deletes a flavor group. If the flavor group is still associated with any hosts, an error will be thrown.
// x-permissions: flavorgroups:delete
// security:
//  - bearerAuth: []
// parameters:
// - name: flavorgroup_id
//   description: Unique ID of the flavorgroup.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '204':
//     description: Successfully deleted the flavorgroup.
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/flavorgroups/826501bd-3c75-4839-a08f-db5f744f8498
// ---
