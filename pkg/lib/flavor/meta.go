/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package flavor

/**
 *
 * @author purvades
 */

// Meta defines meta data of the flavor
type Meta struct {
	Schema      *Schema      `json:"schema,omitempty"`
	ID          string       `json:"id"`
	Author      *Author      `json:"author,omitempty"`
	Realm       string       `json:"realm,omitempty"`
	Description *Description `json:"description"`
}

// Schema defines the URI of the schema
type Schema struct {
	URI string `json:"uri,omitempty"`
}

// Author defines the email address of the author
type Author struct {
	Email string `json:"email,omitempty"`
}
