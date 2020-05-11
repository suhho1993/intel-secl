/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package flavor

/**
 *
 * @author arijitgh
 */

// SignedImageFlavor struct defines the image flavor and
// its corresponding signature
type SignedImageFlavor struct {
	ImageFlavor Image  `json:"flavor"`
	Signature   string `json:"signature"`
}
