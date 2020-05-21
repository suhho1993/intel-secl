/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	cm "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/model"
	taModel "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"strings"
)

/**
 *
 * @author mullas
 */

// SoftwareFlavorUtil contains utility functions for working with Software Flavor
type SoftwareFlavorUtil struct {
}

// GetSoftware returns the Software struct per the integrity Measurements sourced from HostManifest
func (sfu SoftwareFlavorUtil) GetSoftware(measurements taModel.Measurement) cm.Software {
	measurementMap := make(map[string]taModel.MeasurementType)

	// Cleanup Paths for Dir Measurement
	for _, mT := range measurements.Dir {
		measurementMap[sfu.cleanupPaths(mT.Path)] = mT
	}

	// Cleanup Paths for File Measurement
	for _, mT := range measurements.File {
		measurementMap[sfu.cleanupPaths(mT.Path)] = mT
	}

	// Cleanup Paths for Symlink Measurement
	for _, mT := range measurements.Symlink {
		measurementMap[sfu.cleanupPaths(mT.Path)] = mT
	}

	var s cm.Software
	s.Measurements = measurementMap
	s.CumulativeHash = measurements.CumulativeHash
	return s
}

// cleanupPaths is a utility function that cleans up the paths in Measurement XML
func (sfu SoftwareFlavorUtil) cleanupPaths(path string) string {
	measuredPath := strings.ReplaceAll(path, "/", "-")
	if strings.LastIndex(measuredPath, "-") == len(measuredPath)-1 {
		measuredPath = strings.Join(strings.Split(measuredPath, "")[1:len(measuredPath)-1], "")
	} else {
		measuredPath = strings.Join(strings.Split(measuredPath, "")[1:], "")
	}
	return measuredPath
}
