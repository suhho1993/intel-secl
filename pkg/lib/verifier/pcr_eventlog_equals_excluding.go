/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
)

var (
	// This is a map of component names to remove the host manifest's list of events.  The 
	// map value (int) is not relevant, just use the map key for efficient lookups.
	exclude_components = map[string]int {
		"commandLine.": 0,
		"LCP_CONTROL_HASH": 0,
		"initrd": 0,
		"vmlinuz": 0,
		"componentName.imgdb.tgz": 0,
		"componentName.onetime.tgz": 0,
	}
)

func newPcrEventLogEqualsExcluding(expectedEventLogEntry *types.EventLogEntry, flavorID uuid.UUID, marker common.FlavorPart) (rule, error) {
	rule := pcrEventLogEqualsExcluding{
		expectedEventLogEntry: expectedEventLogEntry,
		flavorID: &flavorID,
		marker: marker,
	}

	return &rule, nil
}

type pcrEventLogEqualsExcluding struct {
	expectedEventLogEntry *types.EventLogEntry
	flavorID              *uuid.UUID
	marker                common.FlavorPart
}

// - If the PcrManifest is not present in the host manifest, raise PcrEventLogMissing fault.
// - If the PcrManifest's event log is not present in the host manifest, raise PcrEventLogMissing fault.
// - Otherwise, strip out pre-defined events from the host manifest's event log. Subract out 'expected' 
//   events, subtract events that have a label of "0x4fe".  If the results are not empty, raise a 
//   PcrEventLogContainsUnexpectedEntries fault.  
// - Also report the missing events by taking 'expected' and subtracting 'actual' and raising a 
//   PcrEventLogMissingExpectedEntries fault.
func (rule *pcrEventLogEqualsExcluding) Apply(hostManifest *types.HostManifest) (*RuleResult, error) {

	result := RuleResult{}
	result.Trusted = true
	result.Rule.Name = "com.intel.mtwilson.core.verifier.policy.rule.PcrEventLogEqualsExcluding"
	result.Rule.ExpectedEventLogEntry = rule.expectedEventLogEntry
	result.Rule.Markers = append(result.Rule.Markers, rule.marker)	

	if hostManifest.PcrManifest.IsEmpty() {
		result.Faults = append(result.Faults, newPcrManifestMissingFault())
	} else {

		actualEventLog, err := hostManifest.PcrManifest.PcrEventLogMap.GetEventLog(rule.expectedEventLogEntry.PcrBank, rule.expectedEventLogEntry.PcrIndex)
		if err != nil {
			return nil, err
		}

		if actualEventLog == nil {
			result.Faults  = append(result.Faults , newPcrEventLogMissingFault(rule.expectedEventLogEntry.PcrIndex))
		} else {
			// first strip all of the 'default_excludes' from actual
			unexpectedEventLogs, err := rule.removeExcludedEvents(actualEventLog, exclude_components)
			if err != nil {
				return nil, err
			}

			// also remove all events with the label '0x4fe'
			unexpectedEventLogs, err = rule.removeEventsWithLabel(unexpectedEventLogs, "0x4fe")
			if err != nil {
				return nil, err
			}

			// now subtract out 'expected'
			unexpectedEventLogs, err = unexpectedEventLogs.Subtract(rule.expectedEventLogEntry)
			if err != nil {
				return nil, err
			}

			// if there are any remaining events, then there were unexpected entries...
			if len(unexpectedEventLogs.EventLogs) > 0 {
				result.Faults  = append(result.Faults , newPcrEventLogContainsUnexpectedEntries(unexpectedEventLogs))
			}

			// now, look the other way -- find events that are in actual but not expected (i.e. missing)
			missingEventLogs, err := rule.expectedEventLogEntry.Subtract(actualEventLog)
			if err != nil {
				return nil, err
			}

			if len(missingEventLogs.EventLogs) > 0 {
				result.Faults  = append(result.Faults , newPcrEventLogMissingExpectedEntries(missingEventLogs))
			}
		}
	}

	return &result, nil
}

// Creates a new EventLogEntry without events where the EventLog.Info["ComponentName"] 
// is in 'componentNamesToExclude'
func (rule *pcrEventLogEqualsExcluding) removeExcludedEvents(eventLogEntry *types.EventLogEntry, componentNamesToExclude map[string]int) (*types.EventLogEntry, error) {

	var eventsWithoutComponentName []types.EventLog

	// Loop through the each eventlog and see if it contains a ComponentName key/value.
	// If it does, see if the ComponentName exists in the 'componentNamesToExclude' map,
	// and if so, do not add it to the results eventlog.
	for _, eventLog := range(eventLogEntry.EventLogs) {
		if componentName, ok := eventLog.Info["ComponentName"]; ok {
			if _, ok := componentNamesToExclude[componentName]; ok {
				continue
			}
		}

		// Also, do not add event logs where the PackageName and PackageVendor are present
		// but empty (ex. {"Packagename":""}).
		if packageName, ok := eventLog.Info["PackageName"];ok  && len(packageName) == 0 {
			if packageVendor, ok := eventLog.Info["PackageVendor"]; ok && len(packageVendor) == 0 {
				continue
			}
		}

		eventsWithoutComponentName = append(eventsWithoutComponentName, eventLog)
	}

	return &types.EventLogEntry {
		PcrIndex: eventLogEntry.PcrIndex,
		PcrBank: eventLogEntry.PcrBank,
		EventLogs: eventsWithoutComponentName,
	}, nil
}

// Creates a new EventLogEntry without events where EventLog.label matches 'label'
func (rule *pcrEventLogEqualsExcluding) removeEventsWithLabel(eventLogEntry *types.EventLogEntry, label string) (*types.EventLogEntry, error) {

	var eventsWithoutLabel []types.EventLog

	for _, eventLog := range(eventLogEntry.EventLogs) {
		if eventLog.Label != label {
			eventsWithoutLabel = append(eventsWithoutLabel, eventLog)
		}
	}

	return &types.EventLogEntry {
		PcrIndex: eventLogEntry.PcrIndex,
		PcrBank: eventLogEntry.PcrBank,
		EventLogs: eventsWithoutLabel,
	}, nil
}