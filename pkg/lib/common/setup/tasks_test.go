/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package setup

import (
	"fmt"
	"testing"
)

var TestConfiguration struct {
	ConfigGroup1 struct {
		GroupField1 string
		GroupField2 int
		GroupField3 bool
	}
	ConfigGroup2 struct {
		GroupField1 string
		GroupField2 int
		GroupField3 bool
	}
	ConfigGroup3 struct {
		GroupField1 string
		GroupField2 float64
		GroupField3 bool
	}
	ConfigField1 string
	ConfigField2 float64
	ConfigField3 bool
}

var envArgs = []EnvVars{

	EnvVars{
		Name:        "CG1_GF1",
		ConfigVar:   &TestConfiguration.ConfigGroup1.GroupField1,
		Description: "TestConfiguration.ConfigGroup1.GroupField1",
		EmptyOkay:   false,
	},
	EnvVars{
		Name:        "CG1_GF2",
		ConfigVar:   &TestConfiguration.ConfigGroup1.GroupField2,
		Description: "TestConfiguration.ConfigGroup1.GroupField2",
		EmptyOkay:   true,
	},
	EnvVars{
		Name:        "CG1_GF3",
		ConfigVar:   &TestConfiguration.ConfigGroup1.GroupField3,
		Description: "TestConfiguration.ConfigGroup1.GroupField3",
		EmptyOkay:   true,
	},
	EnvVars{
		Name:        "CG2_GF1",
		ConfigVar:   &TestConfiguration.ConfigGroup2.GroupField1,
		Description: "TestConfiguration.ConfigGroup2.GroupField1",
		EmptyOkay:   false,
	},
	EnvVars{
		Name:        "CG2_GF2",
		ConfigVar:   &TestConfiguration.ConfigGroup2.GroupField2,
		Description: "TestConfiguration.ConfigGroup2.GroupField2",
		EmptyOkay:   true,
	},
	EnvVars{
		Name:        "CG2_GF3",
		ConfigVar:   &TestConfiguration.ConfigGroup2.GroupField3,
		Description: "TestConfiguration.ConfigGroup2.GroupField3",
		EmptyOkay:   true,
	},
	EnvVars{
		Name:        "CG3_GF1",
		ConfigVar:   &TestConfiguration.ConfigGroup3.GroupField1,
		Description: "TestConfiguration.ConfigGroup3.GroupField1",
		EmptyOkay:   false,
	},
	EnvVars{
		Name:        "CG3_GF2",
		ConfigVar:   &TestConfiguration.ConfigGroup3.GroupField2,
		Description: "TestConfiguration.ConfigGroup3.GroupField2",
		EmptyOkay:   true,
	},
	EnvVars{
		Name:        "CG3_GF3",
		ConfigVar:   &TestConfiguration.ConfigGroup3.GroupField3,
		Description: "TestConfiguration.ConfigGroup3.GroupField3",
		EmptyOkay:   true,
	},
	EnvVars{
		Name:        "CF1",
		ConfigVar:   &TestConfiguration.ConfigField1,
		Description: "TestConfiguration.ConfigGroup1",
		EmptyOkay:   false,
	},
	EnvVars{
		Name:        "CF2",
		ConfigVar:   &TestConfiguration.ConfigField2,
		Description: "TestConfiguration.ConfigField2",
		EmptyOkay:   true,
	},
	EnvVars{
		Name:        "CF3",
		ConfigVar:   &TestConfiguration.ConfigField3,
		Description: "TestConfiguration.ConfigField3",
		EmptyOkay:   true,
	},
}

// Run with command: go test --count=1 -v ./...
// Look at standard output and created file to verify implementation
func TestConfig(t *testing.T) {

	var err error
	r := Runner{
		Tasks: []Task{
			Config{
				FilePath:  "test_conf.yaml",
				ConfigObj: &TestConfiguration,
				Vars:      envArgs,
			},
		},
		AskInput: false,
	}
	err = r.RunTasks()
	if err != nil {
		fmt.Println(err.Error())
	}
}
