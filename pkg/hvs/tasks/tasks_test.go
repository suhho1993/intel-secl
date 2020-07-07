/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import "testing"

func TestDekGenerate(t *testing.T) {
	dek := "hello"
	task := CreateDek{
		DekStore: &dek,
	}
	if err := task.Validate(); err == nil {
		t.Error("first validation should not pass")
	}
	if err := task.Run(); err != nil {
		t.Error("run failed:", err.Error())
	}
	t.Log("Generated key:")
	t.Log(dek)
	if err := task.Validate(); err != nil {
		t.Error("second validation should pass:", err.Error())
	}
}

func TestDefaultFlavorGroupDes(t *testing.T) {
	// check if default flavor strings are correct
	for _, fg := range defaultFlavorGroups() {
		t.Log(fg)
	}
}
