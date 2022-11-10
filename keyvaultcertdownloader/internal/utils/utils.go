// Copyright (c) Microsoft and contributors.  All rights reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package that provides some general functions.

package utils

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"internal/models"
)

// PrintHeader prints a header message
func PrintHeader(header string) {
	fmt.Println(header)
	fmt.Println(strings.Repeat("-", len(header)))
}

// ConsoleOutput writes to stdout.
func ConsoleOutput(message string, logger *log.Logger) {
	logger.Println(message)
}

// Contains checks if there is a string already in an existing splice of strings
func Contains(array []string, element string) bool {
	for _, e := range array {
		if e == element {
			return true
		}
	}
	return false
}

// ReadAzureBasicInfoJSON reads the Azure Authentication json file json file and unmarshals it.
func ReadAzureBasicInfoJSON(path string) (*models.AzureBasicInfo, error) {
	infoJSON, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Sprintf("failed to read file: %v", err)
		return &models.AzureBasicInfo{}, err
	}
	var info models.AzureBasicInfo
	json.Unmarshal(infoJSON, &info)
	return &info, nil
}

// FindInSlice returns index greater than -1 and true if item is found
// Code from https://golangcode.com/check-if-element-exists-in-slice/
func FindInSlice(slice []string, val string) (int, bool) {
	for i, item := range slice {
		if item == val {
			return i, true
		}
	}
	return -1, false
}
