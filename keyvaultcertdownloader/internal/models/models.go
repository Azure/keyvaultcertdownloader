// Copyright (c) Microsoft and contributors.  All rights reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.
package models

// AzureAuthInfo object definition
type AzureAuthInfo struct {
	ClientID                       *string
	ClientSecret                   *string
	SubscriptionID                 *string
	TenantID                       *string
	ActiveDirectoryEndpointURL     *string
	ResourceManagerEndpointURL     *string
	ActiveDirectoryGraphResourceID *string
	SQLManagementEndpointURL       *string
	GalleryEndpointURL             *string
	ManagementEndpointURL          *string
}

// AzureBasicInfo object definition
type AzureBasicInfo struct {
	SubscriptionID             *string
	TenantID                   *string
	ResourceManagerEndpointURL *string
	ManagementEndpointURL      *string
}
