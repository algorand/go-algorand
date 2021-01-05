// Copyright (C) 2019-2021 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

// Package common defines models exposed by algod rest api
package common

// Version contains the current algod version.
//
// Note that we annotate this as a model so that legacy clients
// can directly import a swagger generated Version model.
// swagger:model Version
type Version struct {
	// required: true
	// returns a list of supported protocol versions ( i.e. v1, v2, etc. )
	Versions []string `json:"versions"`
	// required: true
	GenesisID string `json:"genesis_id"`
	// required: true
	// swagger:strfmt byte
	GenesisHash []byte `json:"genesis_hash_b64"`
	// required: true
	Build BuildVersion `json:"build"`
}

// BuildVersion contains the current algod build version information.
type BuildVersion struct {
	// required: true
	// Algorand's major version number
	Major int `json:"major"`
	// required: true
	// Algorand's minor version number
	Minor int `json:"minor"`
	// required: true
	// Algorand's Build Number
	BuildNumber int `json:"build_number"`
	// required: true
	// Hash of commit the build is based on
	CommitHash string `json:"commit_hash"`
	// required: true
	// Branch the build is based on
	Branch string `json:"branch"`
	// required: true
	// Branch-derived release channel the build is based on
	Channel string `json:"channel"`
}
