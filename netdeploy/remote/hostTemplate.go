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

package remote

import (
	"encoding/json"
	"fmt"
	"os"
)

type cloudHost struct {
	// Name of the template - referenced by topology files
	Name string

	// Provider is the cloud provider (AWS, Azure, GCP)
	Provider string

	// Region for host (likely provider-specific)
	Region string

	// BaseConfiguration (provider-specific)
	BaseConfiguration string
}

type cloudHosts struct {
	Hosts []cloudHost
}

// HostTemplates contains a mapping (from name to cloudHost definition)
type HostTemplates struct {
	Hosts map[string]cloudHost
}

// LoadHostTemplates returns a HostTemplates object populated from the definitions in templateFile
func LoadHostTemplates(templateFile string) (templates HostTemplates, err error) {
	f, err := os.Open(templateFile)
	if err != nil {
		return
	}
	defer f.Close()

	var hosts cloudHosts
	dec := json.NewDecoder(f)
	err = dec.Decode(&hosts)
	if err != nil {
		return
	}

	templates = HostTemplates{
		Hosts: make(map[string]cloudHost),
	}

	for _, host := range hosts.Hosts {
		if _, has := templates.Hosts[host.Name]; has {
			return templates, fmt.Errorf("duplicate HostTemplate name '%s' encountered", host.Name)
		}
		templates.Hosts[host.Name] = host
	}
	return
}
