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

package dnssec

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

func splitToZones(fqZoneName string) ([]string, error) {
	if fqZoneName == "" || !dns.IsFqdn(fqZoneName) {
		return nil, fmt.Errorf("%s is not FQDN", fqZoneName)
	}
	if fqZoneName == "." {
		return []string{"."}, nil
	}
	components := strings.Split(fqZoneName, ".")
	l := len(components) // always >= 2
	result := make([]string, 0, l)
	result = append(result, ".")

	var zone string
	for i := l - 2; i >= 0; i-- {
		zone = components[i] + "." + zone
		result = append(result, zone)
	}

	return result, nil
}

func getParentZone(fqZoneName string) (string, error) {
	zones, err := splitToZones(fqZoneName)
	if err != nil {
		return "", err
	}
	if len(zones) < 2 {
		return "", fmt.Errorf("No parent zone for %s", fqZoneName)
	}
	return zones[len(zones)-2], nil
}
