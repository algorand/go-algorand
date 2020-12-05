// Copyright (C) 2019-2020 Algorand, Inc.
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

// +build !windows

package dnssec

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/miekg/dns"
)

// SystemConfig return list of servers and timeout from
// This is Linux only.
//
// For Windows need to implement DNS servers retrieval from GetNetworkParams
//  see https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getnetworkparams
func SystemConfig() (servers []ResolverAddress, timeout time.Duration, err error) {
	f, err := os.Open(defaultConfigFile)
	defer f.Close()
	if err != nil {
		return
	}
	return systemConfig(f)
}

func systemConfig(configFile io.Reader) (servers []ResolverAddress, timeout time.Duration, err error) {
	if configFile == nil {
		err = fmt.Errorf("empty config reader")
		return
	}
	cc, err := dns.ClientConfigFromReader(configFile)
	if err != nil {
		return
	}
	for _, addr := range cc.Servers {
		servers = append(servers, MakeResolverAddress(addr, cc.Port))
	}
	timeout = DefaultTimeout
	if cc.Timeout != 0 && len(servers) > 0 {
		timeout = time.Duration(cc.Timeout) * time.Second
	}
	if timeout > maxTimeout {
		timeout = maxTimeout
	}
	return
}
