// Copyright (C) 2019-2023 Algorand, Inc.
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

package dnsaddr

import (
	"context"
	"errors"
	"fmt"

	"github.com/multiformats/go-multiaddr"
)

func isDnsaddr(maddr multiaddr.Multiaddr) bool {
	first, _ := multiaddr.SplitFirst(maddr)
	return first.Protocol().Code == multiaddr.P_DNSADDR
}

func MultiaddrsFromResolver(domain string, controller *DnsaddrResolveController) ([]multiaddr.Multiaddr, error) {
	resolver := controller.Resolver()
	if resolver == nil {
		return nil, errors.New("passed controller has no resolvers MultiaddrsFromResolver")
	}
	dnsaddr, err := multiaddr.NewMultiaddr(fmt.Sprintf("/dnsaddr/%s", domain))
	if err != nil {
		return nil, fmt.Errorf("Unable to construct multiaddr for %s : %v\n", domain, err)
	}
	var resolved []multiaddr.Multiaddr
	var toResolve = []multiaddr.Multiaddr{dnsaddr}
	for resolver != nil && len(toResolve) > 0 {
		curr := toResolve[0]
		maddrs, resolveErr := resolver.Resolve(context.Background(), curr)
		if resolveErr != nil {
			err = resolveErr
			resolver = controller.NextResolver()
			continue
		}
		for _, maddr := range maddrs {
			if isDnsaddr(maddr) {
				toResolve = append(toResolve, maddr)
			} else {
				resolved = append(resolved, maddr)
			}
		}
		toResolve = toResolve[1:]
	}
	return resolved, err
}
