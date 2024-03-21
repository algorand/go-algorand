// Copyright (C) 2019-2024 Algorand, Inc.
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

// Iterate runs through the resolvable dnsaddrs in the tree using the resolveController and invokes f for each dnsaddr node lookup
func Iterate(initial multiaddr.Multiaddr, controller *MultiaddrDNSResolveController, f func(dnsaddr multiaddr.Multiaddr, entries []multiaddr.Multiaddr) error) error {
	resolver := controller.Resolver()
	if resolver == nil {
		return errors.New("passed controller has no resolvers Iterate")
	}
	var toResolve = []multiaddr.Multiaddr{initial}
	for resolver != nil && len(toResolve) > 0 {
		curr := toResolve[0]
		maddrs, resolveErr := resolver.Resolve(context.Background(), curr)
		if resolveErr != nil {
			resolver = controller.NextResolver()
			// If we errored, and have exhausted all resolvers, just return
			if resolver == nil {
				return resolveErr
			}
			continue
		}
		for _, maddr := range maddrs {
			if isDnsaddr(maddr) {
				toResolve = append(toResolve, maddr)
			}
		}
		if err := f(curr, maddrs); err != nil {
			return err
		}
		toResolve = toResolve[1:]
	}
	return nil
}

// MultiaddrsFromResolver attempts to recurse through dnsaddrs starting at domain.
// Any further dnsaddrs will be looked up until all TXT records have been fetched,
// and the full list of resulting Multiaddrs is returned.
// It uses the MultiaddrDNSResolveController to cycle through DNS resolvers on failure.
func MultiaddrsFromResolver(domain string, controller *MultiaddrDNSResolveController) ([]multiaddr.Multiaddr, error) {
	dnsaddr, err := multiaddr.NewMultiaddr(fmt.Sprintf("/dnsaddr/%s", domain))
	if err != nil {
		return nil, fmt.Errorf("unable to construct multiaddr for %s : %v", domain, err)
	}
	var resolved []multiaddr.Multiaddr
	err = Iterate(dnsaddr, controller, func(_ multiaddr.Multiaddr, entries []multiaddr.Multiaddr) error {
		for _, maddr := range entries {
			if !isDnsaddr(maddr) {
				resolved = append(resolved, maddr)
			}
		}
		return nil
	})
	return resolved, err
}
