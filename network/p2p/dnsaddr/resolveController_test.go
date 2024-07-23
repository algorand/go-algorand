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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestDnsAddrResolveController(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	dnsaddrCont := NewMultiaddrDNSResolveController(true, "127.0.0.1")

	// Assert that the dnsaddr resolver cycles through the dns resolvers properly
	assert.Equal(t, dnsaddrCont.controller.SystemDnsaddrResolver(), dnsaddrCont.Resolver())
	assert.Equal(t, dnsaddrCont.controller.FallbackDnsaddrResolver(), dnsaddrCont.NextResolver())
	assert.Equal(t, dnsaddrCont.controller.DefaultDnsaddrResolver(), dnsaddrCont.NextResolver())
	// It should return nil once all the resolvers have been tried
	assert.Nil(t, dnsaddrCont.NextResolver())
	assert.Nil(t, dnsaddrCont.NextResolver())

	// It should not include fallback if none was specified
	dnsaddrCont = NewMultiaddrDNSResolveController(true, "")
	assert.Equal(t, 2, len(dnsaddrCont.nextResolvers))

}
