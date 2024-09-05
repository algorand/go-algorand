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

package dnssec

import (
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestParseRootTrustAnchor(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	an1, err := makeRootTrustAnchor(rootAnchorXML)
	a.NoError(err)
	an2, err := MakeRootTrustAnchor()
	a.NoError(err)
	a.Equal(an1, an2)

	dss := an2.ToDS()
	a.Equal(3, len(dss))
	currentDS := dss[2]
	a.Equal("683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16", currentDS.Digest)
	a.Equal(uint16(38696), currentDS.KeyTag)
	a.Equal(uint8(8), currentDS.Algorithm)
	a.Equal(uint8(2), currentDS.DigestType)

	_, err = makeRootTrustAnchor("not xml")
	a.Error(err)
}
