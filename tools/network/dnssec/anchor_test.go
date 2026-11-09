// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
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
	currentDS := dss[1]
	a.Equal("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D", currentDS.Digest)
	a.Equal(uint16(20326), currentDS.KeyTag)
	a.Equal(uint8(8), currentDS.Algorithm)
	a.Equal(uint8(2), currentDS.DigestType)
	nextDS := dss[2]
	a.Equal("683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16", nextDS.Digest)
	a.Equal(uint16(38696), nextDS.KeyTag)
	a.Equal(uint8(8), nextDS.Algorithm)
	a.Equal(uint8(2), nextDS.DigestType)

	_, err = makeRootTrustAnchor("not xml")
	a.Error(err)
}
