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

package agreement

import (
	"encoding/base64"
	"testing"

	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

// TestSerializableErrorBackwardCompatible ensures Err field of type serializableError can be
// properly decoded from ConsensusVersionView.
// This test is only needed for agreement state serialization switch from reflection to msgp.
func TestSerializableErrorBackwardCompatibility(t *testing.T) {
	partitiontest.PartitionTest(t)

	encodedEmpty, err := base64.StdEncoding.DecodeString("gqNFcnLAp1ZlcnNpb26jdjEw")
	require.NoError(t, err)

	encoded, err := base64.StdEncoding.DecodeString("gqNFcnKndGVzdGVycqdWZXJzaW9uo3YxMA==")
	require.NoError(t, err)

	// run on master f57a276 to get the encoded data for above
	// cv := ConsensusVersionView{
	// 	Err:     nil,
	// 	Version: protocol.ConsensusV10,
	// }

	// result := protocol.EncodeReflect(&cv)
	// fmt.Println(base64.StdEncoding.EncodeToString(result))

	// se := serializableErrorUnderlying("testerr")
	// cv = ConsensusVersionView{
	// 	Err:     &se,
	// 	Version: protocol.ConsensusV10,
	// }

	// result = protocol.EncodeReflect(&cv)
	// fmt.Println(base64.StdEncoding.EncodeToString(result))

	cvEmpty := ConsensusVersionView{
		Err:     nil,
		Version: protocol.ConsensusV10,
	}

	se := serializableError("testerr")
	cv := ConsensusVersionView{
		Err:     &se,
		Version: protocol.ConsensusV10,
	}

	cv1 := ConsensusVersionView{}
	err = protocol.Decode(encodedEmpty, &cv1)
	require.NoError(t, err)

	cv2 := ConsensusVersionView{}
	err = protocol.DecodeReflect(encodedEmpty, &cv2)
	require.NoError(t, err)

	require.Equal(t, cv1, cv2)
	require.Equal(t, cvEmpty, cv2)

	cv1 = ConsensusVersionView{}
	err = protocol.Decode(encoded, &cv1)
	require.NoError(t, err)

	cv2 = ConsensusVersionView{}
	err = protocol.DecodeReflect(encoded, &cv2)
	require.NoError(t, err)

	require.Equal(t, cv1, cv2)
	require.Equal(t, cv, cv2)
}
