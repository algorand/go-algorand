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

package logic

// Export for testing only.  See
// https://medium.com/@robiplus/golang-trick-export-for-test-aa16cbd7b8cd for a
// nice explanation.

func NewExpect(l int, s string) Expect {
	return Expect{l, s}
}

var MakeSampleEnv = makeSampleEnv
var MakeSampleEnvWithVersion = makeSampleEnvWithVersion
var MakeSampleTxn = makeSampleTxn
var MakeSampleTxnGroup = makeSampleTxnGroup
var MakeTestProto = makeTestProto
var MakeTestProtoV = makeTestProtoV
var Obfuscate = obfuscate
var TestApp = testApp
var TestAppBytes = testAppBytes
var TestApps = testApps
var TestProg = testProg

const InnerAppsEnabledVersion = innerAppsEnabledVersion
const CreatedResourcesVersion = createdResourcesVersion
