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

package telemetryspec

// Telemetry categories

// Category is the type used to identify strings used for telemetry categories.
// We want these to be stable and easy to find / document so we can create queries against them.
type Category string

// ApplicationState category
const ApplicationState Category = "ApplicationState"

// HostApplicationState category
const HostApplicationState Category = "HostApplicationState"

// Agreement category
const Agreement Category = "Agreement"

// Accounts category
const Accounts Category = "Accounts"

// Network category
const Network Category = "Network"

// Transaction category
const Transaction Category = "Transaction"
