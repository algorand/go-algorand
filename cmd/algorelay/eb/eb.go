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

package eb

// Relay represents the configuration data necessary for a single Relay
type Relay struct {
	ID             int64  // db key injected when loaded
	Address        string // ip or dns name; use to be called IPOrDNSName.
	MetricsEnabled bool
	CheckSuccess   bool   // true if check was successful
	DNSAlias       string // DNS Alias name used
}
