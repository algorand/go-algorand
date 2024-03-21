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

import "time"

// This file contains parameters for the dynamic filter timeout mechanism. When
// this feature is enabled (dynamicFilterTimeout is true), these parameters
// should migrate to be consensus params.

// DynamicFilterCredentialArrivalHistory specifies the number of past
// credential arrivals that are measured to determine the next filter
// timeout. If DynamicFilterCredentialArrivalHistory <= 0, then the dynamic
// timeout feature is off and the filter step timeout is calculated using
// the static configuration.
const dynamicFilterCredentialArrivalHistory int = 40

// DynamicFilterTimeoutLowerBound specifies a minimal duration that the
// filter timeout must meet.
const dynamicFilterTimeoutLowerBound time.Duration = 2500 * time.Millisecond

// DynamicFilterTimeoutCredentialArrivalHistoryIdx specified which sample to use
// out of a sorted DynamicFilterCredentialArrivalHistory-sized array of time
// samples. The 95th percentile of dynamicFilterCredentialArrivalHistory = 40
// sorted samples, is at index 37.
const dynamicFilterTimeoutCredentialArrivalHistoryIdx int = 37

// DynamicFilterTimeoutGraceInterval is additional extension to the dynamic
// filter time atop the one calculated based on the history of credential
// arrivals.
const dynamicFilterTimeoutGraceInterval time.Duration = 50 * time.Millisecond
