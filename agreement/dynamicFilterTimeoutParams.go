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
const dynamicFilterTimeoutLowerBound time.Duration = 600 * time.Millisecond

// DynamicFilterTimeoutCredentialArrivalHistoryIdx specified which sample to
// use out of a sorted DynamicFilterCredentialArrivalHistory-sized array of
// time samples.
const dynamicFilterTimeoutCredentialArrivalHistoryIdx int = 37

// DynamicFilterTimeoutGraceInterval is additional extension to the dynamic
// filter time atop the one calculated based on the history of credential
// arrivals.
const dynamicFilterTimeoutGraceInterval time.Duration = 50 * time.Millisecond
