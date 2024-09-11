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

package rapidgen

// See https://github.com/flyingmutant/rapid/pull/18

import (
	"fmt"
	"pgregory.net/rapid"
	"strings"
)

// DomainWithPort generates an RFC 1035 compliant domain name with a port.
func DomainWithPort() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		return fmt.Sprintf("%s:%d", Domain().Draw(t, "domain"), rapid.IntRange(1, 65535).Draw(t, "port"))
	})
}

// Domain generates an RFC 1035 compliant domain name.
func Domain() *rapid.Generator[string] {
	return DomainOf(255, 63, "", nil)
}

// DomainWithSuffixAndPort generates an RFC 1035 compliant domain name with the specified domain suffix (assumes compliant), taking a list of domains to not match.
func DomainWithSuffixAndPort(suffix string, dontMatch []string) *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		return fmt.Sprintf("%s:%d", DomainOf(253, 63, suffix, dontMatch).Draw(t, "domain"),
			rapid.IntRange(1, 65535).Draw(t, "port"))
	})
}

// DomainOf generates an RFC 1035 compliant domain name,
// with a maximum overall length of maxLength
// a maximum number of elements of maxElements
// and the specified domain suffix (assumes compliant).
func DomainOf(maxLength, maxElementLength int, domainSuffix string, dontMatch []string) *rapid.Generator[string] {
	assertf(4 <= maxLength, "maximum length (%v) should not be less than 4, to generate a two character domain and a one character subdomain", maxLength)
	assertf(maxLength <= 255, "maximum length (%v) should not be greater than 255 to comply with RFC 1035", maxLength)
	assertf(1 <= maxElementLength, "maximum element length (%v) should not be less than 1 to comply with RFC 1035", maxElementLength)
	assertf(maxElementLength <= 63, "maximum element length (%v) should not be greater than 63 to comply with RFC 1035", maxElementLength)

	genDomain := func() *rapid.Generator[string] {
		return rapid.Custom(func(t *rapid.T) string {
			var domain string
			if domainSuffix != "" {
				domain = domainSuffix
			} else {
				domain = fmt.Sprint(tldGenerator.
					Filter(func(s string) bool { return len(s)+2 <= maxLength }).
					Draw(t, "domain"))
			}

			expr := fmt.Sprintf(`[a-zA-Z]([a-zA-Z0-9\-]{0,%d}[a-zA-Z0-9])?`, maxElementLength-2)

			el := rapid.IntRange(1, 126).Example()
			for i := 0; i < el; i++ {
				subDomain := fmt.Sprint(rapid.StringMatching(expr).Draw(t, "subdomain"))
				if len(domain)+len(subDomain) >= maxLength {
					break
				}
				domain = subDomain + "." + domain
			}

			return domain
		})
	}

	return genDomain().Filter(func(domain string) bool {
		for _, v := range dontMatch {
			if strings.EqualFold(v, domain) {
				return false
			}
		}
		return true
	})
}

var tldGenerator = rapid.SampledFrom(tlds)

func assertf(ok bool, format string, args ...interface{}) {
	if !ok {
		panic(fmt.Sprintf(format, args...))
	}
}
