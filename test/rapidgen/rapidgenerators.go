package rapidgen

// See https://github.com/flyingmutant/rapid/pull/18

import (
	"fmt"
	"pgregory.net/rapid"
)

const (
	domainMaxLength        = 255
	domainMaxElementLength = 63
)

// Domain generates an RFC 1035 compliant domain name.
func Domain() *rapid.Generator {
	return DomainOf(255, 63)
}

// DomainOf generates an RFC 1035 compliant domain name,
// with a maximum overall length of maxLength
// and a maximum number of elements of maxElements.
func DomainOf(maxLength, maxElementLength int) *rapid.Generator {
	assertf(4 <= maxLength, "maximum length (%v) should not be less than 4, to generate a two character domain and a one character subdomain", maxLength)
	assertf(maxLength <= 255, "maximum length (%v) should not be greater than 255 to comply with RFC 1035", maxLength)
	assertf(1 <= maxElementLength, "maximum element length (%v) should not be less than 1 to comply with RFC 1035", maxElementLength)
	assertf(maxElementLength <= 63, "maximum element length (%v) should not be greater than 63 to comply with RFC 1035", maxElementLength)

	return rapid.Custom(func(t *rapid.T) string {
		domain := fmt.Sprint(tldGenerator.
			Filter(func(s string) bool { return len(s)+2 <= domainMaxLength }).
			Draw(t, "domain"))

		expr := fmt.Sprintf(`[a-zA-Z]([a-zA-Z0-9\-]{0,%d}[a-zA-Z0-9])?`, domainMaxElementLength-2)

		el := rapid.Int8Range(1, 126).Example().(int)
		for i := 0; i < el; i++ {
			subDomain := fmt.Sprint(rapid.StringMatching(expr).Draw(t, "subdomain"))
			if len(domain)+len(subDomain) >= domainMaxLength {
				break
			}
			domain = subDomain + "." + domain
		}

		return domain
	})
}

var tldGenerator = rapid.SampledFrom(tlds)

func assertf(ok bool, format string, args ...interface{}) {
	if !ok {
		panic(fmt.Sprintf(format, args...))
	}
}
