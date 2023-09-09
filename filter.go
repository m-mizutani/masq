package masq

import (
	"regexp"
	"strings"
)

type Filter func(s string) string
type Filters []Filter

func (x Filters) ReplaceString(s string) string {
	for _, f := range x {
		s = f(s)
	}
	return s
}

// string
func newStringFilter(target, replaced string) Filter {
	return func(s string) string {
		return strings.ReplaceAll(s, target, replaced)
	}
}

// regex
func newRegexFilter(target *regexp.Regexp, replaced string) Filter {
	return func(s string) string {
		return target.ReplaceAllString(s, replaced)
	}
}
