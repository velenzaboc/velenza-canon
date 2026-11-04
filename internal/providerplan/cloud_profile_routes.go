package providerplan

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

var cloudRouteSelectorPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)
var cloudRouteTokenPattern = regexp.MustCompile(`\{([A-Za-z][A-Za-z0-9_]{0,63})\}`)
var cloudRouteDNSLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func validateCloudOperationRoute(route CloudOperationRoute) error {
	selectors := map[string]string{}
	for _, name := range route.RequiredSelectors {
		selectors[name] = "example"
	}
	_, err := ResolveCloudOperationRoute(route, selectors)
	return err
}

// ResolveCloudOperationRoute composes a declared HTTPS read route without
// credentials or network access. Host, path and query substitutions have
// separate grammars. No selector may introduce authority or URL structure.
func ResolveCloudOperationRoute(route CloudOperationRoute, selectors map[string]string) (string, error) {
	if route.Method != "GET" || !profileText(route.AuthorityTemplate, 253) || !strings.HasPrefix(route.PathTemplate, "/") || strings.HasPrefix(route.PathTemplate, "//") || strings.ContainsAny(route.PathTemplate, "?#\\\r\n\t ") || len(route.PathTemplate) > 4096 {
		return "", fmt.Errorf("invalid operation route")
	}
	if len(selectors) != len(route.RequiredSelectors) || (len(route.RequiredSelectors) > 0 && !strictSortedUniqueProfileStrings(route.RequiredSelectors, 64)) {
		return "", fmt.Errorf("selector roster does not match route")
	}
	for _, name := range route.RequiredSelectors {
		if !cloudRouteSelectorPattern.MatchString(name) || !profileText(selectors[name], 2048) {
			return "", fmt.Errorf("invalid or missing route selector")
		}
	}
	used := map[string]bool{}
	replace := func(template string, encode func(string) string) (string, error) {
		var bad bool
		result := cloudRouteTokenPattern.ReplaceAllStringFunc(template, func(token string) string {
			name := token[1 : len(token)-1]
			value, ok := selectors[name]
			if !ok {
				bad = true
				return token
			}
			used[name] = true
			return encode(value)
		})
		if bad || strings.ContainsAny(result, "{}") {
			return "", fmt.Errorf("undeclared or malformed route selector")
		}
		return result, nil
	}
	// Each authority placeholder is exactly one DNS label. Dots are static
	// profile data; a runtime value cannot append or replace a host suffix.
	authorityParts := strings.Split(route.AuthorityTemplate, ".")
	for i, part := range authorityParts {
		if strings.ContainsAny(part, "{}") {
			if !cloudRouteTokenPattern.MatchString(part) || cloudRouteTokenPattern.FindString(part) != part {
				return "", fmt.Errorf("authority selector must occupy one label")
			}
			var err error
			part, err = replace(part, func(s string) string { return s })
			if err != nil {
				return "", err
			}
		}
		if !cloudRouteDNSLabelPattern.MatchString(part) {
			return "", fmt.Errorf("invalid authority label")
		}
		authorityParts[i] = part
	}
	authority := strings.Join(authorityParts, ".")
	if len(authorityParts) < 2 || len(authority) > 253 {
		return "", fmt.Errorf("invalid authority")
	}
	path, err := replace(route.PathTemplate, url.PathEscape)
	if err != nil {
		return "", err
	}
	// Dot segments are never route coordinates, including escaped ones.
	for _, part := range strings.Split(path, "/") {
		decoded, e := url.PathUnescape(part)
		if e != nil || decoded == "." || decoded == ".." {
			return "", fmt.Errorf("invalid path segment")
		}
	}
	queryKeys := make([]string, 0, len(route.QueryTemplates))
	for key := range route.QueryTemplates {
		queryKeys = append(queryKeys, key)
	}
	sort.Strings(queryKeys)
	query := make([]string, 0, len(queryKeys))
	for _, key := range queryKeys {
		if !profileText(key, 256) || strings.ContainsAny(key, "{}&=#?\\") {
			return "", fmt.Errorf("invalid query key")
		}
		value, err := replace(route.QueryTemplates[key], func(s string) string { return s })
		if err != nil {
			return "", err
		}
		entry := url.QueryEscape(key)
		if value != "" {
			entry += "=" + url.QueryEscape(value)
		}
		query = append(query, entry)
	}
	if len(used) != len(selectors) {
		return "", fmt.Errorf("unused route selector")
	}
	result := "https://" + authority + path
	if len(query) > 0 {
		result += "?" + strings.Join(query, "&")
	}
	u, err := url.Parse(result)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Host != authority || u.Port() != "" || u.Fragment != "" || u.Opaque != "" {
		return "", fmt.Errorf("invalid resolved HTTPS route")
	}
	return result, nil
}

func validateCloudRetryPolicy(policy CloudRetryShape) error {
	if !policy.IdempotentRead || policy.MaxAttempts < 1 || policy.MaxAttempts > 100 || policy.InitialBackoffMillis < 1 || policy.MaxBackoffMillis < policy.InitialBackoffMillis || policy.MaxBackoffMillis > 86400000 || policy.Jitter != "full" || !strictSortedUniqueProfileStrings(policy.Classifications, 128) {
		return fmt.Errorf("invalid bounded read retry policy")
	}
	for _, class := range policy.Classifications {
		switch class {
		case "client_throttling", "server_transient", "transport_transient":
		default:
			return fmt.Errorf("unknown retry classification")
		}
	}
	return nil
}

// CloudRetryDelay returns a deterministic full-jitter planning result. The
// caller supplies entropy and an owner-classified failure; this helper neither
// classifies arbitrary responses nor sleeps, retries or grants access.
func CloudRetryDelay(policy CloudRetryShape, class string, attempt int, entropy uint64) (millis int64, retry bool, err error) {
	if err := validateCloudRetryPolicy(policy); err != nil {
		return 0, false, err
	}
	if attempt < 1 {
		return 0, false, fmt.Errorf("attempt must be positive")
	}
	if attempt >= policy.MaxAttempts || !containsCloudProfileString(policy.Classifications, class) {
		return 0, false, nil
	}
	cap := policy.InitialBackoffMillis
	for n := 1; n < attempt && cap < policy.MaxBackoffMillis; n++ {
		if cap > policy.MaxBackoffMillis/2 {
			cap = policy.MaxBackoffMillis
		} else {
			cap *= 2
		}
	}
	return int64(entropy % uint64(cap+1)), true, nil
}
