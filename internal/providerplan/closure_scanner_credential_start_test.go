package providerplan

import (
	"bytes"
	"math/rand/v2"
	"testing"
)

// credentialClosureCarrierCanStartReference is the introducer predicate exactly
// as it stood before credentialClosureStartPatternsByFirstByte existed: every
// roster entry is tried at every call. It is the behavioral oracle for the
// indexed production predicate and must not be edited to match it.
func credentialClosureCarrierCanStartReference(value []byte) bool {
	value = credentialClosureTrimLeftSpace(value)
	if len(value) == 0 {
		return false
	}

	for _, name := range credentialClosureAssignmentNames {
		nameBytes := []byte(name)
		if len(value) <= len(nameBytes) && credentialClosureEqualFoldASCII(value, nameBytes[:len(value)]) {
			return true
		}
		if len(value) < len(nameBytes) || !credentialClosureEqualFoldASCII(value[:len(nameBytes)], nameBytes) {
			continue
		}
		remainder := credentialClosureTrimLeftHorizontalSpace(value[len(nameBytes):])
		if len(remainder) == 0 || remainder[0] == '=' || remainder[0] == ':' {
			return true
		}
	}
	for _, prefix := range credentialClosureKnownTokenPrefixes {
		if credentialClosureStartsOrIsPrefix(value, []byte(prefix)) {
			return true
		}
	}
	if credentialClosureStartsOrIsPrefix(value, []byte("eyj")) {
		return true
	}
	for _, prefix := range credentialClosureHeaderPrefixes {
		if credentialClosureStartsOrIsPrefix(value, []byte(prefix)) {
			return true
		}
	}
	return false
}

// credentialClosureCarrierStartOffsetReference is the byte-position search
// driven by the reference predicate.
func credentialClosureCarrierStartOffsetReference(value []byte) (int, bool) {
	for start := 0; start < len(value); {
		for start < len(value) && credentialClosureIsSpace(value[start]) {
			start++
		}
		if start == len(value) {
			break
		}
		if credentialClosureCarrierCanStartReference(value[start:]) {
			return start, true
		}
		start++
	}
	return 0, false
}

func credentialClosureStartRosters() []string {
	introducers := append([]string(nil), credentialClosureAssignmentNames...)
	introducers = append(introducers, credentialClosureKnownTokenPrefixes...)
	introducers = append(introducers, credentialClosureJWTPrefix)
	return append(introducers, credentialClosureHeaderPrefixes...)
}

func assertCredentialClosureCarrierCanStartMatchesReference(t *testing.T, value []byte) {
	t.Helper()
	if got, want := credentialClosureCarrierCanStart(value), credentialClosureCarrierCanStartReference(value); got != want {
		t.Fatalf("credentialClosureCarrierCanStart(%q) = %v, reference = %v", value, got, want)
	}
}

func assertCredentialClosureCarrierStartOffsetMatchesReference(t *testing.T, value []byte) {
	t.Helper()
	gotStart, gotFound := credentialClosureCarrierStartOffset(value)
	wantStart, wantFound := credentialClosureCarrierStartOffsetReference(value)
	if gotStart != wantStart || gotFound != wantFound {
		t.Fatalf("credentialClosureCarrierStartOffset(%q) = (%d, %v), reference = (%d, %v)", value, gotStart, gotFound, wantStart, wantFound)
	}
}

func credentialClosureCasePermutations(value string) [][]byte {
	lower := []byte(value)
	upper := bytes.ToUpper(lower)
	alternateLowerFirst := bytes.Clone(lower)
	alternateUpperFirst := bytes.Clone(lower)
	for index := range lower {
		if index%2 == 0 {
			alternateUpperFirst[index] = upper[index]
		} else {
			alternateLowerFirst[index] = upper[index]
		}
	}
	return [][]byte{lower, upper, alternateLowerFirst, alternateUpperFirst}
}

func TestCredentialClosureStartPatternIndexHoldsEveryIntroducerOnceUnderItsFoldedFirstByte(t *testing.T) {
	want := map[string]int{}
	for _, introducer := range credentialClosureStartRosters() {
		want[introducer]++
	}
	got := map[string]int{}
	total := 0
	for first, bucket := range credentialClosureStartPatternsByFirstByte {
		for _, pattern := range bucket {
			if len(pattern.bytes) == 0 {
				t.Fatalf("bucket %q holds an empty introducer", byte(first))
			}
			if folded := credentialClosureFoldASCII(pattern.bytes[0]); int(folded) != first {
				t.Fatalf("introducer %q is indexed under %q, want its folded first byte %q", pattern.bytes, byte(first), folded)
			}
			got[string(pattern.bytes)]++
			total++
		}
	}
	if total != len(credentialClosureStartRosters()) || len(got) != len(want) {
		t.Fatalf("index holds %d entries over %d introducers, want %d entries over %d", total, len(got), len(credentialClosureStartRosters()), len(want))
	}
	for introducer, count := range want {
		if got[introducer] != count {
			t.Fatalf("introducer %q indexed %d times, want %d", introducer, got[introducer], count)
		}
	}
	for _, name := range credentialClosureAssignmentNames {
		for _, pattern := range credentialClosureStartPatternsByFirstByte[credentialClosureFoldASCII(name[0])] {
			if string(pattern.bytes) == name && !pattern.assignment {
				t.Fatalf("assignment name %q is indexed as a prefix introducer", name)
			}
		}
	}
	for _, prefix := range append(append(append([]string(nil), credentialClosureKnownTokenPrefixes...), credentialClosureJWTPrefix), credentialClosureHeaderPrefixes...) {
		for _, pattern := range credentialClosureStartPatternsByFirstByte[credentialClosureFoldASCII(prefix[0])] {
			if string(pattern.bytes) == prefix && pattern.assignment {
				t.Fatalf("prefix introducer %q is indexed as an assignment name", prefix)
			}
		}
	}
}

func TestCredentialClosureStartPatternIndexRefusesEmptyIntroducer(t *testing.T) {
	for _, test := range []struct {
		name  string
		build func()
	}{
		{name: "empty assignment name", build: func() { newCredentialClosureStartPatternIndex([]string{""}, nil, "eyj", nil) }},
		{name: "empty token prefix", build: func() { newCredentialClosureStartPatternIndex(nil, []string{""}, "eyj", nil) }},
		{name: "empty jwt prefix", build: func() { newCredentialClosureStartPatternIndex(nil, nil, "", nil) }},
		{name: "empty header prefix", build: func() { newCredentialClosureStartPatternIndex(nil, nil, "eyj", []string{""}) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			refused := func() (refused bool) {
				defer func() { refused = recover() != nil }()
				test.build()
				return false
			}()
			if !refused {
				t.Fatal("introducer index accepted an empty introducer that would break the first-byte partition")
			}
		})
	}
}

func TestCredentialClosureCarrierCanStartMatchesReferenceOnIntroducerCorpus(t *testing.T) {
	prefixes := []string{"", " ", "\t", "\r\n ", "x", "_", "-"}
	suffixes := []string{"", " ", "=", ":", " =", "\t:", " \t=", "x", " x", "_", "-", "0", "=secret-value", ": Bearer abc"}
	accepted, rejected := 0, 0
	check := func(value []byte) {
		assertCredentialClosureCarrierCanStartMatchesReference(t, value)
		if credentialClosureCarrierCanStartReference(value) {
			accepted++
		} else {
			rejected++
		}
	}
	for _, introducer := range credentialClosureStartRosters() {
		for length := 1; length <= len(introducer); length++ {
			for _, variant := range credentialClosureCasePermutations(introducer[:length]) {
				for _, prefix := range prefixes {
					for _, suffix := range suffixes {
						check([]byte(prefix + string(variant) + suffix))
					}
				}
				// Near misses: the same bytes with the last byte shifted either way.
				for _, delta := range []byte{1, 255} {
					nearMiss := bytes.Clone(variant)
					nearMiss[len(nearMiss)-1] += delta
					check(nearMiss)
					check(append(bytes.Clone(nearMiss), " ="...))
				}
			}
		}
		for _, other := range credentialClosureStartRosters() {
			check([]byte(introducer + other))
			check([]byte(introducer + " " + other))
		}
	}
	// The corpus must exercise both outcomes, or equality proves nothing.
	if accepted == 0 || rejected == 0 {
		t.Fatalf("introducer corpus accepted %d and rejected %d values, want both outcomes", accepted, rejected)
	}
}

func TestCredentialClosureCarrierCanStartMatchesReferenceOnEveryOneAndTwoByteValue(t *testing.T) {
	one := make([]byte, 1)
	two := make([]byte, 2)
	for first := 0; first < 256; first++ {
		one[0] = byte(first)
		assertCredentialClosureCarrierCanStartMatchesReference(t, one)
		for second := 0; second < 256; second++ {
			two[0], two[1] = byte(first), byte(second)
			assertCredentialClosureCarrierCanStartMatchesReference(t, two)
		}
	}
}

func TestCredentialClosureCarrierPredicatesMatchReferenceOnSeededRandomCarriers(t *testing.T) {
	alphabet := []byte(" \t\r\n=:_-./+0123456789\x00\x7f\x80\xff@[`{")
	for _, introducer := range credentialClosureStartRosters() {
		alphabet = append(alphabet, introducer...)
		alphabet = append(alphabet, bytes.ToUpper([]byte(introducer))...)
	}
	random := rand.New(rand.NewPCG(0x7665_6c65_6e7a_6131, 0x7072_6f76_6964_6572))
	fragment := func(maxLength int) []byte {
		if random.IntN(4) == 0 {
			introducer := credentialClosureStartRosters()[random.IntN(len(credentialClosureStartRosters()))]
			variants := credentialClosureCasePermutations(introducer[:1+random.IntN(len(introducer))])
			return variants[random.IntN(len(variants))]
		}
		value := make([]byte, random.IntN(maxLength+1))
		for index := range value {
			value[index] = alphabet[random.IntN(len(alphabet))]
		}
		return value
	}
	found, notFound := 0, 0
	for iteration := 0; iteration < 20_000; iteration++ {
		value := fragment(48)
		assertCredentialClosureCarrierCanStartMatchesReference(t, value)
	}
	for iteration := 0; iteration < 4_000; iteration++ {
		var carrier []byte
		for parts := random.IntN(6); parts >= 0; parts-- {
			carrier = append(carrier, fragment(40)...)
		}
		assertCredentialClosureCarrierStartOffsetMatchesReference(t, carrier)
		if _, ok := credentialClosureCarrierStartOffsetReference(carrier); ok {
			found++
		} else {
			notFound++
		}
	}
	if found == 0 || notFound == 0 {
		t.Fatalf("random carriers found %d and missed %d introducer offsets, want both outcomes", found, notFound)
	}
}

func FuzzCredentialClosureCarrierCanStartMatchesReference(f *testing.F) {
	for _, seed := range []string{"", " ", "API_KEY =", "ghp_", "Bearer ", "eyJ", "-----BEGIN", "access tokenx", "xoxb", "\tpassword:", "sk", "ya29", "zzz"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, value []byte) {
		assertCredentialClosureCarrierCanStartMatchesReference(t, value)
		assertCredentialClosureCarrierStartOffsetMatchesReference(t, value)
	})
}
