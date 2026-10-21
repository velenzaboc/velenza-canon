package providerplan

import (
	"bytes"
	"math/rand/v2"
	"strings"
	"testing"
)

// knownCredentialTokenAnywhereASCIIReference is the ASCII token search exactly
// as it stood before knownCredentialTokenASCIIPrefixesByFirstByte existed: every
// prefix is tried at every start. It is the behavioral oracle for the indexed
// production search and must not be edited to match it.
func knownCredentialTokenAnywhereASCIIReference(value []byte) bool {
	for _, prefix := range []string{"ghp_", "github_pat_", "xoxb-", "xoxp-", "xoxa-", "xoxr-", "sk-", "ya29."} {
		for start := 0; start+len(prefix) <= len(value); start++ {
			if !hasASCIIFoldPrefixBytes(value[start:], prefix) {
				continue
			}
			end := start + len(prefix)
			for end < len(value) && credentialTokenByte(value[end]) {
				end++
			}
			if knownCredentialToken(string(value[start:end])) {
				return true
			}
		}
	}
	for start := 0; start+20 <= len(value); start++ {
		if hasASCIIFoldPrefixBytes(value[start:], "akia") && knownCredentialToken(string(value[start:start+20])) {
			return true
		}
	}
	return false
}

func assertKnownCredentialTokenAnywhereASCIIMatchesReference(t *testing.T, value []byte) bool {
	t.Helper()
	got, want := knownCredentialTokenAnywhereASCII(value), knownCredentialTokenAnywhereASCIIReference(value)
	if got != want {
		t.Fatalf("knownCredentialTokenAnywhereASCII(%q) = %v, reference = %v", value, got, want)
	}
	if bytesAreASCII(value) {
		if wrapped := knownCredentialTokenAnywhere(value); wrapped != want {
			t.Fatalf("knownCredentialTokenAnywhere(%q) = %v, reference = %v", value, wrapped, want)
		}
	}
	return want
}

func knownCredentialTokenIntroducers() []string {
	return append(append([]string(nil), knownCredentialTokenASCIIPrefixes...), knownCredentialAWSAccessKeyIDPrefix)
}

func TestKnownCredentialTokenPrefixIndexHoldsEveryPrefixOnceUnderItsFirstByte(t *testing.T) {
	if want := []string{"ghp_", "github_pat_", "xoxb-", "xoxp-", "xoxa-", "xoxr-", "sk-", "ya29."}; strings.Join(knownCredentialTokenASCIIPrefixes, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("known credential token prefixes = %q, want the knownCredentialToken roster %q", knownCredentialTokenASCIIPrefixes, want)
	}
	if knownCredentialAWSAccessKeyIDPrefix != "akia" || knownCredentialAWSAccessKeyIDLength != 20 {
		t.Fatalf("AWS access key id introducer = %q/%d, want akia/20", knownCredentialAWSAccessKeyIDPrefix, knownCredentialAWSAccessKeyIDLength)
	}
	seen := map[string]int{}
	total := 0
	for first, bucket := range knownCredentialTokenASCIIPrefixesByFirstByte {
		for _, prefix := range bucket {
			if prefix == "" || int(prefix[0]) != first {
				t.Fatalf("prefix %q is indexed under %q", prefix, byte(first))
			}
			seen[prefix]++
			total++
		}
	}
	if total != len(knownCredentialTokenASCIIPrefixes) || len(seen) != len(knownCredentialTokenASCIIPrefixes) {
		t.Fatalf("index holds %d entries over %d prefixes, want %d", total, len(seen), len(knownCredentialTokenASCIIPrefixes))
	}
	for _, prefix := range knownCredentialTokenASCIIPrefixes {
		if seen[prefix] != 1 {
			t.Fatalf("prefix %q indexed %d times, want once", prefix, seen[prefix])
		}
	}
	for _, roster := range [][]string{{""}, {"Ghp_"}, {"sk-", ""}} {
		refused := func() (refused bool) {
			defer func() { refused = recover() != nil }()
			newKnownCredentialTokenASCIIPrefixIndex(roster)
			return false
		}()
		if !refused {
			t.Fatalf("known credential token prefix index accepted roster %q", roster)
		}
	}
}

func TestKnownCredentialTokenAnywhereASCIIMatchesReferenceOnTokenCorpus(t *testing.T) {
	tails := []string{
		"", "abc", "Abcdefgh12345678", "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOP", "1234567890ABCDEF", "1234567890ABCDE", "1234567890ABCDEFG",
		"Abcdefghijklmno1234!", "abc.def~ghi+jkl/mno=pqr-stu", "<API_KEY>", "${TOKEN}", "{{secret}}", "aaaaaaaaaaaaaaaaaaaaaaaa", "a1a1a1a1a1a1a1a1",
	}
	leads := []string{"", " ", "x", "prefix ", "\"", "=", "sk"}
	trails := []string{"", " suffix", "\"", ";", ".end", "!"}
	accepted, rejected := 0, 0
	for _, introducer := range knownCredentialTokenIntroducers() {
		for length := 1; length <= len(introducer); length++ {
			for _, variant := range credentialClosureCasePermutations(introducer[:length]) {
				for _, tail := range tails {
					for _, lead := range leads {
						for _, trail := range trails {
							if assertKnownCredentialTokenAnywhereASCIIMatchesReference(t, []byte(lead+string(variant)+tail+trail)) {
								accepted++
							} else {
								rejected++
							}
						}
					}
				}
			}
		}
		for _, other := range knownCredentialTokenIntroducers() {
			assertKnownCredentialTokenAnywhereASCIIMatchesReference(t, []byte(introducer+other+"Abcdefgh12345678"))
		}
	}
	if accepted == 0 || rejected == 0 {
		t.Fatalf("token corpus accepted %d and rejected %d values, want both outcomes", accepted, rejected)
	}
}

func TestKnownCredentialTokenAnywhereASCIIMatchesReferenceOnEveryOneAndTwoByteValue(t *testing.T) {
	one := make([]byte, 1)
	two := make([]byte, 2)
	for first := 0; first < 256; first++ {
		one[0] = byte(first)
		assertKnownCredentialTokenAnywhereASCIIMatchesReference(t, one)
		for second := 0; second < 256; second++ {
			two[0], two[1] = byte(first), byte(second)
			assertKnownCredentialTokenAnywhereASCIIMatchesReference(t, two)
		}
	}
}

func TestKnownCredentialTokenAnywhereASCIIMatchesReferenceOnSeededRandomCarriers(t *testing.T) {
	alphabet := []byte(" \t\"'<>{}$;:,._~+/=-!0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	random := rand.New(rand.NewPCG(0x6b6e_6f77_6e5f_746f, 0x6b65_6e5f_7363_616e))
	accepted, rejected := 0, 0
	for iteration := 0; iteration < 12_000; iteration++ {
		var value []byte
		for parts := random.IntN(5); parts >= 0; parts-- {
			if random.IntN(3) == 0 {
				introducers := knownCredentialTokenIntroducers()
				introducer := introducers[random.IntN(len(introducers))]
				variants := credentialClosureCasePermutations(introducer)
				value = append(value, variants[random.IntN(len(variants))]...)
			}
			for length := random.IntN(28); length > 0; length-- {
				value = append(value, alphabet[random.IntN(len(alphabet))])
			}
		}
		if assertKnownCredentialTokenAnywhereASCIIMatchesReference(t, value) {
			accepted++
		} else {
			rejected++
		}
	}
	if accepted == 0 || rejected == 0 {
		t.Fatalf("random carriers accepted %d and rejected %d values, want both outcomes", accepted, rejected)
	}
	long := bytes.Repeat([]byte("xoxb-sk-ghp_akia ya29."), 400)
	long = append(long, "AKIA1234567890ABCDEF"...)
	if !assertKnownCredentialTokenAnywhereASCIIMatchesReference(t, long) {
		t.Fatal("long carrier ending in an AWS access key id was not detected by the reference")
	}
}

func FuzzKnownCredentialTokenAnywhereASCIIMatchesReference(f *testing.F) {
	for _, seed := range []string{"", "ghp_", "prefix sk-Abcdefghijklmno1234!", "safe-prefix [aKiA1234567890ABCDEF] safe-suffix", "xoxb-<TOKEN>", "YA29.abcdefghijklmnop1234", "github_pat_", "ordinary documentation sentence"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, value []byte) {
		assertKnownCredentialTokenAnywhereASCIIMatchesReference(t, value)
	})
}
