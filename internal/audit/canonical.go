// RFC 8785 JSON Canonicalization Scheme (JCS) encoder, hand-rolled to
// avoid taking on a third-party dependency for a one-call surface.
// Used by chain.go to produce the bytes hashed into row_hash.
//
// Subset implemented (covers what audit Event records produce):
//   - Object keys sorted by UTF-16 code-unit ordering (RFC 8785 §3.2.3).
//   - No insignificant whitespace.
//   - Strings: NFC unicode normalisation + RFC 8785 string escaping.
//   - Numbers: ECMAScript ToString(Number) per RFC 8785 §3.2.4. Integer
//     values render with no `.` or `e`; non-integer floats use fixed
//     notation when the decimal exponent k satisfies -6 <= k <= 20 and
//     exponential notation (form `<digits>e+<exp>` / `<digits>e-<exp>`,
//     always signed, never zero-padded) otherwise. The boundary at
//     1e21 / 1e-7 differs from Go's strconv 'g' formatter; we
//     reconstruct the ECMAScript output directly so byte-identical
//     canonical encoding holds across implementations.
//   - Booleans, null, arrays handled per JSON.
//   - UTF-8 byte output.
//
// Not implemented: JSON numbers outside double precision (BigInt), since
// audit Event values never carry them; if a future field needs one, add
// handling here with a test.
package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"unicode/utf16"

	"golang.org/x/text/unicode/norm"
)

// Canonicalize returns the RFC 8785 JCS encoding of v.
//
// Accepted shapes are the JSON-native Go types: nil, bool, string,
// json.Number, all numeric types, []any, map[string]any, plus structs
// (encoded via their JSON marshalling, then re-canonicalised). Anything
// outside that returns an error rather than silently coercing — callers
// in this package only ever pass map[string]any built from typed
// columns, so the strict surface catches accidental misuse.
func Canonicalize(v any) ([]byte, error) {
	// Round-trip through encoding/json to flatten structs / pointers /
	// any custom MarshalJSON into a uniform map/slice tree, then
	// canonicalise that tree. encoding/json's number handling becomes
	// json.Number which we re-format below.
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonicalize: marshal: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		return nil, fmt.Errorf("canonicalize: decode: %w", err)
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, tree); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
		return nil
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
		return nil
	case string:
		return writeCanonicalString(buf, x)
	case json.Number:
		return writeCanonicalNumber(buf, string(x))
	case []any:
		buf.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sortKeysUTF16(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalString(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeCanonical(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	default:
		return fmt.Errorf("canonicalize: unsupported type %T", v)
	}
}

// sortKeysUTF16 orders strings by their UTF-16 code-unit sequence per
// RFC 8785 §3.2.3. Go's natural string < compares UTF-8 bytes, which
// ranks supplementary-plane code points BELOW BMP code points whose
// UTF-16 surrogate pair encoding starts with a high surrogate (0xD800+).
// JCS requires the UTF-16 view; we materialise it explicitly.
func sortKeysUTF16(keys []string) {
	encoded := make([][]uint16, len(keys))
	for i, k := range keys {
		encoded[i] = utf16.Encode([]rune(norm.NFC.String(k)))
	}
	idx := make([]int, len(keys))
	for i := range idx {
		idx[i] = i
	}
	sort.Slice(idx, func(a, b int) bool {
		ka, kb := encoded[idx[a]], encoded[idx[b]]
		for n := 0; n < len(ka) && n < len(kb); n++ {
			if ka[n] != kb[n] {
				return ka[n] < kb[n]
			}
		}
		return len(ka) < len(kb)
	})
	tmp := make([]string, len(keys))
	for i, j := range idx {
		tmp[i] = keys[j]
	}
	copy(keys, tmp)
}

// writeCanonicalString emits an RFC 8785 string: NFC-normalise the
// runes, then escape per RFC 8259 §7 with the JCS-mandated short forms
// (\b, \t, \n, \f, \r, \", \\) and \uXXXX for everything else under
// 0x20. Characters >= 0x20 pass through as UTF-8.
func writeCanonicalString(buf *bytes.Buffer, s string) error {
	s = norm.NFC.String(s)
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\t':
			buf.WriteString(`\t`)
		case '\n':
			buf.WriteString(`\n`)
		case '\f':
			buf.WriteString(`\f`)
		case '\r':
			buf.WriteString(`\r`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
	return nil
}

// writeCanonicalNumber emits a JSON number per RFC 8785 §3.2.4, which
// references the ECMAScript ToString(Number) algorithm
// (ES2023 §6.1.6.1.20). We accept a json.Number string (already
// validated as a JSON number by the decoder) and:
//   - keep integer literals as integer (no trailing `.0`),
//   - reformat floats via the ECMAScript rules (see ecmaScriptNumber),
//   - reject NaN / +Inf / -Inf (RFC 8785 forbids them in JCS).
func writeCanonicalNumber(buf *bytes.Buffer, s string) error {
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		buf.WriteString(strconv.FormatInt(i, 10))
		return nil
	}
	if u, err := strconv.ParseUint(s, 10, 64); err == nil {
		buf.WriteString(strconv.FormatUint(u, 10))
		return nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return fmt.Errorf("canonicalize: parse number %q: %w", s, err)
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return fmt.Errorf("canonicalize: NaN/Inf not representable in JCS")
	}
	buf.WriteString(ecmaScriptNumber(f))
	return nil
}

// ecmaScriptNumber renders f per the ECMAScript ToString(Number)
// algorithm (ES2023 §6.1.6.1.20), which RFC 8785 §3.2.4 inherits.
//
// The shape:
//   - Zero -> "0".
//   - Integer-valued floats inside int64 range -> decimal integer with
//     no decimal point or exponent.
//   - Otherwise, derive the shortest round-trip mantissa s and decimal
//     exponent expE from strconv.FormatFloat 'e' / -1 (s is in [1, 10),
//     so the printed exponent expE satisfies value = mantissa * 10^expE
//     where the leading digit is non-zero). Let k = digit-count of s.
//     ECMAScript "n" = expE + 1.
//   - If -6 <= expE <= 20: fixed notation.
//   - Otherwise: exponential as `<digit>[.<rest>]e<+|->|n-1|` — the
//     sign is always present (no `e+0`-style padding, no leading zero
//     on the exponent value).
//
// The boundary at expE=21 (1e21 -> "1e+21") and expE=-7 (1e-7 ->
// "1e-7") differs from Go's strconv 'g' format; we reconstruct the
// ECMAScript output directly to keep canonical encoding byte-identical
// across implementations.
func ecmaScriptNumber(f float64) string {
	if f == 0 {
		// Both +0 and -0 render as "0" per ECMAScript ToString(0).
		return "0"
	}
	// Integer fast-path: whole-valued floats inside int64 range emit as
	// the decimal integer form, matching ECMAScript ToString for any
	// integer in the safe-integer range.
	const int64MaxAsFloat = 9.223372036854775e18
	if f == math.Trunc(f) && f >= -int64MaxAsFloat && f <= int64MaxAsFloat {
		return strconv.FormatInt(int64(f), 10)
	}

	// FormatFloat 'e' / -1 yields "<sign?><digit>.<rest>e<sign><expdigits>"
	// with the shortest round-trip mantissa. We split on 'e' and extract
	// the digits (sans decimal point) plus the integer exponent.
	raw := strconv.FormatFloat(f, 'e', -1, 64)
	negative := false
	if raw[0] == '-' {
		negative = true
		raw = raw[1:]
	}
	eIdx := -1
	for i := 0; i < len(raw); i++ {
		if raw[i] == 'e' {
			eIdx = i
			break
		}
	}
	if eIdx < 0 {
		// Defensive — FormatFloat 'e' always emits an 'e'. Fall back
		// to 'g' rather than panicking; only reachable if the stdlib
		// changes its contract.
		return strconv.FormatFloat(f, 'g', -1, 64)
	}
	mantissaStr := raw[:eIdx]
	expStr := raw[eIdx+1:]
	expE, err := strconv.Atoi(expStr)
	if err != nil {
		return strconv.FormatFloat(f, 'g', -1, 64)
	}
	// Strip the decimal point so digits is the bare significand.
	digits := mantissaStr
	if dot := indexByte(mantissaStr, '.'); dot >= 0 {
		digits = mantissaStr[:dot] + mantissaStr[dot+1:]
	}
	// Trim trailing zeros so digit count k matches the ECMAScript
	// "minimal s digits" contract. FormatFloat 'e' / -1 already does
	// this for the mantissa, but the manual splice above can leave
	// nothing to trim — guard anyway for robustness.
	for len(digits) > 1 && digits[len(digits)-1] == '0' {
		digits = digits[:len(digits)-1]
	}
	k := len(digits)
	n := expE + 1 // ECMAScript "n" — value = digits * 10^(n-k)

	var out string
	switch {
	case expE >= -6 && expE <= 20:
		// Fixed notation. Three sub-cases keyed by n vs k.
		switch {
		case n >= k:
			// digits, then (n-k) trailing zeros, no decimal.
			out = digits + repeatZeros(n-k)
		case n > 0:
			// First n digits, '.', remaining (k-n).
			out = digits[:n] + "." + digits[n:]
		default:
			// n <= 0: "0." + (-n) leading zeros + digits.
			out = "0." + repeatZeros(-n) + digits
		}
	default:
		// Exponential. ECMAScript: "<digit>[.<rest>]e<sign>|n-1|".
		exp := n - 1
		var expSign string
		if exp >= 0 {
			expSign = "+"
		} else {
			expSign = "-"
			exp = -exp
		}
		if k == 1 {
			out = digits + "e" + expSign + strconv.Itoa(exp)
		} else {
			out = digits[:1] + "." + digits[1:] + "e" + expSign + strconv.Itoa(exp)
		}
	}
	if negative {
		out = "-" + out
	}
	return out
}

// indexByte is a stdlib-free byte search used only inside this file's
// number rendering to keep the import surface minimal.
func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// repeatZeros returns a string of n '0' characters; n <= 0 returns "".
func repeatZeros(n int) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = '0'
	}
	return string(b)
}
