package main

import "strings"

// reorderArgs lifts all flag tokens to the front of the slice so that
// stdlib `flag.Parse` (which stops at the first positional) sees the
// flags regardless of where the user typed them.
//
// `valueFlags` is the set of flag names that consume a following token
// (e.g. `--remote-port 6022` rather than `--verbose`). Boolean flags
// should NOT appear in valueFlags; they're recognized in `--name=val`
// form by their leading dash alone.
//
// Behavior:
//   - `--foo`           -> standalone flag token (bool / =val form)
//   - `--foo bar`       -> flag pair (if "foo" is in valueFlags)
//   - `-foo bar`        -> same as above
//   - `--foo=bar`       -> single token, treated as flag-only
//   - anything else     -> positional
//
// Tokens are kept in their original relative order within each bucket.
func reorderArgs(args []string, valueFlags []string) []string {
	valueSet := make(map[string]struct{}, len(valueFlags))
	for _, v := range valueFlags {
		valueSet[v] = struct{}{}
	}

	var flagsOut, positional []string
	i := 0
	for i < len(args) {
		a := args[i]
		if strings.HasPrefix(a, "-") && a != "-" && a != "--" {
			flagsOut = append(flagsOut, a)
			// `--foo=val` is already self-contained.
			if strings.Contains(a, "=") {
				i++
				continue
			}
			// Strip leading dashes to get the flag name.
			name := strings.TrimLeft(a, "-")
			if _, takesValue := valueSet[name]; takesValue && i+1 < len(args) {
				flagsOut = append(flagsOut, args[i+1])
				i += 2
				continue
			}
			i++
			continue
		}
		positional = append(positional, a)
		i++
	}
	return append(flagsOut, positional...)
}
