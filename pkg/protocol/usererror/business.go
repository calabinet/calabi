package usererror

import (
	_ "embed"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

//go:embed business.json
var businessJSON []byte

type businessRule struct {
	Key       string            `json:"key"`
	Pattern   string            `json:"pattern"`
	Args      map[string]int    `json:"args"`
	Constants map[string]string `json:"constants"`
	re        *regexp.Regexp
}

type argumentRule struct {
	Pattern string   `json:"pattern"`
	Values  []string `json:"values"`
	re      *regexp.Regexp
}

var businessCatalog = func() struct {
	Messages  map[string]string       `json:"messages"`
	Rules     []businessRule          `json:"rules"`
	Codes     map[string]string       `json:"codes"`
	Arguments map[string]argumentRule `json:"arguments"`
} {
	var c struct {
		Messages  map[string]string       `json:"messages"`
		Rules     []businessRule          `json:"rules"`
		Codes     map[string]string       `json:"codes"`
		Arguments map[string]argumentRule `json:"arguments"`
	}
	if err := json.Unmarshal(businessJSON, &c); err != nil {
		panic(err)
	}
	for i := range c.Rules {
		c.Rules[i].re = regexp.MustCompile("(?i)" + c.Rules[i].Pattern)
	}
	for k, rule := range c.Arguments {
		if rule.Pattern != "" {
			rule.re = regexp.MustCompile(rule.Pattern)
			c.Arguments[k] = rule
		}
	}
	return c
}()

var templateSlot = regexp.MustCompile(`\{\{([a-zA-Z]+)\}\}`)
var protocolPrefix = regexp.MustCompile(`^calabi: code=\d+\s+`)

// Format supplies an English fallback for a catalogued business reason. Only
// declared placeholders are interpolated, once; argument text is never a template.
func Format(key string, args map[string]string) (string, bool) {
	template, ok := businessCatalog.Messages[strings.TrimPrefix(key, "business.")]
	if !ok {
		return "", false
	}
	valid := true
	text := templateSlot.ReplaceAllStringFunc(template, func(slot string) string {
		name := slot[2 : len(slot)-2]
		value, ok := args[name]
		if !ok || !validArgument(name, value) {
			valid = false
		}
		return value
	})
	return text, valid
}

func validArgument(name, value string) bool {
	rule, ok := businessCatalog.Arguments[name]
	if !ok {
		return false
	}
	if rule.re != nil {
		return rule.re.MatchString(value)
	}
	for _, allowed := range rule.Values {
		if value == allowed {
			return true
		}
	}
	return false
}

// Business classifies verified, user-actionable reasons, not arbitrary internal
// diagnostics. Internal RPC codes are deliberately rejected before matching.
func Business(raw, code string) (message, key string, args map[string]string, ok bool) {
	msg := protocolPrefix.ReplaceAllString(strings.TrimSpace(raw), "")
	for strings.Contains(msg, "rpc error: code = ") {
		rest := msg[strings.Index(msg, "rpc error: code = ")+len("rpc error: code = "):]
		grpcCode, desc, found := strings.Cut(rest, " desc = ")
		if !found {
			return "", "", nil, false
		}
		switch grpcCode {
		case "Internal", "Unknown", "DataLoss", "Unavailable", "DeadlineExceeded":
			return "", "", nil, false
		}
		msg = desc
	}
	if k, found := businessCatalog.Codes[code]; found {
		text, valid := Format(k, nil)
		return text, "business." + k, nil, valid
	}
	for _, rule := range businessCatalog.Rules {
		match := rule.re.FindStringSubmatch(msg)
		if match == nil {
			continue
		}
		args = make(map[string]string)
		for k, v := range rule.Constants {
			args[k] = v
		}
		for k, index := range rule.Args {
			if index < len(match) {
				args[k] = match[index]
			}
		}
		text, valid := Format(rule.Key, args)
		return text, "business." + rule.Key, args, valid
	}
	// A local API may receive the already formatted English fallback from an
	// older gateway. Recognize it without treating a translated sentence as a code.
	for k, template := range businessCatalog.Messages {
		if !templateSlot.MatchString(template) && msg == template {
			return template, "business." + k, nil, true
		}
	}
	return "", "", nil, false
}

// Hint is a structured, translatable recovery instruction. Keep Message as an
// English fallback for older clients; Key and Args are the localization contract.
type Hint struct {
	Key     string            `json:"key"`
	Args    map[string]string `json:"args,omitempty"`
	Message string            `json:"message"`
}

func NewHint(key string, args map[string]string) Hint {
	text, ok := Format(key, args)
	if !ok {
		panic("invalid business hint: " + key)
	}
	return Hint{Key: "business." + strings.TrimPrefix(key, "business."), Args: args, Message: text}
}

func stringArgs(v any) map[string]string {
	if m, ok := v.(map[string]string); ok {
		return m
	}
	args := map[string]string{}
	if m, ok := v.(map[string]any); ok {
		for k, v := range m {
			switch x := v.(type) {
			case string:
				args[k] = x
			case float64:
				args[k] = strconv.FormatFloat(x, 'f', -1, 64)
			case int:
				args[k] = strconv.Itoa(x)
			}
		}
	}
	return args
}
