package sarif

import (
	"encoding/json"
)

// RenameRuleIDs rewrites the rule ids of the runs for which renamer returns a
// function: runs[].tool.driver.rules[].id, runs[].results[].ruleId and
// runs[].results[].rule.id. rename answers the new id and true, or false to
// keep the id. Every other byte of the log is kept. It returns the number of
// ids rewritten. A member that is not where SARIF puts it (not an object, not
// a string) is left alone: Parse accepted the file, and the server decides.
func RenameRuleIDs(l *Log, renamer func(*Run) func(id string) (string, bool)) int {
	n := 0
	for ri := range l.Runs {
		run := &l.Runs[ri]
		rename := renamer(run)
		if rename == nil {
			continue
		}
		if raw, ok := run.Tool.Driver.Extra["rules"]; ok {
			if out, c := renameInArray(raw, rename); c > 0 {
				run.Tool.Driver.Extra["rules"] = out
				n += c
			}
		}
		for i := range run.Results {
			res := &run.Results[i]
			if raw, ok := res.Extra["ruleId"]; ok {
				if out, ok := renameString(raw, rename); ok {
					res.Extra["ruleId"] = out
					n++
				}
			}
			if raw, ok := res.Extra["rule"]; ok {
				if out, ok := renameMember(raw, "id", rename); ok {
					res.Extra["rule"] = out
					n++
				}
			}
		}
	}
	return n
}

// renameString rewrites a JSON string value.
func renameString(raw json.RawMessage, rename func(string) (string, bool)) (json.RawMessage, bool) {
	if isNull(raw) {
		return nil, false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, false
	}
	to, ok := rename(s)
	if !ok || to == s {
		return nil, false
	}
	return encodeString(to), true
}

// renameMember rewrites the string member key of a JSON object, keeping the
// other members and their order.
func renameMember(raw json.RawMessage, key string, rename func(string) (string, bool)) (json.RawMessage, bool) {
	if isNull(raw) {
		return nil, false
	}
	order, vals, err := decodeObject(raw, "object")
	if err != nil {
		return nil, false
	}
	v, ok := vals[key]
	if !ok {
		return nil, false
	}
	nv, ok := renameString(v, rename)
	if !ok {
		return nil, false
	}
	vals[key] = nv
	f := fields{order: order}
	out, err := writeObject(nil, &f, nil, vals)
	if err != nil {
		return nil, false
	}
	return out, true
}

// renameInArray rewrites the id of each object of a JSON array.
func renameInArray(raw json.RawMessage, rename func(string) (string, bool)) (json.RawMessage, int) {
	items, err := decodeArray(raw, "rules")
	if err != nil || items == nil {
		return nil, 0
	}
	n := 0
	for i, it := range items {
		if out, ok := renameMember(it, "id", rename); ok {
			items[i] = out
			n++
		}
	}
	if n == 0 {
		return nil, 0
	}
	out := []byte{'['}
	for i, it := range items {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, it...)
	}
	return append(out, ']'), n
}
