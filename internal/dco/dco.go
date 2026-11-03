// Package dco checks that commits carry a Developer Certificate of Origin sign-off.
package dco

import (
	"regexp"
	"strings"
)

// Commit is one commit: its SHA and its full message.
type Commit struct{ SHA, Message string }

// signoff matches a sign-off trailer as git writes it (the key is case-sensitive).
var signoff = regexp.MustCompile(`(?m)^Signed-off-by: .+ <.+@.+>$`)

// MissingSignoff returns the SHAs of the commits whose message has no sign-off line, in input order.
func MissingSignoff(commits []Commit) []string {
	var missing []string
	for _, c := range commits {
		if !signoff.MatchString(strings.ReplaceAll(c.Message, "\r\n", "\n")) {
			missing = append(missing, c.SHA)
		}
	}
	return missing
}

// ParseLog reads the output of `git log --format=%H%x00%B%x1e`.
func ParseLog(out string) []Commit {
	var commits []Commit
	for _, record := range strings.Split(out, "\x1e") {
		record = strings.TrimLeft(record, "\n")
		if record == "" {
			continue
		}
		sha, message, _ := strings.Cut(record, "\x00")
		commits = append(commits, Commit{SHA: strings.TrimSpace(sha), Message: message})
	}
	return commits
}
