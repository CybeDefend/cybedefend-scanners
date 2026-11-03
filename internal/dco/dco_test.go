package dco

import (
	"reflect"
	"testing"
)

func TestMissingSignoffFindsUnsignedCommits(t *testing.T) {
	commits := []Commit{
		{SHA: "a", Message: "feat: x\n\nSigned-off-by: Jane <jane@example.org>"},
		{SHA: "b", Message: "fix: y"},
		{SHA: "c", Message: "docs: z\n\nsigned-off-by: lower <l@example.org>"},
	}
	got := MissingSignoff(commits)
	want := []string{"b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("MissingSignoff() = %v, want %v", got, want)
	}
}

func TestMissingSignoffAcceptsATrailerAmongOthers(t *testing.T) {
	commits := []Commit{
		{SHA: "d", Message: "feat: w\n\nCo-Authored-By: Bot <bot@example.org>\nSigned-off-by: Jane <jane@example.org>\n"},
	}
	if got := MissingSignoff(commits); len(got) != 0 {
		t.Fatalf("MissingSignoff() = %v, want none", got)
	}
}

func TestParseLogReadsTheGitLogFormat(t *testing.T) {
	// git log --format=%H%x00%B%x1e: each record ends with 0x1e, git adds a newline between records.
	in := "aaa\x00feat: x\n\nSigned-off-by: Jane <jane@example.org>\n\x1e\nbbb\x00fix: y\n\x1e\n"
	got := ParseLog(in)
	want := []Commit{
		{SHA: "aaa", Message: "feat: x\n\nSigned-off-by: Jane <jane@example.org>\n"},
		{SHA: "bbb", Message: "fix: y\n"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseLog() = %#v, want %#v", got, want)
	}
}

func TestParseLogOfNothingIsEmpty(t *testing.T) {
	if got := ParseLog("\n"); len(got) != 0 {
		t.Fatalf("ParseLog() = %#v, want none", got)
	}
}
