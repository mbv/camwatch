package recorder

import (
	"strings"
	"testing"
)

func TestBuildRemuxArgsTrimAfterInput(t *testing.T) {
	args := buildRemuxBaseArgs("hevc", "in.es", 8, 20)
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-i in.es -ss 8 -t 20") {
		t.Fatalf("trim must follow -i for post-decode cut: %v", args)
	}
	if strings.Index(joined, "-ss") < strings.Index(joined, "-i") {
		t.Fatalf("-ss before -i would skip keyframe sync buffer: %v", args)
	}
}

func TestBuildRemuxArgsNoTrim(t *testing.T) {
	args := buildRemuxBaseArgs("h264", "in.es", 0, 20)
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "-ss") {
		t.Fatalf("unexpected -ss: %v", args)
	}
	if !strings.Contains(joined, "-t 20") {
		t.Fatalf("missing -t: %v", args)
	}
}
