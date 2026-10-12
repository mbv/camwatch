package recorder

import (
	"strings"
	"testing"
)

func TestBuildRemuxArgsTrimAfterInput(t *testing.T) {
	args := buildRemuxBaseArgs("hevc", "in.es", 8, 20, 15)
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-i in.es -ss 8 -t 20") {
		t.Fatalf("trim must follow -i for post-decode cut: %v", args)
	}
	if strings.Index(joined, "-ss") < strings.Index(joined, "-i") {
		t.Fatalf("-ss before -i would skip keyframe sync buffer: %v", args)
	}
}

func TestBuildRemuxArgsNoTrim(t *testing.T) {
	args := buildRemuxBaseArgs("h264", "in.es", 0, 20, 15)
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "-ss") {
		t.Fatalf("unexpected -ss: %v", args)
	}
	if !strings.Contains(joined, "-t 20") {
		t.Fatalf("missing -t: %v", args)
	}
}

func TestRemuxUsesMeasuredFPS(t *testing.T) {
	if j := strings.Join(buildRemuxBaseArgs("h264", "in.es", 0, 20, 10.04), " "); !strings.Contains(j, "-r 10.040 -i") {
		t.Fatalf("measured fps not used: %s", j)
	}
	// Unknown / absurd rates fall back to the default.
	for _, bad := range []float64{0, -1, 0.2, 500} {
		if j := strings.Join(buildRemuxBaseArgs("h264", "in.es", 0, 20, bad), " "); !strings.Contains(j, "-r 15.000 -i") {
			t.Fatalf("fps %v should fall back: %s", bad, j)
		}
	}
}
