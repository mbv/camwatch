package mtp

import "fmt"

// Verbose enables full wire-level TX/RX debug prints (CHK/KCP/CNT/media frames).
// Default off. When set, Protocol milestones are included automatically.
var Verbose bool

// Protocol enables concise milestone logs for the MTP session (dial, login,
// media bind, miss cmds, RDT timeline). Far quieter than Verbose.
var Protocol bool

// Logf prints only when Verbose is set (unchanged wire dumps).
func Logf(format string, args ...any) {
	if !Verbose {
		return
	}
	fmt.Printf(format, args...)
}

// Logp prints key protocol moments when Protocol or Verbose is set.
func Logp(format string, args ...any) {
	if !Protocol && !Verbose {
		return
	}
	fmt.Printf(format, args...)
}
