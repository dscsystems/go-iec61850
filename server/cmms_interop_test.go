package server_test

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestCMMSUtilityEd2Classes points libiec61850's mms_utility at our server
// serving the Edition 2.1 fixture, whose GAPC1 and LTRK1 carry the classes
// Edition 2 and 2.1 added: the C stack must see them in the domain
// directory, under their functional constraints (SP, and SR for service
// tracking), and read them. Set IEC61850_C_MMS_UTILITY to the mms_utility
// binary to enable it.
func TestCMMSUtilityEd2Classes(t *testing.T) {
	bin := os.Getenv("IEC61850_C_MMS_UTILITY")
	if bin == "" {
		t.Skip("set IEC61850_C_MMS_UTILITY to the libiec61850 mms_utility binary")
	}
	m, err := loadEd21(t)
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	addr, _ := startServerWith(t, m)
	host, port, _ := strings.Cut(addr, ":")

	run := func(args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, bin, append([]string{"-h", host, "-p", port}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("mms_utility %v: %v\n%s", args, err, out)
		}
		return string(out)
	}

	dir := run("-t", "ED21LD0")
	for _, name := range []string{
		"GAPC1$ST$Hst$hstVal", "GAPC1$CF$Hst$hstRangeC",
		"GAPC1$MX$ColChg$mxVal", "GAPC1$CO$ColChg$Oper$ctlVal",
		"GAPC1$SP$InRef1$setTstRef", "GAPC1$SP$StrTm$setTm", "GAPC1$SP$Cur$cur",
		"GAPC1$SP$Txt$setVal", "GAPC1$SP$Crv$crvPts",
		"LTRK1$SR$SpcTrk$respAddCause", "LTRK1$SR$GocbTrk$dstAddress$APPID",
	} {
		if !strings.Contains(dir, name) {
			t.Errorf("domain directory lacks %s", name)
		}
	}
	if t.Failed() {
		t.Logf("mms_utility -t output:\n%s", dir)
	}

	for _, tc := range []struct{ variable, want string }{
		{"GAPC1$SP$Cur$cur", "EUR"},
		{"GAPC1$SP$InRef1$setSrcRef", "ED21LD0/GGIO1.Ind1"},
		{"GAPC1$SP$Crv$numPts", "2"},
	} {
		if out := run("-a", "ED21LD0", "-r", tc.variable); !strings.Contains(out, tc.want) {
			t.Errorf("read %s: want %q in\n%s", tc.variable, tc.want, out)
		}
	}
	// Structured and array-valued attributes read as a whole.
	for _, v := range []string{"LTRK1$SR$GocbTrk", "GAPC1$CF$Hst$hstRangeC", "GAPC1$ST$Hst$hstVal"} {
		if out := run("-a", "ED21LD0", "-r", v); strings.Contains(strings.ToLower(out), "error") ||
			strings.Contains(strings.ToLower(out), "failed") {
			t.Errorf("read %s failed:\n%s", v, out)
		} else {
			t.Logf("read %s:\n%s", v, out)
		}
	}
}
