package db

import (
	"context"
	"testing"
)

// TestFanOutDiagnostic 只用于定位扇出未处理事件的原因(临时诊断,保留其断言价值:
// 扇出必须能把未处理事件一次性清空)。
func TestFanOutDiagnostic(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	ctx := context.Background()

	var before int
	if err := d.QueryRow(`SELECT count(*) FROM verdict_events WHERE processed_at IS NULL`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	ev, jobs, err := d.FanOutVerdictEvents(ctx, 100)
	if err != nil {
		t.Fatalf("扇出返回错误: %v", err)
	}
	var after int
	if err := d.QueryRow(`SELECT count(*) FROM verdict_events WHERE processed_at IS NULL`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	t.Logf("before=%d processed=%d jobs=%d after=%d", before, ev, jobs, after)
	if after > 0 {
		t.Fatalf("扇出后仍有 %d 条未处理事件(处理了 %d 条)", after, ev)
	}
}
