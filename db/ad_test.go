package db

import (
	"encoding/json"
	"testing"
)

func TestADWeaponsAndEventsLifecycle(t *testing.T) {
	dsn, _, err := DSN()
	if err != nil {
		t.Skip("postgres unavailable")
	}
	d, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	task, err := d.CreateTaskWithOptions("stage5-ad-db", "defend and attack", TaskCreateOptions{Mode: "ctf", ChallengeType: "web"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)

	w, err := d.CreateADWeapon(t.Context(), ADWeapon{
		TaskID:        task.ID,
		TargetService: "pwn1",
		ScriptPath:    "/work/exp_pwn1.py",
		Targets:       []string{"10.0.1.2:9999", "10.0.2.2:9999"},
		IntervalSec:   30,
	})
	if err != nil {
		t.Fatal(err)
	}
	if w.Status != ADWeaponActive || len(w.Targets) != 2 || !containsStr(w.CheckCmd, "/work/exp_pwn1.py") {
		t.Fatalf("unexpected weapon: %+v", w)
	}

	// Hit once
	w, err = d.RecordADWeaponRun(t.Context(), task.ID, w.ID, 2, 0, "flag{round1}", "")
	if err != nil || w.SuccessCount != 2 || w.ConsecutiveFails != 0 || w.LastFlag != "flag{round1}" {
		t.Fatalf("unexpected hit stats: w=%+v err=%v", w, err)
	}

	// 3 consecutive fails auto-blocks weapon (Stop-Loss)
	for i := 0; i < 3; i++ {
		w, err = d.RecordADWeaponRun(t.Context(), task.ID, w.ID, 0, 2, "", "patched")
		if err != nil {
			t.Fatal(err)
		}
	}
	if w.Status != ADWeaponBlocked || w.ConsecutiveFails != 3 {
		t.Fatalf("expected weapon auto-blocked after 3 consecutive fails, got status=%s consec=%d", w.Status, w.ConsecutiveFails)
	}

	// Reactivate resets consecutive_fails
	w, err = d.UpdateADWeapon(t.Context(), task.ID, w.ID, ADWeaponActive, nil, 45)
	if err != nil || w.Status != ADWeaponActive || w.ConsecutiveFails != 0 || w.IntervalSec != 45 {
		t.Fatalf("reactivate failed: w=%+v err=%v", w, err)
	}

	ev, err := d.AddADEvent(t.Context(), ADEvent{
		TaskID:   task.ID,
		WeaponID: &w.ID,
		Role:     "repeater",
		Kind:     "round_hit",
		Target:   "10.0.1.2:9999",
		Summary:  "captured flag{round1}",
		Detail:   json.RawMessage(`{"flag":"flag{round1}"}`),
	})
	if err != nil || ev.ID <= 0 {
		t.Fatalf("AddADEvent failed: ev=%+v err=%v", ev, err)
	}
	evs, err := d.ListADEvents(t.Context(), task.ID, 10)
	if err != nil || len(evs) != 1 || evs[0].Role != "repeater" {
		t.Fatalf("ListADEvents failed: %+v err=%v", evs, err)
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (sub == "" || indexStr(s, sub) >= 0)
}

func indexStr(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
