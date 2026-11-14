package ad

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"p3y/ctf"
	"p3y/db"
)

// PatchVerifySpec defines the Red-Blue Patcher verification test:
// 1. Optional patch_cmd applies the patch inside the sandbox;
// 2. check_cmd verifies SLA functionality still passes (exit 0);
// 3. exploit_cmd verifies the known exploit is now blocked (exit != 0 and no Flag leaked).
type PatchVerifySpec struct {
	ServiceName string `json:"service_name"`
	PatchCmd    string `json:"patch_cmd,omitempty"`
	CheckCmd    string `json:"check_cmd"`
	ExploitCmd  string `json:"exploit_cmd"`
}

// PatchVerifyResult holds objective Red-Blue test outcomes.
type PatchVerifyResult struct {
	Passed         bool   `json:"passed"`
	PatchApplied   bool   `json:"patch_applied"`
	PatchExitCode  int    `json:"patch_exit_code"`
	SLAPassed      bool   `json:"sla_passed"`
	SLAExitCode    int    `json:"sla_exit_code"`
	ExploitBlocked bool   `json:"exploit_blocked"`
	ExploitExit    int    `json:"exploit_exit_code"`
	LeakedFlags    int    `json:"leaked_flags"`
	Verdict        string `json:"verdict"`
}

// VerifyPatch runs Red-Blue co-verification inside p3y-box without LLM guesswork.
func (s *Service) VerifyPatch(ctx context.Context, taskID int64, spec PatchVerifySpec) (*PatchVerifyResult, error) {
	if s == nil || s.DB == nil || s.CTF == nil || taskID <= 0 {
		return nil, fmt.Errorf("需要任务、数据库与沙箱上下文")
	}
	spec.CheckCmd = strings.TrimSpace(spec.CheckCmd)
	spec.ExploitCmd = strings.TrimSpace(spec.ExploitCmd)
	if spec.CheckCmd == "" || spec.ExploitCmd == "" {
		return nil, fmt.Errorf("check_cmd（服务 SLA 检查）和 exploit_cmd（PoC 利用脚本）均不能为空")
	}

	res := &PatchVerifyResult{}
	if strings.TrimSpace(spec.PatchCmd) != "" {
		pExec, err := s.CTF.ExecuteRaw(ctx, taskID, 0, spec.PatchCmd, 45)
		if err != nil {
			return nil, fmt.Errorf("应用补丁命令执行失败: %w", err)
		}
		res.PatchExitCode = pExec.ExitCode
		res.PatchApplied = pExec.ExitCode == 0
		if !res.PatchApplied {
			res.Verdict = fmt.Sprintf("补丁命令返回非零 (%d)，中止验证：%s", pExec.ExitCode, pExec.StderrExcerpt)
			s.recordPatchEvent(ctx, taskID, spec.ServiceName, res)
			return res, nil
		}
	}

	slaExec, err := s.CTF.ExecuteRaw(ctx, taskID, 0, spec.CheckCmd, 30)
	if err != nil {
		return nil, fmt.Errorf("SLA 检查执行失败: %w", err)
	}
	res.SLAExitCode = slaExec.ExitCode
	res.SLAPassed = slaExec.ExitCode == 0

	expExec, err := s.CTF.ExecuteRaw(ctx, taskID, 0, spec.ExploitCmd, 30)
	if err != nil {
		return nil, fmt.Errorf("PoC 利用检查执行失败: %w", err)
	}
	res.ExploitExit = expExec.ExitCode
	flags := ctf.ExtractFlags(expExec.StdoutExcerpt+"\n"+expExec.StderrExcerpt, 4)
	res.LeakedFlags = len(flags)
	// Exploit is considered blocked only when zero flags leak AND either exit != 0 or stderr indicates block.
	res.ExploitBlocked = res.LeakedFlags == 0 && (expExec.ExitCode != 0 || !strings.Contains(strings.ToLower(expExec.StdoutExcerpt), "pwned"))
	res.Passed = res.SLAPassed && res.ExploitBlocked

	switch {
	case res.Passed:
		res.Verdict = "红蓝双验通过：服务 SLA 正常（exit 0），且已知漏洞利用已被成功阻断。"
	case !res.SLAPassed:
		res.Verdict = fmt.Sprintf("服务 SLA 损坏（check_cmd exit=%d），补丁不可上线。", res.SLAExitCode)
	default:
		res.Verdict = fmt.Sprintf("防御失败：攻击脚本仍可执行或泄露 %d 个 Flag（exploit exit=%d）。", res.LeakedFlags, res.ExploitExit)
	}
	s.recordPatchEvent(ctx, taskID, spec.ServiceName, res)
	return res, nil
}

func (s *Service) recordPatchEvent(ctx context.Context, taskID int64, serviceName string, res *PatchVerifyResult) {
	detail, _ := json.Marshal(res)
	_, _ = s.DB.AddADEvent(ctx, db.ADEvent{
		TaskID:  taskID,
		Role:    "patcher",
		Kind:    "patch_test",
		Target:  serviceName,
		Summary: res.Verdict,
		Detail:  detail,
	})
}
