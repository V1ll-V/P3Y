"use client";

import * as React from "react";

import {
  CrosshairIcon,
  PauseIcon,
  PlayIcon,
  PlusIcon,
  RadarIcon,
  RefreshCwIcon,
  ShieldCheckIcon,
  SwordsIcon,
  Trash2Icon,
  ZapIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { ADOverview, ADWeapon, PatchVerifyResult } from "@/lib/types";

const PRIO_BADGE: Record<string, string> = {
  high: "border-rose-500/40 bg-rose-500/10 text-rose-500",
  medium: "border-amber-500/40 bg-amber-500/10 text-amber-500",
  low: "border-sky-500/40 bg-sky-500/10 text-sky-500",
};

export function ADConsolePanel({ taskId }: { taskId: string }) {
  const [data, setData] = React.useState<ADOverview | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [runningRepeater, setRunningRepeater] = React.useState(false);
  const [scanningCatcher, setScanningCatcher] = React.useState(false);
  const [verifyingPatch, setVerifyingPatch] = React.useState(false);
  const [patchResult, setPatchResult] = React.useState<PatchVerifyResult | null>(null);

  // Add weapon form
  const [showAddWeapon, setShowAddWeapon] = React.useState(false);
  const [targetService, setTargetService] = React.useState("");
  const [scriptPath, setScriptPath] = React.useState("/work/exp.py");
  const [checkCmd, setCheckCmd] = React.useState("");
  const [targetsText, setTargetsText] = React.useState("");
  const [submitUrl, setSubmitUrl] = React.useState("");
  const [intervalSec, setIntervalSec] = React.useState("30");

  // Patcher form
  const [patchService, setPatchService] = React.useState("web");
  const [patchCmd, setPatchCmd] = React.useState("");
  const [slaCmd, setSlaCmd] = React.useState("python3 /work/sla_check.py");
  const [exploitCmd, setExploitCmd] = React.useState("python3 /work/exp.py");

  // Catcher optional sample
  const [catcherSample, setCatcherSample] = React.useState("");

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.taskADOverview(taskId);
      setData(res);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "加载 AD 攻防控制台失败");
    } finally {
      setLoading(false);
    }
  }, [taskId]);

  React.useEffect(() => {
    void load();
  }, [load]);

  const createWeapon = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetService.trim() || !scriptPath.trim()) {
      toast.error("靶标服务名和脚本路径不能为空");
      return;
    }
    const targets = targetsText
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    try {
      await api.taskADWeaponCreate(taskId, {
        target_service: targetService.trim(),
        script_path: scriptPath.trim(),
        check_cmd: checkCmd.trim() || undefined,
        targets,
        submit_url: submitUrl.trim() || undefined,
        interval_sec: Number(intervalSec) || 30,
      });
      toast.success("已注册 Repeater 武器");
      setShowAddWeapon(false);
      setTargetService("");
      setTargetsText("");
      setCheckCmd("");
      await load();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "创建武器失败");
    }
  };

  const toggleWeaponStatus = async (w: ADWeapon) => {
    const nextStatus = w.status === "active" ? "paused" : "active";
    try {
      await api.taskADWeaponUpdate(taskId, w.id, { status: nextStatus });
      toast.success(nextStatus === "active" ? "已恢复自动打靶" : "已暂停武器");
      await load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "更新状态失败");
    }
  };

  const deleteWeapon = async (id: number) => {
    try {
      await api.taskADWeaponDelete(taskId, id);
      toast.success("已移除武器");
      await load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "删除失败");
    }
  };

  const runRepeater = async (weaponId?: number) => {
    setRunningRepeater(true);
    try {
      const res = await api.taskADRepeaterRun(taskId, { weapon_id: weaponId, force: true });
      toast.success(
        `Repeater 完成：运行 ${res.weapons_run} 武器，命中 ${res.targets_hit}，未命中 ${res.targets_miss}，捕获 ${res.flags_found.length} Flag`,
      );
      await load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "打靶执行失败");
    } finally {
      setRunningRepeater(false);
    }
  };

  const scanCatcher = async () => {
    setScanningCatcher(true);
    try {
      const samples = catcherSample.trim()
        ? [{ target: "manual", request: catcherSample.trim(), source: "ui" }]
        : undefined;
      const res = await api.taskADCatcherScan(taskId, { samples, record_board: true });
      toast.success(`Catcher 扫描 ${res.scanned} 条样本，捕获 ${res.findings.length} 条攻击载荷特征`);
      await load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Catcher 扫描失败");
    } finally {
      setScanningCatcher(false);
    }
  };

  const verifyPatch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!slaCmd.trim() || !exploitCmd.trim()) {
      toast.error("SLA 检查命令和 PoC 利用命令均不能为空");
      return;
    }
    setVerifyingPatch(true);
    try {
      const res = await api.taskADPatcherVerify(taskId, {
        service_name: patchService.trim() || "service",
        patch_cmd: patchCmd.trim() || undefined,
        check_cmd: slaCmd.trim(),
        exploit_cmd: exploitCmd.trim(),
      });
      setPatchResult(res);
      toast[res.passed ? "success" : "error"](res.verdict);
      await load();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "红蓝验证失败");
    } finally {
      setVerifyingPatch(false);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      {/* 领队建议 + 总控制栏 */}
      <Card>
        <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2">
          <div>
            <CardTitle className="flex items-center gap-2 text-base">
              <SwordsIcon className="size-4 text-primary" /> AD 攻防控制台（Lead · Repeater · Catcher · Patcher）
            </CardTitle>
            <CardDescription>
              0-LLM 周期打靶、敌方攻击流量反向提炼、红蓝双验自动补丁与 Lead 止损建议。
            </CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <Button size="sm" variant="outline" onClick={() => void runRepeater()} disabled={runningRepeater}>
              <ZapIcon className={runningRepeater ? "animate-pulse" : ""} />
              全量打靶一次
            </Button>
            <Button size="sm" variant="outline" onClick={() => void load()} disabled={loading}>
              <RefreshCwIcon className={loading ? "animate-spin" : ""} />
              刷新
            </Button>
          </div>
        </CardHeader>
        {data && data.recommendations.length > 0 && (
          <CardContent className="flex flex-col gap-2 pt-0">
            <div className="text-xs font-medium text-muted-foreground">Lead 实时战术建议</div>
            <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
              {data.recommendations.map((rec, idx) => (
                <div key={`${rec.kind}-${idx}`} className="rounded-md border p-2.5 text-xs">
                  <div className="flex items-center gap-1.5">
                    <Badge variant="outline" className={PRIO_BADGE[rec.priority] ?? ""}>
                      {rec.priority.toUpperCase()}
                    </Badge>
                    <Badge variant="secondary" className="font-mono">
                      {rec.kind}
                    </Badge>
                    {rec.target && <span className="font-mono text-muted-foreground">{rec.target}</span>}
                  </div>
                  <div className="mt-1 font-medium text-sm">{rec.title}</div>
                  <div className="mt-0.5 text-muted-foreground">{rec.detail}</div>
                </div>
              ))}
            </div>
          </CardContent>
        )}
      </Card>

      {/* Repeater 武器库 */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2">
          <div>
            <CardTitle className="flex items-center gap-2 text-base">
              <CrosshairIcon className="size-4 text-primary" /> Repeater 批量打靶武器 ({data?.weapons.length ?? 0})
            </CardTitle>
          </div>
          <Button size="sm" variant="outline" onClick={() => setShowAddWeapon((v) => !v)}>
            <PlusIcon />
            {showAddWeapon ? "收起" : "注册武器"}
          </Button>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {showAddWeapon && (
            <form onSubmit={createWeapon} className="flex flex-col gap-2.5 rounded-md border bg-muted/30 p-3">
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
                <Input
                  placeholder="服务名（如 web1 / pwn_note）"
                  value={targetService}
                  onChange={(e) => setTargetService(e.target.value)}
                />
                <Input
                  placeholder="脚本路径（如 /work/exp.py）"
                  value={scriptPath}
                  onChange={(e) => setScriptPath(e.target.value)}
                />
                <Input
                  placeholder="间隔秒数（默认 30）"
                  value={intervalSec}
                  onChange={(e) => setIntervalSec(e.target.value)}
                />
              </div>
              <Input
                placeholder="目标列表（逗号或空格分隔，如 10.0.1.2:80, 10.0.1.3:80）"
                value={targetsText}
                onChange={(e) => setTargetsText(e.target.value)}
              />
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                <Input
                  placeholder="自定义执行命令（可用 {{target}} 占位，可选）"
                  value={checkCmd}
                  onChange={(e) => setCheckCmd(e.target.value)}
                />
                <Input
                  placeholder="裁判 Flag 提交 URL（可选）"
                  value={submitUrl}
                  onChange={(e) => setSubmitUrl(e.target.value)}
                />
              </div>
              <div className="flex justify-end">
                <Button type="submit" size="sm">保存武器</Button>
              </div>
            </form>
          )}

          {!data || data.weapons.length === 0 ? (
            <div className="text-sm text-muted-foreground">暂无注册武器。点击右上角「注册武器」开始自动化每轮打靶。</div>
          ) : (
            <div className="flex flex-col gap-2">
              {data.weapons.map((w) => (
                <div key={w.id} className="flex flex-wrap items-center justify-between gap-2 rounded-md border p-2.5 text-xs">
                  <div className="flex min-w-0 flex-col gap-1">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <Badge variant={w.status === "active" ? "default" : w.status === "blocked" ? "destructive" : "secondary"}>
                        {w.status}
                      </Badge>
                      <span className="font-semibold text-sm">{w.target_service}</span>
                      <span className="font-mono text-muted-foreground">{w.script_path}</span>
                      <span className="text-muted-foreground">每 {w.interval_sec}s</span>
                    </div>
                    <div className="flex flex-wrap items-center gap-3 text-muted-foreground">
                      <span>靶标: {w.targets.length > 0 ? w.targets.join(", ") : "默认"}</span>
                      <span className="text-emerald-600 dark:text-emerald-400">成功 {w.success_count}</span>
                      <span className="text-rose-600 dark:text-rose-400">失败 {w.fail_count}</span>
                      {w.last_flag && <span className="font-mono text-primary">最新: {w.last_flag}</span>}
                      {w.last_error && <span className="text-rose-500">错误: {w.last_error}</span>}
                    </div>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => void runRepeater(w.id)} disabled={runningRepeater}>
                      <ZapIcon /> 打靶
                    </Button>
                    <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => void toggleWeaponStatus(w)}>
                      {w.status === "active" ? <PauseIcon /> : <PlayIcon />}
                      {w.status === "active" ? "暂停" : "启用"}
                    </Button>
                    <Button size="icon-xs" variant="ghost" className="text-destructive" onClick={() => void deleteWeapon(w.id)}>
                      <Trash2Icon className="size-3.5" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Catcher + Patcher 双栏 */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <RadarIcon className="size-4 text-primary" /> Catcher 流量捕手
            </CardTitle>
            <CardDescription>扫描 MITM 流量或手工贴入可疑请求，提取高频攻击特征反哺己方攻击与加固。</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-2.5">
            <Textarea
              rows={3}
              className="font-mono text-xs"
              placeholder="可选：粘贴一段原始 HTTP / Payload 样本进行即时检测（留空则直接扫描任务已有 Traffic 流量库）"
              value={catcherSample}
              onChange={(e) => setCatcherSample(e.target.value)}
            />
            <div className="flex justify-end">
              <Button size="sm" variant="outline" onClick={() => void scanCatcher()} disabled={scanningCatcher}>
                <RadarIcon className={scanningCatcher ? "animate-spin" : ""} />
                执行捕获扫描
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <ShieldCheckIcon className="size-4 text-primary" /> Patcher 红蓝对撞沙箱
            </CardTitle>
            <CardDescription>在 p3y-box 内依次验证：应用补丁 → SLA 连通性检查 → 已知 PoC 阻断测试。</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={verifyPatch} className="flex flex-col gap-2">
              <div className="grid grid-cols-2 gap-2">
                <Input placeholder="服务名" value={patchService} onChange={(e) => setPatchService(e.target.value)} />
                <Input placeholder="补丁命令（可选）" value={patchCmd} onChange={(e) => setPatchCmd(e.target.value)} />
              </div>
              <Input placeholder="SLA 检查命令（需 exit 0）" value={slaCmd} onChange={(e) => setSlaCmd(e.target.value)} />
              <Input placeholder="PoC 利用命令（需被阻断且不泄 Flag）" value={exploitCmd} onChange={(e) => setExploitCmd(e.target.value)} />
              <div className="flex items-center justify-between gap-2 pt-1">
                {patchResult ? (
                  <span className={`text-xs font-medium ${patchResult.passed ? "text-emerald-500" : "text-rose-500"}`}>
                    {patchResult.verdict}
                  </span>
                ) : (
                  <span />
                )}
                <Button type="submit" size="sm" disabled={verifyingPatch}>
                  {verifyingPatch ? "验证中..." : "开始红蓝双验"}
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      </div>

      {/* ADEvent 实时战况流 */}
      {data && data.events.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">攻防战况事件流 ({data.events.length})</CardTitle>
          </CardHeader>
          <CardContent className="flex max-h-72 flex-col gap-1.5 overflow-y-auto text-xs">
            {data.events.map((ev) => (
              <div key={ev.id} className="flex items-start justify-between gap-2 rounded border px-2.5 py-1.5">
                <div className="flex flex-col gap-0.5">
                  <div className="flex items-center gap-1.5">
                    <Badge variant="outline" className="font-mono uppercase">
                      {ev.role}
                    </Badge>
                    <span className="font-mono text-muted-foreground">{ev.kind}</span>
                    {ev.target && <span className="font-mono text-primary">{ev.target}</span>}
                  </div>
                  <div>{ev.summary}</div>
                </div>
                <span className="shrink-0 text-muted-foreground">{new Date(ev.created_at).toLocaleTimeString()}</span>
              </div>
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
