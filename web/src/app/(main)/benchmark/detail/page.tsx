"use client";

import * as React from "react";
import { Suspense } from "react";

import Link from "next/link";
import { useSearchParams } from "next/navigation";

import {
  ArrowLeftIcon,
  CheckCircle2Icon,
  ClockIcon,
  DownloadIcon,
  ExternalLinkIcon,
  FlagIcon,
  LightbulbIcon,
  Loader2Icon,
  PlayIcon,
  RefreshCwIcon,
  ServerIcon,
  SlidersHorizontalIcon,
  SquareIcon,
  TrophyIcon,
  XCircleIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import { fmtTokens, formatTokenBreakdown } from "@/lib/format-tokens";
import type { BenchmarkChallenge, BenchmarkDetailResponse } from "@/lib/types";

type ChallengeFilter = "all" | "completed" | "active" | "pending" | "error";

function challengeHasContainer(c: BenchmarkChallenge, provider: string): boolean {
  if (typeof c.meta?.has_container === "boolean") {
    return c.meta.has_container;
  }
  return (
    provider === "tsecbench" ||
    c.container_addr.length > 0 ||
    c.container_status === "available" ||
    c.container_status === "pending"
  );
}

function renderContainerLabel(c: BenchmarkChallenge, provider: string): { label: string; tone: "running" | "pending" | "none" | "stopped" } {
  if (c.container_status === "available") {
    return { label: "运行中", tone: "running" };
  }
  if (c.container_status === "pending") {
    return { label: "启动中", tone: "pending" };
  }
  if (!challengeHasContainer(c, provider)) {
    return { label: "无需容器", tone: "none" };
  }
  if (c.is_completed) {
    return { label: "已回收", tone: "none" };
  }
  return { label: "未启动", tone: "stopped" };
}

function BenchmarkDetailInner() {
  const searchParams = useSearchParams();
  const id = searchParams.get("id");
  const [data, setData] = React.useState<BenchmarkDetailResponse | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [busy, setBusy] = React.useState(false);
  const [filter, setFilter] = React.useState<"all" | "completed" | "active" | "pending" | "error">("all");
  const [settingsOpen, setSettingsOpen] = React.useState(false);
  const [editConcurrent, setEditConcurrent] = React.useState(3);
  const [editTimeout, setEditTimeout] = React.useState(5400);
  const [savingSettings, setSavingSettings] = React.useState(false);
  const [nowMs, setNowMs] = React.useState(() => Date.now());

  React.useEffect(() => {
    const id = window.setInterval(() => setNowMs(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, []);

  const load = React.useCallback(async () => {
    if (!id) return;
    try {
      const res = await api.benchmarkGetSession(id);
      setData(res);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "读取测评详情失败");
    } finally {
      setLoading(false);
    }
  }, [id]);

  React.useEffect(() => {
    void load();
    const timer = window.setInterval(() => {
      if (!id) return;
      void api.benchmarkGetSession(id).then(setData).catch(() => undefined);
    }, 3500);
    return () => window.clearInterval(timer);
  }, [id, load]);

  if (!id) {
    return (
      <div className="p-6 text-sm text-muted-foreground">
        缺少测评 ID 参数。
        <Link href="/benchmark" className="ml-2 text-primary underline">
          返回测评列表
        </Link>
      </div>
    );
  }

  if (loading || !data) {
    return (
      <div className="flex items-center justify-center p-20 text-muted-foreground">
        <Loader2Icon className="mr-2 h-5 w-5 animate-spin" />
        加载测评实况...
      </div>
    );
  }

  const { session, challenges, submissions, events } = data;
  const activeEnvs = challenges.filter((c) => c.container_status === "available" || c.container_status === "pending");
  const isNoFlagChallenge = (c: BenchmarkChallenge) =>
    c.title.includes("[无flag]") || (c.description || "").includes("本题无flag");
  const isTerminalTaskStatus = (status?: string) =>
    status === "failed" || status === "stopped" || status === "cancelled" || status === "done" || status === "timeout";
  const isChallengeInterrupted = (c: BenchmarkChallenge) =>
    !c.is_completed &&
    !isNoFlagChallenge(c) &&
    !c.last_error &&
    Boolean(c.bound_task_id) &&
    c.container_status !== "available" &&
    c.container_status !== "pending" &&
    isTerminalTaskStatus(c.bound_task_status);
  const isChallengeActive = (c: BenchmarkChallenge) =>
    !c.is_completed &&
    (c.container_status === "available" ||
      c.container_status === "pending" ||
      (Boolean(c.bound_task_id) && !c.last_error && !isTerminalTaskStatus(c.bound_task_status)));
  const interruptedCount = challenges.filter((c) => isChallengeInterrupted(c)).length;
  const counts = {
    all: challenges.length,
    completed: challenges.filter((c) => c.is_completed).length,
    active: challenges.filter((c) => isChallengeActive(c)).length,
    error: challenges.filter((c) => !c.is_completed && Boolean(c.last_error)).length,
    pending: challenges.filter((c) => !c.is_completed && !c.last_error && !isChallengeActive(c)).length,
  };
  const filteredChallenges = challenges.filter((c) => {
    if (filter === "completed") return c.is_completed;
    if (filter === "active") return isChallengeActive(c);
    if (filter === "error") return !c.is_completed && Boolean(c.last_error);
    if (filter === "pending") return !c.is_completed && !c.last_error && !isChallengeActive(c);
    return true;
  });

  return (
    <div className="mx-auto flex w-full max-w-7xl flex-col gap-6 p-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <Button asChild variant="ghost" size="icon-sm">
            <Link href="/benchmark">
              <ArrowLeftIcon className="h-4 w-4" />
            </Link>
          </Button>
          <div>
            <div className="flex items-center gap-2">
              <TrophyIcon className="h-5 w-5 text-amber-500" />
              <h1 className="text-xl font-semibold">{session.name}</h1>
              <Badge variant={session.status === "running" ? "default" : "secondary"}>{session.status}</Badge>
              <Badge variant="outline">{session.provider}</Badge>
            </div>
            <p className="mt-0.5 text-xs text-muted-foreground">
              {session.base_url} · 最大并发槽位 {session.max_concurrent} · 单题预算 {session.per_challenge_timeout}s ({Math.round(session.per_challenge_timeout / 60)} 分钟)
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Dialog
            open={settingsOpen}
            onOpenChange={(open) => {
              if (open) {
                setEditConcurrent(session.max_concurrent);
                setEditTimeout(session.per_challenge_timeout);
              }
              setSettingsOpen(open);
            }}
          >
            <DialogTrigger asChild>
              <Button variant="outline" size="sm" disabled={busy}>
                <SlidersHorizontalIcon className="mr-1.5 h-3.5 w-3.5" />
                调整预算/并发
              </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-md">
              <DialogHeader>
                <DialogTitle>调整测评参数</DialogTitle>
                <DialogDescription>
                  修改最大并发槽位或单题预算超时时间。待调度或冷却重排的新任务会立即采用新预算。
                </DialogDescription>
              </DialogHeader>
              <div className="grid gap-4 py-2">
                <div className="space-y-2">
                  <Label className="text-xs font-medium">最大并发题目/容器数</Label>
                  <Input
                    type="number"
                    min={1}
                    max={16}
                    value={editConcurrent}
                    onChange={(e) => setEditConcurrent(Math.min(16, Math.max(1, Number(e.target.value) || 1)))}
                  />
                </div>
                <div className="space-y-2">
                  <Label className="text-xs font-medium">
                    单题预算超时 (秒 · 约 {Math.round(editTimeout / 60)} 分钟)
                  </Label>
                  <Input
                    type="number"
                    min={60}
                    max={14400}
                    value={editTimeout}
                    onChange={(e) => setEditTimeout(Math.min(14400, Math.max(60, Number(e.target.value) || 5400)))}
                  />
                  <div className="flex flex-wrap gap-1">
                    {[
                      { label: "30分", sec: 1800 },
                      { label: "60分", sec: 3600 },
                      { label: "90分", sec: 5400 },
                      { label: "120分", sec: 7200 },
                      { label: "180分", sec: 10800 },
                    ].map((preset) => (
                      <Button
                        key={preset.sec}
                        type="button"
                        variant={editTimeout === preset.sec ? "default" : "outline"}
                        size="sm"
                        className="h-6 px-2 text-[11px]"
                        onClick={() => setEditTimeout(preset.sec)}
                      >
                        {preset.label}
                      </Button>
                    ))}
                  </div>
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setSettingsOpen(false)} disabled={savingSettings}>
                  取消
                </Button>
                <Button
                  disabled={savingSettings}
                  onClick={async () => {
                    setSavingSettings(true);
                    try {
                      await api.benchmarkUpdateSession(session.id, {
                        max_concurrent: editConcurrent,
                        per_challenge_timeout: editTimeout,
                      });
                      await load();
                      toast.success(`已更新并发=${editConcurrent}，单题预算=${editTimeout}s (${Math.round(editTimeout / 60)}分钟)`);
                      setSettingsOpen(false);
                    } catch (err) {
                      toast.error(err instanceof Error ? err.message : "更新失败");
                    } finally {
                      setSavingSettings(false);
                    }
                  }}
                >
                  {savingSettings ? "保存中..." : "保存设置"}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
          <Button
            variant="outline"
            size="sm"
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              try {
                await api.benchmarkSyncSession(session.id);
                await load();
                toast.success("题库与进度已同步");
              } finally {
                setBusy(false);
              }
            }}
          >
            <RefreshCwIcon className="mr-1.5 h-3.5 w-3.5" />
            同步题库
          </Button>
          {(interruptedCount > 0 || counts.error > 0) && (
            <Button
              variant="outline"
              size="sm"
              disabled={busy}
              onClick={async () => {
                setBusy(true);
                try {
                  const res = await api.benchmarkRetryFailed(session.id);
                  await load();
                  toast.success(`已将 ${res.reset} 道中断/失败题目重置回优先队列`);
                } finally {
                  setBusy(false);
                }
              }}
            >
              <PlayIcon className="mr-1.5 h-3.5 w-3.5" />
              重排中断/失败题 ({interruptedCount + counts.error})
            </Button>
          )}
          <Button variant="outline" size="sm" onClick={() => void api.benchmarkExportSession(session.id)}>
            <DownloadIcon className="mr-1.5 h-3.5 w-3.5" />
            导出成绩单
          </Button>
          {session.status === "running" ? (
            <Button
              variant="destructive"
              size="sm"
              disabled={busy}
              onClick={async () => {
                setBusy(true);
                try {
                  await api.benchmarkStopSession(session.id);
                  await load();
                } finally {
                  setBusy(false);
                }
              }}
            >
              <SquareIcon className="mr-1.5 h-3.5 w-3.5" />
              停止测评
            </Button>
          ) : (
            <Button
              size="sm"
              disabled={busy}
              onClick={async () => {
                setBusy(true);
                try {
                  await api.benchmarkStartSession(session.id);
                  await load();
                } finally {
                  setBusy(false);
                }
              }}
            >
              <PlayIcon className="mr-1.5 h-3.5 w-3.5" />
              启动 / 恢复测评
            </Button>
          )}
        </div>
      </div>

      {/* KPI Strip */}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>累计得分</CardDescription>
            <CardTitle className="font-mono text-2xl">
              {session.total_score} <span className="text-sm font-normal text-muted-foreground">/ {session.max_possible_score}</span>
            </CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>完成题目</CardDescription>
            <CardTitle className="font-mono text-2xl">
              {session.completed_count} <span className="text-sm font-normal text-muted-foreground">/ {session.total_count}</span>
            </CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>活跃靶机槽位</CardDescription>
            <CardTitle className="font-mono text-2xl">
              {activeEnvs.length} <span className="text-sm font-normal text-muted-foreground">/ {session.max_concurrent}</span>
            </CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>平台验证提交记录</CardDescription>
            <CardTitle className="font-mono text-2xl">
              {submissions.filter((x) => x.correct).length}{" "}
              <span className="text-sm font-normal text-muted-foreground">/ {submissions.length} 次通过</span>
            </CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>总消耗 Token</CardDescription>
            <CardTitle className="font-mono text-2xl">
              {fmtTokens(session.tokens?.total_tokens ?? 0)}
            </CardTitle>
            <div className="pt-0.5 font-mono text-[11px] text-muted-foreground">
              {formatTokenBreakdown(session.tokens)}
            </div>
          </CardHeader>
        </Card>
      </div>

      {/* Active Slots */}
      {activeEnvs.length > 0 && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-sm">
              <ServerIcon className="h-4 w-4 text-emerald-500" />
              当前活跃靶机槽位
            </CardTitle>
          </CardHeader>
          <CardContent className="grid gap-3 sm:grid-cols-3">
            {activeEnvs.map((c) => (
              <div key={c.id} className="rounded-md border bg-muted/20 p-3 text-xs">
                <div className="flex items-center justify-between gap-2 font-medium">
                  <span className="truncate">{c.title || c.unique_code}</span>
                  <Badge variant={c.container_status === "available" ? "default" : "secondary"} className="text-[10px]">
                    {c.container_status === "available" ? "运行中" : "启动中"}
                  </Badge>
                </div>
                <div className="mt-1 font-mono text-[11px] text-muted-foreground">
                  {c.container_addr.length > 0 ? c.container_addr.join(", ") : "分配端口中..."}
                </div>
                {c.bound_task_id && (
                  <div className="mt-2">
                    <Link
                      href={`/function/tasks/detail?id=${c.bound_task_id}`}
                      className="inline-flex items-center gap-1 text-[11px] text-primary hover:underline"
                    >
                      查看隔离求解轨迹 (#{c.bound_task_id})
                      <ExternalLinkIcon className="h-3 w-3" />
                    </Link>
                  </div>
                )}
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Challenge Matrix */}
      <Card>
        <CardHeader className="flex flex-col gap-3 pb-3 sm:flex-row sm:items-center sm:justify-between">
          <CardTitle className="text-sm">
            题库实时矩阵 ({filteredChallenges.length} / {challenges.length})
          </CardTitle>
          <div className="flex flex-wrap gap-1.5 text-xs">
            {(
              [
                ["all", `全部 (${counts.all})`],
                ["completed", `已完成 (${counts.completed})`],
                ["active", `进行中 (${counts.active})`],
                ["pending", `待调度 (${counts.pending})`],
                ["error", `异常 (${counts.error})`],
              ] as Array<[ChallengeFilter, string]>
            ).map(([key, label]) => (
              <Button
                key={key}
                type="button"
                variant={filter === key ? "default" : "outline"}
                size="sm"
                className="h-7 px-2.5 text-[11px]"
                onClick={() => setFilter(key)}
              >
                {label}
              </Button>
            ))}
          </div>
        </CardHeader>
        <CardContent className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b text-muted-foreground">
                <th className="py-2 pr-3">代号 / 题目</th>
                <th className="py-2 pr-3">状态</th>
                <th className="py-2 pr-3">分类 / 难度</th>
                <th className="py-2 pr-3">类型</th>
                <th className="py-2 pr-3">得分</th>
                <th className="py-2 pr-3">Flag 进度</th>
                <th className="py-2 pr-3">容器状态</th>
                <th className="py-2 pr-3">尝试</th>
                <th className="py-2 pr-3">Token 消耗</th>
                <th className="py-2">执行跟踪</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {filteredChallenges.map((c) => {
                const envInfo = renderContainerLabel(c, session.provider);
                const active = isChallengeActive(c);
                return (
                  <tr key={c.id} className={c.is_completed ? "bg-emerald-500/5" : ""}>
                    <td className="py-2.5 pr-3">
                      <div className="flex items-center gap-1.5 font-medium">
                        {c.is_completed ? (
                          <CheckCircle2Icon className="h-3.5 w-3.5 shrink-0 text-emerald-500" />
                        ) : c.last_error ? (
                          <XCircleIcon className="h-3.5 w-3.5 shrink-0 text-destructive" />
                        ) : active ? (
                          <Loader2Icon className="h-3.5 w-3.5 shrink-0 animate-spin text-primary" />
                        ) : (
                          <ClockIcon className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                        )}
                        <span>{c.title}</span>
                      </div>
                      <div className="pl-5 font-mono text-[11px] text-muted-foreground">{c.unique_code}</div>
                      {!c.is_completed && c.last_error && (
                        <div
                          className="mt-0.5 max-w-[320px] truncate pl-5 text-[11px] text-destructive"
                          title={c.last_error}
                        >
                          {c.last_error}
                        </div>
                      )}
                    </td>
                    <td className="py-2.5 pr-3">
                      {(() => {
                        const retrySec = c.next_retry_at
                          ? Math.max(0, Math.ceil((Date.parse(c.next_retry_at) - nowMs) / 1000))
                          : 0;
                        if (c.is_completed) {
                          return (
                            <Badge
                              variant="default"
                              className="border-emerald-500/30 bg-emerald-500/15 text-[10px] text-emerald-600 hover:bg-emerald-500/15 dark:text-emerald-400"
                            >
                              已完成
                            </Badge>
                          );
                        }
                        if (c.next_retry_at) {
                          return (
                            <Badge
                              variant="secondary"
                              className="border-sky-500/30 bg-sky-500/15 text-[10px] text-sky-700 dark:text-sky-300"
                            >
                              {retrySec > 0
                                ? `冷却重排 (${retrySec}s · ${c.auto_retry_count ?? 1}/3)`
                                : "即将重排"}
                            </Badge>
                          );
                        }
                        if (c.last_error) {
                          return (
                            <Badge variant="destructive" className="text-[10px]">
                              异常
                            </Badge>
                          );
                        }
                        if (active) {
                          return (
                            <Badge variant="default" className="text-[10px]">
                              求解中
                            </Badge>
                          );
                        }
                        if (isChallengeInterrupted(c)) {
                          return (
                            <Badge
                              variant="secondary"
                              className="border-amber-500/30 bg-amber-500/15 text-[10px] text-amber-700 dark:text-amber-300"
                            >
                              已中断 ({c.bound_task_status})
                            </Badge>
                          );
                        }
                        if (isNoFlagChallenge(c)) {
                          return (
                            <Badge variant="secondary" className="text-[10px] text-muted-foreground">
                              无Flag跳过
                            </Badge>
                          );
                        }
                        return (
                          <Badge variant="outline" className="text-[10px] text-muted-foreground">
                            待调度
                          </Badge>
                        );
                      })()}
                    </td>
                    <td className="py-2.5 pr-3">
                      <Badge variant="outline" className="mr-1 text-[10px]">
                        {c.category || "auto"}
                      </Badge>
                      <span className="text-muted-foreground">{c.difficulty || `L${c.level}`}</span>
                    </td>
                    <td className="py-2.5 pr-3">
                      <Badge variant="secondary" className="text-[10px]">
                        {c.submission_type}
                      </Badge>
                    </td>
                    <td className="py-2.5 pr-3 font-mono">
                      {c.cumulative_score}/{c.total_score}
                    </td>
                    <td className="py-2.5 pr-3 font-mono">
                      {c.correct_flag_count}/{c.flag_count}
                    </td>
                    <td className="py-2.5 pr-3">
                      <Badge
                        variant={
                          envInfo.tone === "running"
                            ? "default"
                            : envInfo.tone === "pending"
                              ? "secondary"
                              : "outline"
                        }
                        className={
                          envInfo.tone === "none" ? "text-[10px] text-muted-foreground" : "text-[10px]"
                        }
                      >
                        {envInfo.label}
                      </Badge>
                      {c.container_status === "available" && c.container_addr.length > 0 && (
                        <div
                          className="mt-0.5 max-w-[220px] truncate font-mono text-[10px] text-emerald-600 dark:text-emerald-400"
                          title={c.container_addr.join(", ")}
                        >
                          {c.container_addr.join(", ")}
                        </div>
                      )}
                    </td>
                    <td className="py-2.5 pr-3 font-mono">{c.attempt_count}</td>
                    <td className="py-2.5 pr-3 font-mono" title={formatTokenBreakdown(c.tokens)}>
                      {(c.tokens?.total_tokens ?? 0) > 0 ? (
                        <div>
                          <div>{fmtTokens(c.tokens!.total_tokens)}</div>
                          <div className="text-[10px] text-muted-foreground">
                            入 {fmtTokens(c.tokens!.input_tokens)} · 出 {fmtTokens(c.tokens!.output_tokens)}
                          </div>
                        </div>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </td>
                    <td className="py-2.5">
                      <div className="flex items-center gap-2">
                        {c.bound_task_id ? (
                          <Link
                            href={`/function/tasks/detail?id=${c.bound_task_id}`}
                            className="inline-flex items-center gap-1 text-primary hover:underline"
                          >
                            任务 #{c.bound_task_id}
                            <ExternalLinkIcon className="h-3 w-3" />
                          </Link>
                        ) : (c.history_task_ids?.length ?? 0) > 0 ? (
                          <Link
                            href={`/function/tasks/detail?id=${c.history_task_ids![c.history_task_ids!.length - 1]}`}
                            className="inline-flex items-center gap-1 text-muted-foreground hover:text-primary hover:underline"
                          >
                            上次 #{c.history_task_ids![c.history_task_ids!.length - 1]}
                            <ExternalLinkIcon className="h-3 w-3" />
                          </Link>
                        ) : (
                          <span className="text-muted-foreground">{c.is_completed ? "—" : "待调度"}</span>
                        )}
                        {(c.history_task_ids?.length ?? 0) > 1 && (
                          <span
                            className="text-[10px] text-muted-foreground"
                            title={`已关联前序任务：${c.history_task_ids!.map((id) => `#${id}`).join(", ")}`}
                          >
                            (记忆链×{c.history_task_ids!.length})
                          </span>
                        )}
                        {c.hint_used && (
                          <span title={c.hint_content || "已用 Hint"}>
                            <LightbulbIcon className="h-3.5 w-3.5 text-amber-500" />
                          </span>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </CardContent>
      </Card>

      {/* Bottom Split: Submissions & Orchestrator Events */}
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-sm">
              <FlagIcon className="h-4 w-4" />
              平台验证提交日志 ({submissions.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="max-h-96 space-y-2 overflow-y-auto text-xs">
            {submissions.length === 0 ? (
              <div className="py-6 text-center text-muted-foreground">暂无 Flag / 答案提交记录</div>
            ) : (
              submissions.map((sub) => (
                <div key={sub.id} className="rounded-md border p-2.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono font-medium">{sub.unique_code}</span>
                    <Badge variant={sub.correct ? "default" : "destructive"} className="text-[10px]">
                      {sub.correct ? `通过 +${sub.awarded}` : "错误"}
                    </Badge>
                  </div>
                  <div className="mt-1 truncate font-mono text-[11px] text-muted-foreground">{sub.answer_value}</div>
                  {sub.message && <div className="mt-1 text-[11px] text-muted-foreground">{sub.message}</div>}
                </div>
              ))
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm">自动调度与环境编排事件 ({events.length})</CardTitle>
          </CardHeader>
          <CardContent className="max-h-96 space-y-2 overflow-y-auto text-xs">
            {events.length === 0 ? (
              <div className="py-6 text-center text-muted-foreground">暂无事件</div>
            ) : (
              events.map((ev) => (
                <div key={ev.id} className="rounded-md border p-2.5">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-1.5">
                      <Badge variant="outline" className="text-[10px]">
                        {ev.kind}
                      </Badge>
                      {ev.unique_code && <span className="font-mono text-[11px]">{ev.unique_code}</span>}
                    </div>
                    <span className="text-[10px] text-muted-foreground">
                      {new Date(ev.created_at).toLocaleTimeString()}
                    </span>
                  </div>
                  <div className="mt-1 text-foreground">{ev.summary}</div>
                </div>
              ))
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

export default function BenchmarkDetailPage() {
  return (
    <Suspense fallback={<div className="p-6 text-sm text-muted-foreground">加载中...</div>}>
      <BenchmarkDetailInner />
    </Suspense>
  );
}
