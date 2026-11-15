"use client";

import * as React from "react";

import Link from "next/link";
import { useRouter } from "next/navigation";

import {
  CheckCircle2Icon,
  ExternalLinkIcon,
  FileArchiveIcon,
  Loader2Icon,
  PlayIcon,
  PlugZapIcon,
  PlusIcon,
  RefreshCwIcon,
  ServerIcon,
  ShieldCheckIcon,
  SquareIcon,
  Trash2Icon,
  TrophyIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { fmtTokens, formatTokenBreakdown } from "@/lib/format-tokens";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type {
  BenchmarkParsedSkill,
  BenchmarkProviderKind,
  BenchmarkSession,
  BenchmarkTestConnectionResult,
  LLMProfile,
} from "@/lib/types";

const STATUS_BADGE: Record<string, { label: string; variant: "default" | "secondary" | "destructive" | "outline" }> = {
  idle: { label: "待启动", variant: "outline" },
  running: { label: "测评中", variant: "default" },
  completed: { label: "已完成", variant: "secondary" },
  stopped: { label: "已停止", variant: "outline" },
  expired: { label: "已到期", variant: "destructive" },
  failed: { label: "异常终止", variant: "destructive" },
};

const PROVIDER_META: Record<BenchmarkProviderKind, { name: string; defaultUrl: string; desc: string }> = {
  tsecbench: {
    name: "TSecBench REST API",
    defaultUrl: "http://127.0.0.1:8000",
    desc: "标准赛题平台 HTTP 接口（BENCHMARK_TOKEN 鉴权、最多 3 并发靶机、多 Flag 累加计分）",
  },
  ctf2: {
    name: "CTF2 / DASCTF MCP",
    defaultUrl: "https://ctf2.dasctf.com/api/ai/v1/mcp",
    desc: "Streamable HTTP MCP 接入（Bearer Token、whoami 并发配额、客观选择题、5 分钟签名附件、脱敏解题笔记）",
  },
  generic_mcp: {
    name: "通用 HTTP MCP + Skill.zip",
    defaultUrl: "https://",
    desc: "支持任意兼容 HTTP MCP 赛题网关，配合上传平台 *-agent-skill.zip 自动注入解题规程与工具发现",
  },
};

export default function BenchmarkListPage() {
  const router = useRouter();
  const [sessions, setSessions] = React.useState<BenchmarkSession[]>([]);
  const [profiles, setProfiles] = React.useState<LLMProfile[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [createOpen, setCreateOpen] = React.useState(false);

  // Create form state
  const [name, setName] = React.useState("");
  const [provider, setProvider] = React.useState<BenchmarkProviderKind>("tsecbench");
  const [baseUrl, setBaseUrl] = React.useState(PROVIDER_META.tsecbench.defaultUrl);
  const [token, setToken] = React.useState("");
  const [source, setSource] = React.useState<"auto" | "competition" | "practice">("auto");
  const [competitionId, setCompetitionId] = React.useState("");
  const [stageId, setStageId] = React.useState("");
  const [inviteCode, setInviteCode] = React.useState("");
  const [maxConcurrent, setMaxConcurrent] = React.useState(3);
  const [perTimeout, setPerTimeout] = React.useState(1500);
  const [hintPolicy, setHintPolicy] = React.useState<"never" | "stagnant_only">("stagnant_only");
  const [insecureTls, setInsecureTls] = React.useState(false);
  const [vpnConfig, setVpnConfig] = React.useState("");
  const [vpnFilename, setVpnFilename] = React.useState("");
  const [selectedProfileId, setSelectedProfileId] = React.useState<string>("auto");
  const [autoStart, setAutoStart] = React.useState(true);

  const [skillFile, setSkillFile] = React.useState<File | null>(null);
  const [parsedSkill, setParsedSkill] = React.useState<BenchmarkParsedSkill | null>(null);
  const [testingConn, setTestingConn] = React.useState(false);
  const [testResult, setTestResult] = React.useState<BenchmarkTestConnectionResult | null>(null);
  const [submitting, setSubmitting] = React.useState(false);

  const loadAll = React.useCallback(async () => {
    try {
      const [list, profs] = await Promise.all([api.benchmarkListSessions(), api.llmProfiles()]);
      setSessions(list);
      setProfiles(profs);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "加载测评列表失败");
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void loadAll();
    const timer = window.setInterval(() => {
      void api.benchmarkListSessions().then(setSessions).catch(() => undefined);
    }, 5000);
    return () => window.clearInterval(timer);
  }, [loadAll]);

  const handleProviderChange = (next: BenchmarkProviderKind) => {
    setProvider(next);
    setBaseUrl(PROVIDER_META[next].defaultUrl);
    setMaxConcurrent(next === "ctf2" ? 1 : 3);
    setTestResult(null);
  };

  const handleSkillFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setSkillFile(file);
    try {
      const parsed = await api.benchmarkParseSkill(file);
      setParsedSkill(parsed);
      toast.success(`已解析 Skill 包：${parsed.name}（${parsed.files.length} 个文件）`);
    } catch (err) {
      setParsedSkill(null);
      toast.error(err instanceof Error ? err.message : "解析 Skill 包失败");
    }
  };

  const handleVpnFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    setVpnConfig(text);
    setVpnFilename(file.name);
    toast.success(`已载入 WireGuard 配置：${file.name}`);
  };

  const handleTestConnection = async () => {
    if (!baseUrl.trim()) {
      toast.error("请输入平台 Base URL / MCP URL");
      return;
    }
    setTestingConn(true);
    setTestResult(null);
    try {
      const res = await api.benchmarkTestConnection({
        provider,
        base_url: baseUrl.trim(),
        token: token.trim(),
        config: {
          source,
          competition_id: competitionId.trim() || undefined,
          stage_id: stageId.trim() || undefined,
          invite_code: inviteCode.trim() || undefined,
          insecure_tls: insecureTls,
        },
      });
      setTestResult(res);
      if (res.profile?.max_environments && res.profile.max_environments > 0) {
        setMaxConcurrent(res.profile.max_environments);
      }
      if (res.ok) {
        toast.success(`连通性正常，同步发现 ${res.challenge_count} 道题目`);
      } else {
        toast.warning(res.error || "已连接，但获取题库失败");
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "连通性测试失败");
    } finally {
      setTestingConn(false);
    }
  };

  const handleCreate = async () => {
    if (!baseUrl.trim()) {
      toast.error("请填写平台地址");
      return;
    }
    setSubmitting(true);
    try {
      const llmIds = selectedProfileId !== "auto" ? [Number(selectedProfileId)] : [];
      const created = await api.benchmarkCreateSession(
        {
          name: name.trim() || `${PROVIDER_META[provider].name} 测评`,
          provider,
          base_url: baseUrl.trim(),
          token: token.trim(),
          max_concurrent: maxConcurrent,
          hint_policy: hintPolicy,
          per_challenge_timeout: perTimeout,
          llm_profile_ids: llmIds,
          auto_start: autoStart,
          config: {
            source,
            competition_id: competitionId.trim() || undefined,
            stage_id: stageId.trim() || undefined,
            invite_code: inviteCode.trim() || undefined,
            insecure_tls: insecureTls,
            ctf_vpn_config: vpnConfig || undefined,
            ctf_vpn_filename: vpnFilename || undefined,
            skill_name: parsedSkill?.name,
            skill_instructions: parsedSkill?.instructions,
          },
        },
        skillFile,
      );
      toast.success(`测评会话 #${created.id} 已创建`);
      setCreateOpen(false);
      router.push(`/benchmark/detail?id=${created.id}`);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "创建测评失败");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="mx-auto flex w-full max-w-7xl flex-col gap-6 p-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <TrophyIcon className="h-6 w-6 text-amber-500" />
            <h1 className="text-2xl font-semibold tracking-tight">零交互自动测评控制台</h1>
            <Badge variant="outline" className="text-xs">
              Zero-Touch Multi-Platform
            </Badge>
          </div>
          <p className="mt-1 text-sm text-muted-foreground">
            无人值守自动编排求解全题库：兼容 TSecBench REST API、CTF2/DASCTF MCP 及通用 HTTP MCP + Skill 包。子任务完全隔离，不干扰常规任务列表。
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => void loadAll()}>
            <RefreshCwIcon className="mr-1.5 h-4 w-4" />
            刷新
          </Button>
          <Button size="sm" onClick={() => setCreateOpen(true)}>
            <PlusIcon className="mr-1.5 h-4 w-4" />
            新建自动测评
          </Button>
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-20 text-muted-foreground">
          <Loader2Icon className="mr-2 h-5 w-5 animate-spin" />
          正在加载测评会话...
        </div>
      ) : sessions.length === 0 ? (
        <Card className="border-dashed">
          <CardContent className="flex flex-col items-center justify-center gap-3 py-16 text-center">
            <TrophyIcon className="h-10 w-10 text-muted-foreground/60" />
            <div className="text-base font-medium">暂无零交互测评会话</div>
            <p className="max-w-lg text-sm text-muted-foreground">
              配置比赛平台的 REST 接口或 MCP Server + Token（可选导入官方 Skill.zip 与赛题 WireGuard VPN），系统将自动管理靶机并发槽位、附件挂载、自动提交 Flag 与客观题验真。
            </p>
            <Button onClick={() => setCreateOpen(true)} className="mt-2">
              <PlusIcon className="mr-1.5 h-4 w-4" />
              立即接入赛题平台
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {sessions.map((s) => {
            const st = STATUS_BADGE[s.status] ?? { label: s.status, variant: "outline" as const };
            const pct = s.total_count > 0 ? Math.round((s.completed_count / s.total_count) * 100) : 0;
            return (
              <Card key={s.id} className="flex flex-col justify-between transition-shadow hover:shadow-md">
                <CardHeader className="pb-3">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <CardTitle className="truncate text-base">{s.name}</CardTitle>
                      <CardDescription className="mt-1 truncate text-xs">{s.base_url}</CardDescription>
                    </div>
                    <Badge variant={st.variant}>{st.label}</Badge>
                  </div>
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    <Badge variant="secondary" className="text-[11px]">
                      {PROVIDER_META[s.provider]?.name ?? s.provider}
                    </Badge>
                    <Badge variant="outline" className="text-[11px]">
                      并发上限 {s.max_concurrent}
                    </Badge>
                    {s.config?.skill_name && (
                      <Badge variant="outline" className="text-[11px]">
                        Skill: {s.config.skill_name}
                      </Badge>
                    )}
                  </div>
                </CardHeader>
                <CardContent className="flex flex-col gap-3 pt-0">
                  <div className="grid grid-cols-2 gap-2 rounded-md border bg-muted/30 p-2.5 text-center sm:grid-cols-4">
                    <div>
                      <div className="text-xs text-muted-foreground">总分</div>
                      <div className="font-mono text-sm font-semibold">
                        {s.total_score}/{s.max_possible_score}
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-muted-foreground">通关题目</div>
                      <div className="font-mono text-sm font-semibold">
                        {s.completed_count}/{s.total_count}
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-muted-foreground">活跃槽位</div>
                      <div className="font-mono text-sm font-semibold">{s.active_slots}</div>
                    </div>
                    <div title={formatTokenBreakdown(s.tokens)}>
                      <div className="text-xs text-muted-foreground">累计 Token</div>
                      <div className="font-mono text-sm font-semibold">
                        {fmtTokens(s.tokens?.total_tokens ?? 0)}
                      </div>
                    </div>
                  </div>
                  <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
                    <div className="h-full bg-emerald-500 transition-all" style={{ width: `${pct}%` }} />
                  </div>
                  {s.last_error && (
                    <div className="truncate text-xs text-destructive" title={s.last_error}>
                      {s.last_error}
                    </div>
                  )}
                  <div className="flex items-center justify-between gap-2 pt-1">
                    <div className="flex items-center gap-1.5">
                      {s.status === "running" ? (
                        <Button
                          variant="outline"
                          size="xs"
                          onClick={async () => {
                            await api.benchmarkStopSession(s.id);
                            void loadAll();
                          }}
                        >
                          <SquareIcon className="mr-1 h-3 w-3" />
                          停止
                        </Button>
                      ) : (
                        <Button
                          variant="default"
                          size="xs"
                          onClick={async () => {
                            await api.benchmarkStartSession(s.id);
                            void loadAll();
                          }}
                        >
                          <PlayIcon className="mr-1 h-3 w-3" />
                          启动
                        </Button>
                      )}
                      <Button
                        variant="ghost"
                        size="icon-xs"
                        title="删除测评会话"
                        onClick={async () => {
                          await api.benchmarkDeleteSession(s.id);
                          toast.success("已删除测评会话");
                          void loadAll();
                        }}
                      >
                        <Trash2Icon className="h-3.5 w-3.5 text-muted-foreground" />
                      </Button>
                    </div>
                    <Button asChild variant="secondary" size="xs">
                      <Link href={`/benchmark/detail?id=${s.id}`}>
                        查看详情
                        <ExternalLinkIcon className="ml-1 h-3 w-3" />
                      </Link>
                    </Button>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent className="max-h-[90dvh] w-[min(95vw,760px)] overflow-y-auto p-6 sm:max-w-[760px]">
          <DialogHeader>
            <DialogTitle>接入零交互自动测评平台</DialogTitle>
            <DialogDescription>
              支持按竞赛平台类型自动适配 REST API / MCP 协议与 Skill 规范包，全程禁止人工审批弹窗或阻塞等待。
            </DialogDescription>
          </DialogHeader>

          <div className="flex flex-col gap-5 py-2">
            <div className="space-y-2">
              <Label className="block text-xs font-medium text-muted-foreground">平台接入协议</Label>
              <Tabs value={provider} onValueChange={(v) => handleProviderChange(v as BenchmarkProviderKind)}>
                <TabsList className="grid h-9 w-full grid-cols-3 gap-1">
                  <TabsTrigger value="tsecbench" className="truncate text-xs">
                    TSecBench REST
                  </TabsTrigger>
                  <TabsTrigger value="ctf2" className="truncate text-xs">
                    CTF2 / DASCTF MCP
                  </TabsTrigger>
                  <TabsTrigger value="generic_mcp" className="truncate text-xs">
                    通用 MCP + Skill
                  </TabsTrigger>
                </TabsList>
              </Tabs>
              <p className="text-xs leading-relaxed text-muted-foreground">{PROVIDER_META[provider].desc}</p>
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label className="text-xs font-medium">测评名称</Label>
                <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="如：DASCTF 秋季赛全自动打榜" />
              </div>
              <div className="space-y-2">
                <Label className="text-xs font-medium">LLM 配置覆盖</Label>
                <Select value={selectedProfileId} onValueChange={setSelectedProfileId}>
                  <SelectTrigger className="w-full">
                    <SelectValue placeholder="跟随系统默认 LLM" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="auto">跟随系统当前激活模型</SelectItem>
                    {profiles.map((p) => (
                      <SelectItem key={p.id} value={String(p.id)}>
                        {p.name} ({p.model})
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label className="text-xs font-medium">
                  {provider === "tsecbench" ? "Challenges API Base URL" : "Streamable HTTP MCP URL"}
                </Label>
                <Input value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} placeholder="https://..." />
              </div>
              <div className="space-y-2">
                <Label className="text-xs font-medium">
                  {provider === "tsecbench" ? "BENCHMARK_TOKEN" : "Bearer Token / Agent Token"}
                </Label>
                <Input
                  type="password"
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                  placeholder="平台分配的 Token"
                />
              </div>
            </div>

            {(provider === "ctf2" || provider === "generic_mcp") && (
              <div className="grid gap-3 rounded-lg border bg-muted/20 p-3.5 sm:grid-cols-2 lg:grid-cols-4">
                <div className="space-y-1.5">
                  <Label className="text-xs">题库来源</Label>
                  <Select value={source} onValueChange={(v) => setSource(v as "auto" | "competition" | "practice")}>
                    <SelectTrigger className="h-8 w-full text-xs">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="auto">自动探测</SelectItem>
                      <SelectItem value="competition">仅正式比赛</SelectItem>
                      <SelectItem value="practice">仅训练场</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs">比赛 ID (可选)</Label>
                  <Input className="h-8 text-xs" value={competitionId} onChange={(e) => setCompetitionId(e.target.value)} />
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs">阶段/场次 ID</Label>
                  <Input className="h-8 text-xs" value={stageId} onChange={(e) => setStageId(e.target.value)} />
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs">训练场邀请码</Label>
                  <Input className="h-8 text-xs" value={inviteCode} onChange={(e) => setInviteCode(e.target.value)} />
                </div>
              </div>
            )}

            <div className="grid gap-4 sm:grid-cols-3">
              <div className="space-y-2">
                <Label className="text-xs font-medium">最大并发题目/容器数</Label>
                <Input
                  type="number"
                  min={1}
                  max={16}
                  value={maxConcurrent}
                  onChange={(e) => setMaxConcurrent(Math.max(1, Number(e.target.value) || 1))}
                />
              </div>
              <div className="space-y-2">
                <Label className="text-xs font-medium">单题预算超时 (秒)</Label>
                <Input
                  type="number"
                  min={60}
                  max={7200}
                  value={perTimeout}
                  onChange={(e) => setPerTimeout(Math.max(60, Number(e.target.value) || 1500))}
                />
              </div>
              <div className="space-y-2">
                <Label className="text-xs font-medium">Hint 获取策略</Label>
                <Select value={hintPolicy} onValueChange={(v) => setHintPolicy(v as "never" | "stagnant_only")}>
                  <SelectTrigger className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="stagnant_only">停滞后自动求助 Hint</SelectItem>
                    <SelectItem value="never">禁用 Hint（纯裸解）</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="flex flex-col gap-2.5 rounded-lg border p-3.5">
                <Label className="flex items-center gap-1.5 text-xs font-medium">
                  <FileArchiveIcon className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                  导入平台 Skill 包 (.zip 可选)
                </Label>
                <div className="flex items-center gap-2">
                  <Button asChild type="button" variant="outline" size="sm" className="shrink-0 text-xs">
                    <label className="cursor-pointer">
                      选择 .zip 文件
                      <input type="file" accept=".zip" className="sr-only" onChange={(e) => void handleSkillFileChange(e)} />
                    </label>
                  </Button>
                  <span className="truncate text-xs text-muted-foreground">
                    {skillFile ? skillFile.name : "未选择文件"}
                  </span>
                </div>
                {parsedSkill && (
                  <p className="text-xs text-emerald-600">
                    已提取 {parsedSkill.name} ({parsedSkill.files.length} 文件 · {parsedSkill.instructions.length} 字符)
                  </p>
                )}
              </div>

              <div className="flex flex-col gap-2.5 rounded-lg border p-3.5">
                <Label className="flex items-center gap-1.5 text-xs font-medium">
                  <ShieldCheckIcon className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                  赛题内网 WireGuard VPN (.conf 可选)
                </Label>
                <div className="flex items-center gap-2">
                  <Button asChild type="button" variant="outline" size="sm" className="shrink-0 text-xs">
                    <label className="cursor-pointer">
                      选择 .conf 文件
                      <input type="file" accept=".conf,.txt" className="sr-only" onChange={(e) => void handleVpnFileChange(e)} />
                    </label>
                  </Button>
                  <span className="truncate text-xs text-muted-foreground">
                    {vpnFilename || "未选择文件"}
                  </span>
                </div>
                <Textarea
                  rows={2}
                  value={vpnConfig}
                  onChange={(e) => setVpnConfig(e.target.value)}
                  placeholder="或直接粘贴 [Interface] / [Peer] 配置..."
                  className="text-xs"
                />
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-4 rounded-lg border bg-muted/20 px-3.5 py-2.5">
              <div className="flex items-center gap-2">
                <Switch checked={autoStart} onCheckedChange={setAutoStart} id="bench-autostart" />
                <Label htmlFor="bench-autostart" className="cursor-pointer text-xs">
                  创建并同步题库后立即启动全自动测评
                </Label>
              </div>
              <div className="flex items-center gap-2">
                <Switch checked={insecureTls} onCheckedChange={setInsecureTls} id="bench-tls" />
                <Label htmlFor="bench-tls" className="cursor-pointer text-xs">
                  允许自签名 TLS 证书
                </Label>
              </div>
            </div>

            <div className="flex flex-col gap-2.5 rounded-lg border px-3.5 py-2.5 sm:flex-row sm:items-center sm:justify-between">
              <div className="text-xs text-muted-foreground">
                {testResult ? (
                  <span className="flex items-center gap-1.5 text-foreground">
                    <CheckCircle2Icon className="h-4 w-4 shrink-0 text-emerald-500" />
                    同步发现 {testResult.challenge_count} 道题目
                    {testResult.profile ? ` · 平台配额 ${testResult.profile.max_environments} 个环境` : ""}
                    {testResult.discovered_tools?.length ? ` · MCP 工具 ${testResult.discovered_tools.length} 个` : ""}
                  </span>
                ) : (
                  "建议先测试连通性以确认 Token 有效与并发配额"
                )}
              </div>
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="shrink-0"
                disabled={testingConn}
                onClick={() => void handleTestConnection()}
              >
                {testingConn ? <Loader2Icon className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : <PlugZapIcon className="mr-1.5 h-3.5 w-3.5" />}
                测试连通性
              </Button>
            </div>
          </div>

          <DialogFooter>
            <Button variant="ghost" onClick={() => setCreateOpen(false)}>
              取消
            </Button>
            <Button disabled={submitting} onClick={() => void handleCreate()}>
              {submitting ? <Loader2Icon className="mr-1.5 h-4 w-4 animate-spin" /> : <ServerIcon className="mr-1.5 h-4 w-4" />}
              创建测评会话
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
