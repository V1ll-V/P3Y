"use client";

import * as React from "react";

import Link from "next/link";
import {
  CheckCircle2Icon,
  Code2Icon,
  CopyIcon,
  PlusIcon,
  RefreshCwIcon,
  SearchIcon,
  SparklesIcon,
  Trash2Icon,
  WrenchIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { BoardKit, TipCard } from "@/lib/types";
import { copyText } from "@/lib/utils";

const CATEGORIES = ["", "pwn", "web", "reverse", "crypto", "misc", "ad", "auto"] as const;

export default function KitsAndTipsPage() {
  const [section, setSection] = React.useState<"tips" | "kits">("tips");
  const [loading, setLoading] = React.useState(true);
  const [tips, setTips] = React.useState<TipCard[]>([]);
  const [kits, setKits] = React.useState<BoardKit[]>([]);

  const [categoryFilter, setCategoryFilter] = React.useState("");
  const [tagFilter, setTagFilter] = React.useState("");
  const [searchText, setSearchText] = React.useState("");

  // Create TipCard form
  const [showCreate, setShowCreate] = React.useState(false);
  const [newCategory, setNewCategory] = React.useState("pwn");
  const [newTags, setNewTags] = React.useState("");
  const [newTitle, setNewTitle] = React.useState("");
  const [newPitfall, setNewPitfall] = React.useState("");
  const [newCode, setNewCode] = React.useState("");
  const [saving, setSaving] = React.useState(false);

  const loadData = React.useCallback(async () => {
    setLoading(true);
    try {
      const [tipsRes, kitsRes] = await Promise.all([
        api.listTips({
          category: categoryFilter || undefined,
          tags: tagFilter.trim() || undefined,
          limit: 100,
        }),
        api.listKits({ limit: 100 }),
      ]);
      setTips(tipsRes);
      setKits(kitsRes);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "加载武库与避坑卡失败");
    } finally {
      setLoading(false);
    }
  }, [categoryFilter, tagFilter]);

  React.useEffect(() => {
    void loadData();
  }, [loadData]);

  const createTip = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim() || !newPitfall.trim()) {
      toast.error("标题与避坑规律不能为空");
      return;
    }
    setSaving(true);
    try {
      const tags = newTags
        .split(",")
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean);
      const created = await api.createTip({
        category: newCategory,
        tags,
        title: newTitle.trim(),
        pitfall: newPitfall.trim(),
        pattern_code: newCode.trim() || undefined,
      });
      setTips((prev) => [created, ...prev]);
      setNewTitle("");
      setNewTags("");
      setNewPitfall("");
      setNewCode("");
      setShowCreate(false);
      toast.success("已保存避坑卡");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "创建失败");
    } finally {
      setSaving(false);
    }
  };

  const removeTip = async (id: number) => {
    try {
      await api.deleteTip(id);
      setTips((prev) => prev.filter((c) => c.id !== id));
      toast.success("已删除避坑卡");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "删除失败");
    }
  };

  const q = searchText.trim().toLowerCase();
  const filteredTips = React.useMemo(() => {
    if (!q) return tips;
    return tips.filter(
      (t) =>
        t.title.toLowerCase().includes(q) ||
        t.pitfall.toLowerCase().includes(q) ||
        (t.pattern_code ?? "").toLowerCase().includes(q) ||
        t.tags.some((tg) => tg.toLowerCase().includes(q)),
    );
  }, [tips, q]);

  const filteredKits = React.useMemo(() => {
    if (!q) return kits;
    return kits.filter(
      (k) =>
        k.name.toLowerCase().includes(q) ||
        k.path.toLowerCase().includes(q) ||
        k.summary.toLowerCase().includes(q) ||
        (k.source_task_name ?? "").toLowerCase().includes(q) ||
        (k.content ?? "").toLowerCase().includes(q) ||
        String(k.task_id).includes(q),
    );
  }, [kits, q]);

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-bold tracking-tight">
            <WrenchIcon className="size-6 text-primary" />
            武库与套件（Kits & Tips）
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            管理跨任务沉淀的可复用 Exploit / 交互套件（Board Kits）与赛后自动提炼的避坑规则卡（Tips）。
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => void loadData()} disabled={loading}>
            <RefreshCwIcon className={loading ? "animate-spin" : ""} />
            刷新
          </Button>
          {section === "tips" && (
            <Button size="sm" onClick={() => setShowCreate((v) => !v)}>
              <PlusIcon />
              {showCreate ? "收起表单" : "新增避坑卡"}
            </Button>
          )}
        </div>
      </div>

      {/* 切换条 + 过滤条 */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-1 rounded-lg border bg-muted/40 p-1">
          <button
            type="button"
            onClick={() => setSection("tips")}
            className={`rounded-md px-3 py-1 text-sm font-medium transition-colors ${
              section === "tips" ? "bg-background shadow-xs" : "text-muted-foreground hover:text-foreground"
            }`}
          >
            Tips 避坑卡库 ({filteredTips.length})
          </button>
          <button
            type="button"
            onClick={() => setSection("kits")}
            className={`rounded-md px-3 py-1 text-sm font-medium transition-colors ${
              section === "kits" ? "bg-background shadow-xs" : "text-muted-foreground hover:text-foreground"
            }`}
          >
            Kits 可复用套件 ({filteredKits.length})
          </button>
        </div>

        <div className="relative ml-auto min-w-52 flex-1 sm:max-w-xs">
          <SearchIcon className="absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            className="h-8 pl-8"
            value={searchText}
            onChange={(e) => setSearchText(e.target.value)}
            placeholder={section === "tips" ? "搜索标题 / 规律 / 代码 / 标签" : "搜索文件名 / 路径 / 任务 ID"}
          />
        </div>

        {section === "tips" && (
          <>
            <NativeSelect
              size="sm"
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              aria-label="题型筛选"
            >
              {CATEGORIES.map((c) => (
                <NativeSelectOption key={c || "all"} value={c}>
                  {c ? `类型: ${c.toUpperCase()}` : "全部题型"}
                </NativeSelectOption>
              ))}
            </NativeSelect>
            <Input
              className="h-8 w-44"
              value={tagFilter}
              onChange={(e) => setTagFilter(e.target.value)}
              placeholder="按 tag 过滤（逗号分隔）"
            />
          </>
        )}
      </div>

      {/* 新增 TipCard 表单 */}
      {section === "tips" && showCreate && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <SparklesIcon className="size-4 text-primary" /> 新建跨题避坑卡
            </CardTitle>
            <CardDescription>Precheck 阶段会根据题型与特征标签自动召回匹配的避坑卡注入主攻手。</CardDescription>
          </CardHeader>
          <CardContent>
            <form className="flex flex-col gap-3" onSubmit={createTip}>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                <NativeSelect value={newCategory} onChange={(e) => setNewCategory(e.target.value)}>
                  {CATEGORIES.filter(Boolean).map((c) => (
                    <NativeSelectOption key={c} value={c}>
                      {c.toUpperCase()}
                    </NativeSelectOption>
                  ))}
                </NativeSelect>
                <Input
                  value={newTags}
                  onChange={(e) => setNewTags(e.target.value)}
                  placeholder="标签（如 amd64, stack_alignment, glibc_2_31）"
                />
                <Input
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  placeholder="标题（<= 50 字）"
                />
              </div>
              <Textarea
                rows={2}
                value={newPitfall}
                onChange={(e) => setNewPitfall(e.target.value)}
                placeholder="避坑规律：什么特征下会踩坑、如何绕过或验证"
              />
              <Textarea
                rows={3}
                className="font-mono text-xs"
                value={newCode}
                onChange={(e) => setNewCode(e.target.value)}
                placeholder="可复用代码或命令模板（可选）"
              />
              <div className="flex justify-end gap-2">
                <Button type="button" variant="ghost" size="sm" onClick={() => setShowCreate(false)}>
                  取消
                </Button>
                <Button type="submit" size="sm" disabled={saving}>
                  {saving ? "保存中..." : "保存避坑卡"}
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      )}

      {/* Tips 列表 */}
      {section === "tips" && (
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
          {filteredTips.length === 0 ? (
            <Card className="col-span-full">
              <CardContent className="py-10 text-center text-sm text-muted-foreground">
                {loading ? "正在加载避坑卡..." : "暂无匹配的 Tips 避坑卡；解出题目后可自动沉淀或点击上方手动新增。"}
              </CardContent>
            </Card>
          ) : (
            filteredTips.map((card) => (
              <Card key={card.id} className="flex flex-col justify-between">
                <CardHeader className="pb-2">
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex flex-col gap-1">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <Badge variant="secondary" className="uppercase">
                          {card.category || "auto"}
                        </Badge>
                        {card.tags.map((tg) => (
                          <Badge key={tg} variant="outline" className="font-mono text-[11px]">
                            #{tg}
                          </Badge>
                        ))}
                        {card.hit_count > 0 && (
                          <span className="text-xs text-muted-foreground">命中 {card.hit_count} 次</span>
                        )}
                      </div>
                      <CardTitle className="text-base">{card.title}</CardTitle>
                    </div>
                    <Button
                      size="icon-xs"
                      variant="ghost"
                      className="text-muted-foreground hover:text-destructive"
                      onClick={() => void removeTip(card.id)}
                      title="删除避坑卡"
                    >
                      <Trash2Icon className="size-3.5" />
                    </Button>
                  </div>
                </CardHeader>
                <CardContent className="flex flex-col gap-2.5 text-sm">
                  <p className="leading-relaxed text-foreground/90">{card.pitfall}</p>
                  {card.pattern_code && (
                    <div className="relative rounded-md border bg-muted/40 p-2.5">
                      <pre className="overflow-x-auto pr-8 font-mono text-xs whitespace-pre-wrap break-all">
                        {card.pattern_code}
                      </pre>
                      <Button
                        size="icon-xs"
                        variant="ghost"
                        className="absolute top-1.5 right-1.5"
                        title="复制代码模板"
                        onClick={async () => {
                          if (await copyText(card.pattern_code ?? "")) toast.success("已复制模板代码");
                        }}
                      >
                        <CopyIcon className="size-3.5" />
                      </Button>
                    </div>
                  )}
                  <div className="flex items-center justify-between text-xs text-muted-foreground">
                    <span>
                      {card.source_task_id ? (
                        <Link href={`/function/tasks/detail?id=${card.source_task_id}`} className="hover:underline">
                          来源任务 #{card.source_task_id}
                        </Link>
                      ) : (
                        "手工录入"
                      )}
                    </span>
                    <span>{new Date(card.created_at).toLocaleString()}</span>
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </div>
      )}

      {/* Kits 列表 */}
      {section === "kits" && (
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
          {filteredKits.length === 0 ? (
            <Card className="col-span-full">
              <CardContent className="py-10 text-center text-sm text-muted-foreground">
                {loading ? "正在加载套件..." : "暂无登记的可复用 Kit 套件。"}
              </CardContent>
            </Card>
          ) : (
            filteredKits.map((kit) => (
              <Card key={kit.id}>
                <CardHeader className="pb-2">
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex flex-col gap-1">
                      <div className="flex items-center gap-2">
                        <Code2Icon className="size-4 text-primary" />
                        <CardTitle className="font-mono text-base">{kit.name}</CardTitle>
                        {kit.verified && (
                          <Badge className="gap-1 bg-emerald-600/15 text-emerald-500 hover:bg-emerald-600/20">
                            <CheckCircle2Icon className="size-3" /> 已验证
                          </Badge>
                        )}
                      </div>
                      <CardDescription className="font-mono text-xs">{kit.path}</CardDescription>
                    </div>
                    <Button
                      size="icon-xs"
                      variant="ghost"
                      title="复制沙箱路径"
                      onClick={async () => {
                        if (await copyText(kit.path)) toast.success("已复制路径");
                      }}
                    >
                      <CopyIcon className="size-3.5" />
                    </Button>
                  </div>
                </CardHeader>
                <CardContent className="flex flex-col gap-2.5 text-sm">
                  <p className="text-foreground/90">{kit.summary || "—"}</p>
                  {kit.content && (
                    <div className="relative rounded-md border bg-muted/40 p-2.5">
                      <pre className="max-h-56 overflow-auto pr-8 font-mono text-xs whitespace-pre-wrap break-all">
                        {kit.content}
                      </pre>
                      <Button
                        size="icon-xs"
                        variant="ghost"
                        className="absolute top-1.5 right-1.5"
                        title="复制套件脚本内容"
                        onClick={async () => {
                          if (await copyText(kit.content ?? "")) toast.success("已复制套件代码");
                        }}
                      >
                        <CopyIcon className="size-3.5" />
                      </Button>
                    </div>
                  )}
                  <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground">
                    <div className="flex items-center gap-3">
                      {kit.task_id > 0 ? (
                        <Link href={`/function/tasks/detail?id=${kit.task_id}`} className="text-primary hover:underline">
                          任务 #{kit.task_id}
                          {kit.source_task_name ? ` · ${kit.source_task_name}` : ""}
                        </Link>
                      ) : (
                        <span>
                          已清理任务{kit.source_task_name ? ` · ${kit.source_task_name}` : ""}
                        </span>
                      )}
                      {kit.savepoint_id && <span>Savepoint #{kit.savepoint_id}</span>}
                      {kit.sha256 && <span className="font-mono">sha256:{kit.sha256.slice(0, 12)}</span>}
                    </div>
                    <span>{new Date(kit.created_at).toLocaleString()}</span>
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </div>
      )}
    </div>
  );
}
