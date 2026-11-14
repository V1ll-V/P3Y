"use client";

import * as React from "react";

import {
  BookmarkCheckIcon,
  CheckCircle2Icon,
  ChevronDownIcon,
  ChevronRightIcon,
  Code2Icon,
  OctagonAlertIcon,
  RefreshCwIcon,
  RotateCcwIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import type { BoardItem, BoardItemKind, BoardKit } from "@/lib/types";

const KIND_STYLE: Record<BoardItemKind, { label: string; cls: string }> = {
  fact: { label: "Fact 线索", cls: "border-sky-500/30 bg-sky-500/10 text-sky-600 dark:text-sky-400" },
  step: { label: "Step 冲刺", cls: "border-violet-500/30 bg-violet-500/10 text-violet-600 dark:text-violet-400" },
  savepoint: { label: "Savepoint 存档", cls: "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400" },
  deadend: { label: "Deadend 死胡同", cls: "border-rose-500/30 bg-rose-500/10 text-rose-600 dark:text-rose-400" },
};

export function BoardTreePanel({ taskId }: { taskId: string }) {
  const [items, setItems] = React.useState<BoardItem[]>([]);
  const [kits, setKits] = React.useState<BoardKit[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [expanded, setExpanded] = React.useState<Record<number, string>>({});
  const [loadingDetail, setLoadingDetail] = React.useState<Record<number, boolean>>({});
  const [rewindingId, setRewindingId] = React.useState<number | null>(null);
  const [deadendNote, setDeadendNote] = React.useState("");

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.taskBoard(taskId);
      setItems(res.items);
      setKits(res.kits);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "加载状态看板失败");
    } finally {
      setLoading(false);
    }
  }, [taskId]);

  React.useEffect(() => {
    void load();
  }, [load]);

  const toggleDetail = async (item: BoardItem) => {
    if (expanded[item.id] !== undefined) {
      setExpanded((prev) => {
        const next = { ...prev };
        delete next[item.id];
        return next;
      });
      return;
    }
    setLoadingDetail((prev) => ({ ...prev, [item.id]: true }));
    try {
      const full = await api.taskBoardItem(taskId, item.id);
      setExpanded((prev) => ({ ...prev, [item.id]: full.detail?.trim() || "(无 L3 详情)" }));
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "读取详情失败");
    } finally {
      setLoadingDetail((prev) => ({ ...prev, [item.id]: false }));
    }
  };

  const triggerRewind = async (sp: BoardItem) => {
    setRewindingId(sp.id);
    try {
      const res = await api.taskBoardRewind(taskId, {
        savepoint_id: sp.id,
        deadend_title: "手动读档回滚",
        deadend_reason: deadendNote.trim() || `由前端看板触发回滚至 Savepoint #${sp.id} (${sp.title})`,
      });
      toast.success(`已读档恢复快照 ${res.snapshot_id}（累计回滚 ${res.rewind_count} 次）`);
      setDeadendNote("");
      await load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "读档回滚失败");
    } finally {
      setRewindingId(null);
    }
  };

  // 构建 parent_id -> children 树形结构，保持紧凑层级缩进
  const childrenMap = React.useMemo(() => {
    const map = new Map<number, BoardItem[]>();
    const roots: BoardItem[] = [];
    const byId = new Set(items.map((i) => i.id));
    for (const it of items) {
      if (it.parent_id && byId.has(it.parent_id)) {
        const list = map.get(it.parent_id) ?? [];
        list.push(it);
        map.set(it.parent_id, list);
      } else {
        roots.push(it);
      }
    }
    return { roots, map };
  }, [items]);

  const renderNode = (node: BoardItem, depth: number): React.ReactNode => {
    const meta = KIND_STYLE[node.kind] ?? KIND_STYLE.fact;
    const isOpen = expanded[node.id] !== undefined;
    const children = childrenMap.map.get(node.id) ?? [];

    return (
      <div key={node.id} className="flex flex-col gap-1.5" style={{ marginLeft: depth > 0 ? 18 : 0 }}>
        <div className="rounded-lg border bg-card p-3 shadow-2xs">
          <div className="flex flex-wrap items-start justify-between gap-2">
            <div className="flex min-w-0 flex-1 flex-col gap-1">
              <div className="flex flex-wrap items-center gap-1.5">
                <Badge variant="outline" className={meta.cls}>
                  {meta.label}
                </Badge>
                <span className="font-mono text-xs text-muted-foreground">#{node.id}</span>
                {node.verified && (
                  <Badge className="gap-1 bg-emerald-600/15 text-emerald-500 hover:bg-emerald-600/20">
                    <CheckCircle2Icon className="size-3" /> 已验证
                  </Badge>
                )}
                {node.snapshot_id && (
                  <Badge variant="secondary" className="font-mono text-[11px]">
                    snap:{node.snapshot_id.slice(0, 12)}
                  </Badge>
                )}
              </div>
              <div className="font-medium text-sm">{node.title}</div>
              {node.summary && <p className="text-xs leading-relaxed text-muted-foreground">{node.summary}</p>}
            </div>

            <div className="flex items-center gap-1.5">
              {node.kind === "savepoint" && node.snapshot_id && (
                <Button
                  size="sm"
                  variant="outline"
                  className="h-7 text-xs"
                  disabled={rewindingId === node.id}
                  onClick={() => void triggerRewind(node)}
                  title="回滚容器 /work 至此 Savepoint 快照并记录 Deadend"
                >
                  <RotateCcwIcon className={rewindingId === node.id ? "animate-spin" : ""} />
                  读档回滚
                </Button>
              )}
              <Button
                size="sm"
                variant="ghost"
                className="h-7 px-2 text-xs"
                onClick={() => void toggleDetail(node)}
                disabled={loadingDetail[node.id]}
              >
                {isOpen ? <ChevronDownIcon /> : <ChevronRightIcon />}
                {loadingDetail[node.id] ? "加载..." : "L3 详情"}
              </Button>
            </div>
          </div>

          {isOpen && (
            <pre className="mt-2.5 max-h-64 overflow-auto rounded-md border bg-muted/40 p-2.5 font-mono text-xs whitespace-pre-wrap break-all">
              {expanded[node.id]}
            </pre>
          )}
        </div>

        {children.map((ch) => renderNode(ch, depth + 1))}
      </div>
    );
  };

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2">
          <div>
            <CardTitle className="flex items-center gap-2 text-base">
              <BookmarkCheckIcon className="size-4 text-primary" /> 状态看板（Board / Savepoint / Deadend）
            </CardTitle>
            <CardDescription>
              三层渐进式共享状态树；点击 Savepoint 的「读档回滚」可原子恢复快照并自动记录 Deadend 排除分支。
            </CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <Input
              className="h-8 w-56 text-xs"
              value={deadendNote}
              onChange={(e) => setDeadendNote(e.target.value)}
              placeholder="可选：回滚 Deadend 备注原因"
            />
            <Button size="sm" variant="outline" onClick={() => void load()} disabled={loading}>
              <RefreshCwIcon className={loading ? "animate-spin" : ""} />
              刷新
            </Button>
          </div>
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          {items.length === 0 ? (
            <div className="flex items-center gap-2 py-8 text-sm text-muted-foreground">
              <OctagonAlertIcon className="size-4" />
              {loading ? "正在加载看板条目..." : "当前任务暂无 Board 记录。"}
            </div>
          ) : (
            childrenMap.roots.map((r) => renderNode(r, 0))
          )}
        </CardContent>
      </Card>

      {kits.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Code2Icon className="size-4 text-primary" /> 任务绑定 Kits 套件 ({kits.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="grid grid-cols-1 gap-2 md:grid-cols-2">
            {kits.map((k) => (
              <div key={k.id} className="rounded-md border p-2.5 text-xs">
                <div className="flex items-center justify-between gap-2 font-mono font-medium">
                  <span>{k.name}</span>
                  {k.verified && <Badge variant="secondary">已验证</Badge>}
                </div>
                <div className="mt-0.5 font-mono text-muted-foreground">{k.path}</div>
                {k.summary && <div className="mt-1">{k.summary}</div>}
              </div>
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
