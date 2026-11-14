"use client";

import * as React from "react";

import {
  FileCode2Icon,
  FlaskConicalIcon,
  RefreshCwIcon,
  SparklesIcon,
  TargetIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import type { PrecheckResult } from "@/lib/types";

export function PrecheckPanel({ taskId, isCtf }: { taskId: string; isCtf: boolean }) {
  const [data, setData] = React.useState<PrecheckResult | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [running, setRunning] = React.useState(false);

  const load = React.useCallback(async () => {
    if (!isCtf) return;
    setLoading(true);
    try {
      const res = await api.taskPrecheckGet(taskId);
      setData(res);
    } catch {
      // 未生成时后端可能返回 404，保持空状态即可
      setData(null);
    } finally {
      setLoading(false);
    }
  }, [taskId, isCtf]);

  React.useEffect(() => {
    void load();
  }, [load]);

  if (!isCtf) return null;

  const runNow = async () => {
    setRunning(true);
    try {
      const res = await api.taskPrecheckRun(taskId);
      setData(res);
      toast.success("已完成 Phase-0 Precheck 静态初检");
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Precheck 执行失败");
    } finally {
      setRunning(false);
    }
  };

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between gap-3">
        <div>
          <CardTitle className="flex items-center gap-2 text-base">
            <FlaskConicalIcon className="size-4 text-primary" /> Phase-0 Precheck 化验单
            {data?.inferred_category && (
              <Badge variant="secondary" className="uppercase">
                {data.inferred_category}
              </Badge>
            )}
          </CardTitle>
          <CardDescription>
            0-LLM 秒级静态侦察：自动提取附件特征、ELF 保护位、靶机地址，并按标签召回历史 Tips 避坑卡。
          </CardDescription>
        </div>
        <Button size="sm" variant="outline" onClick={() => void runNow()} disabled={running}>
          <RefreshCwIcon className={running || loading ? "animate-spin" : ""} />
          {data ? "重新初检" : "执行初检"}
        </Button>
      </CardHeader>
      <CardContent className="flex flex-col gap-3 text-sm">
        {!data ? (
          <div className="text-muted-foreground">
            {loading ? "正在加载 Precheck 化验单..." : "尚无 Precheck 结果，点击右上角「执行初检」即可立即生成。"}
          </div>
        ) : (
          <>
            {data.summary && <p className="rounded-md border bg-muted/30 p-2.5 text-sm whitespace-pre-wrap">{data.summary}</p>}

            {data.targets && data.targets.length > 0 && (
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="flex items-center gap-1 text-xs font-medium text-muted-foreground">
                  <TargetIcon className="size-3.5" /> 靶标:
                </span>
                {data.targets.map((t) => (
                  <Badge key={t} variant="outline" className="font-mono text-xs">
                    {t}
                  </Badge>
                ))}
              </div>
            )}

            {data.files && data.files.length > 0 && (
              <div className="flex flex-col gap-2">
                <div className="flex items-center gap-1 text-xs font-medium text-muted-foreground">
                  <FileCode2Icon className="size-3.5" /> 附件静态分析 ({data.files.length})
                </div>
                <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
                  {data.files.map((f) => (
                    <div key={f.id} className="rounded-md border p-2.5 text-xs">
                      <div className="flex items-center justify-between gap-2 font-mono font-medium">
                        <span className="truncate">{f.name}</span>
                        <Badge variant="outline">{f.arch || f.kind || "file"}</Badge>
                      </div>
                      {f.protections && Object.keys(f.protections).length > 0 && (
                        <div className="mt-1.5 flex flex-wrap gap-1">
                          {Object.entries(f.protections).map(([k, v]) => (
                            <Badge key={k} variant="secondary" className="font-mono text-[11px]">
                              {k}: {String(v)}
                            </Badge>
                          ))}
                        </div>
                      )}
                      {f.notes && <div className="mt-1 text-muted-foreground">{f.notes}</div>}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {data.matched_tips && data.matched_tips.length > 0 && (
              <div className="flex flex-col gap-1.5">
                <div className="flex items-center gap-1 text-xs font-medium text-muted-foreground">
                  <SparklesIcon className="size-3.5 text-amber-500" /> 召回 Tips 避坑卡 ({data.matched_tips.length})
                </div>
                <div className="flex flex-col gap-1.5">
                  {data.matched_tips.map((tip) => (
                    <div key={tip.id} className="rounded-md border border-amber-500/30 bg-amber-500/5 px-2.5 py-2 text-xs">
                      <div className="font-medium text-amber-600 dark:text-amber-400">{tip.title}</div>
                      <div className="mt-0.5 text-foreground/85">{tip.pitfall}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}
