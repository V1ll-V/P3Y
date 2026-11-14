"use client";

import * as React from "react";

import { Card, CardContent } from "@/components/ui/card";
import { ExplorationGraph } from "@/components/exploration-graph";
import { api } from "@/lib/api";
import type { Edge, TaskNode } from "@/lib/types";
import { BoardTreePanel } from "./board-tree-panel";

export function GraphTab({ taskId }: { taskId: string }) {
  const [view, setView] = React.useState<"board" | "graph">("board");
  const [nodes, setNodes] = React.useState<TaskNode[]>([]);
  const [edges, setEdges] = React.useState<Edge[]>([]);
  // 上一次图数据的签名:轮询拿到相同数据时跳过 setState,避免整图无谓重建(拖动时
  // 才不会被 20s 轮询打断而顿挫)。只取影响渲染的字段。
  const sigRef = React.useRef("");

  React.useEffect(() => {
    let cancelled = false;
    sigRef.current = ""; // 换任务:强制下一次刷新
    const load = () => {
      api
        .explorationGraph(taskId)
        .then((g) => {
          if (cancelled) return;
          const ns = g.nodes ?? [];
          const es = g.edges ?? [];
          const sig = JSON.stringify([
            ns.map((n) => [n.id, n.type, n.state, n.priority, n.payload]),
            es.map((e) => [e.src, e.dst, e.rel]),
          ]);
          if (sig === sigRef.current) return; // 无变化 → 不重建
          sigRef.current = sig;
          setNodes(ns);
          setEdges(es);
        })
        .catch(() => {
          /* keep last good data */
        });
    };
    load();
    const timer = setInterval(load, 20000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [taskId]);

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center gap-1 self-start rounded-lg border bg-muted/40 p-1">
        <button
          type="button"
          onClick={() => setView("board")}
          className={`rounded-md px-3 py-1 text-sm font-medium transition-colors ${
            view === "board" ? "bg-background shadow-xs" : "text-muted-foreground hover:text-foreground"
          }`}
        >
          状态看板 Tree (Board / Savepoint)
        </button>
        <button
          type="button"
          onClick={() => setView("graph")}
          className={`rounded-md px-3 py-1 text-sm font-medium transition-colors ${
            view === "graph" ? "bg-background shadow-xs" : "text-muted-foreground hover:text-foreground"
          }`}
        >
          探索关系图 ({nodes.length})
        </button>
      </div>
      {view === "board" ? (
        <BoardTreePanel taskId={taskId} />
      ) : (
        <Card>
          <CardContent className="p-0">
            <ExplorationGraph nodes={nodes} edges={edges} className="h-[72vh]" />
          </CardContent>
        </Card>
      )}
    </div>
  );
}
