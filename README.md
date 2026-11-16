# P3Y

面向渗透测试、CTF 自动求解、Attack-Defense 实时攻防与多平台自动化测评的安全智能体系统。核心由 **Go 控制面（`cmd/p3y`）**、**物理隔离沙箱执行器（`cmd/p3y-box`）** 与 **嵌入式控制台（`web/`）** 组成，围绕“控制面与执行面解耦、图谱黑板持久化状态、0-LLM 确定性预处理与单模型攻坚纠偏”构建。

---

## 系统架构

```text
  浏览器控制台 (Next.js, embedui)
               │  HTTP / SSE / JWT
               ▼
  ┌───────────────────────────────────────────────┐
  │ cmd/p3y 控制面                                 │
  │  ├── 调度引擎: Planner / Worker / 优雅超时收尾  │
  │  ├── 业务域:   CTF / AD / Benchmark / Intercept │
  │  ├── LLM 池:   多 Profile Failover + llmrec 审计│
  │  ├── MITM代理: 127.0.0.1:8788 流量捕获与取证    │
  │  └── PostgreSQL: 探索图 / 看板 / 任务 / 存档快照 │
  └──────────────────────┬────────────────────────┘
                         │  HTTP + Bearer Token（无 Docker Socket）
                         ▼
  ┌───────────────────────────────────────────────┐
  │ cmd/p3y-box 执行面（独立守护进程）              │
  │  ├── 工具容器: /work (rw) + /work/.inputs (ro)  │
  │  ├── 交互/作业: PTY 伪终端、后台任务与超时隔离    │
  │  ├── 快照引擎: /work 硬链接 Savepoint / Rewind  │
  │  └── VPN 网关:  p3y-box-vpn-<hash> 共享隧道     │
  └───────────────────────────────────────────────┘
```

---

## 核心设计与结构特点

### 1. 控制面与沙箱物理隔离
- **最小权限边界**：主服务 `p3y` 本身不挂载宿主机 `/var/run/docker.sock`，所有容器生命周期、命令执行与网络挂载均通过令牌鉴权的 `p3y-box`（`ctfrunner`）代理完成；工作容器默认按受限资源与非特权参数启动。
- **Bind-Mount 持久卷直挂**：任务工作区直接绑定到容器 `/work`，原始题目附件以只读模式挂载至 `/work/.inputs`，消除每次执行全量打包拷贝的延迟、体积限制和并发竞态。
- **同配置共享 VPN Sidecar**：支持 WireGuard（`.conf`）与 OpenVPN（`.ovpn`），并按配置内容 SHA-256 哈希在同配置并发任务间复用同一个 `p3y-box-vpn-<hash[:16]>` 隧道容器（串行建链与健康探测，全部关联容器退出后再回收），避免同一客户端证书多任务并发拨号互踢。

### 2. 图谱黑板驱动的多轮推进与跨任务继承
- **状态落在探索图而不是堆在单轮上下文里**：引擎将目标（`goal`）、约束/提示（`hint`）、子意图（`intent`）、客观事实（`fact`）、漏洞结论（`finding`）与冷折叠摘要（`digest`）持久化于 PostgreSQL（`db.ExplorationStore`），Worker 按轮领取轻量意图并写回结构化节点，避免单条长对话爆炸导致失忆或偏航。
- **渐进式披露与冷图压缩**：看板与探索记录严格区分 **L1 标题 / L2 摘要 / L3 全文详情（`board_read_detail`）**；冷图折叠（`agent/coldgraph.go`）与可选 `noa` 压缩把过期细节收拢到节点详情中；旁路问答（`sidequestion`）在不打断主任务步进的前提下响应异步追问。
- **只读血缘继承（`SourceTaskIDs`）**：新任务可声明继承前序任务的只读黑板视图，直接查阅其已确认资产、漏洞事实、冷摘要与终态意图总结，但保留边界隔离（源任务节点只读，不混淆当前任务的写权限与执行路径）。
- **多源模型高可用（`llmpool`）与审计（`llmrec`）**：支持任务级多 LLM Profile 顺序故障切换、建连/流式退避重试、以及任务级预算超时时的优雅收尾机制；所有原生 LLM 请求与响应持久化落库 `llm_records` 便于排查。

### 3. CTF 单模型攻坚闭环（初检 / 快照回滚树 / 旁路协查 / 反向证伪）
围绕复杂单题（尤其是 Pwn / Reverse / 复杂 Web）设计了一套确定性验真与防陷入死胡同机制：
- **Phase-0 零消耗初检与 `TipCard` 经验结晶**：起跑前用确定性脚本提取附件哈希、架构、ELF/PE 保护位（NX / Canary / PIE / RELRO 等）与目标地址（`ctf/precheck.go`）；按特征标签召回历史跨题避坑卡注入开局；验收完成后由 `CrystallizeTips` 自动将有效解法与避坑经验沉淀为新 `TipCard`。
- **动静合一主攻 + 旁路协查（`ask_helper`）**：针对 Pwn/Reverse，Planner 在轻量 `recon` 后仅派发 **1 个动静合一主攻 Worker** 在共享 `/work` 与连续上下文中打通静态分析、GDB 调试与利用；重型反编译、海量符号提取或编写交互脚本 `interact.py` 等脏活通过 `ask_helper`（`agent/helper.go`）派给短生命周期临时会话处理，只带回浓缩结论与落盘脚本，不污染主攻上下文。
- **Savepoint / Rewind / Deadend 状态树与停滞分叉（`plateau_fork`）**：突破关键里程碑且经过 0-LLM `check_cmd` 验真后，调用 `board_mark_savepoint` 冻结 `/work` 硬链接快照并使用 `board_save_kit` 沉淀套件；分支走死时调用 `board_rewind` 原子回滚工作区，并在该存档点下追加单行 `Deadend` 负向约束（`agent/board_tools.go`）。同一存档点回滚达 `2` 次即判定停滞，触发 `plateau_fork`（`agent/plateau_fork.go`）在 `/work/.forks/...` 隔离工作区并发跑 `2~3` 条竞争假设分支并合入胜出者。
- **连续失败自动证伪（`Critic`）与神经符号工具**：`ctfCriticHooks`（`agent/critic.go`）监控核心执行工具，**连续 3 次失败后自动拦截盲目微调参数并插入 1 轮反向证伪审讯**，指出最可能假的前提并要求执行最小对照实验，例如本地/远端行为与 Hex 对齐工具 **`diff_local_remote`**、Web 批量差分聚类工具 **`http_fuzz_diff`**、以及持久化符号计算环境 **`PyREPL`**（`ctf/pyrepl.go`、`agent/neuro_tools.go`）。
- **因果裁剪战报（`ctf/wp.go`）**：基于真实命令记录与探索图谱证据链生成 Write-up，自动剪除已 `Rewind` 放弃的试错噪音。

### 4. 多平台零交互自动化测评（`benchmark` + `server/benchmark.go`）
- **多平台统一接入**：原生支持 **TSecBench（REST + `.ovpn`）**、**CTF2 / DASCTF（MCP）** 与 **Generic MCP（自定义 MCP + `Skill.zip` 注入）**。
- **资源与状态调度闭环**：自动同步题库与附件、管控平台并发容器配额、主动探测并回收残留环境、容器临近过期时自动续期，并在平台限流/维护时进入全局冷却。
- **超时/异常自动冷却重试 + 跨轮记忆继承**：默认单题预算 `5400s`（90 分钟，创建前与运行中均可通过 `PATCH /api/benchmarks/{id}` 动态调整）；遇到预算超时或靶场/子任务异常时，进入阶梯冷却（`30s -> 60s -> 120s`，上限 3 次）后自动重新入队，重开子任务通过 `history_task_ids -> SourceTaskIDs` 自动继承前序任务的全部黑板探索记忆；所有测评子任务同时在「任务」列表中可见并携带 `测评 #N` 跳转标记，方便独立审计。

### 5. Attack-Defense 自主攻防（`ad`）与安全拦截（`intercept`）
- **AD 引擎（`p3y/ad`）**：由态势推演 `Lead`、后台 0-LLM 并发定期打靶并内置失败熔断的 `Repeater`、对抓包与镜像流量进行常见利用载荷特征提取的 `Catcher`、以及在沙箱中同时验证补丁生效 + 服务 SLA 连通（`check_cmd`）+ PoC 阻断的 `Patcher` 组成。
- **人工审批边界（`intercept`）**：支持按资产/规则匹配拦截敏感工具调用，挂起等待人工放行或超时兜底处理；支持内置 HTTP 抓包代理流量检索与证据联动（`traffic` / `evidence`）。

---

## 目录结构速览

| 目录 | 职责 |
| :--- | :--- |
| `cmd/p3y` / `cmd/p3y-box` | 主控制面二进制入口 / 独立容器沙箱守护进程入口 |
| `server/` | HTTP/SSE API 路由、任务与并发调度引擎（`engine.go`）、`BenchmarkManager` |
| `agent/` | Planner / Worker 编排、工具目录、`Critic`、`ask_helper`、`plateau_fork`、`board_tools` |
| `ctf/` / `ctfrunner/` | CTF Precheck、Tips 召回与结晶、`PyREPL`、WP 生成 / Docker 容器、Savepoint、VPN 引擎 |
| `benchmark/` | TSecBench、CTF2 MCP、Generic MCP 适配器与 `Skill.zip` 解析器 |
| `ad/` | Attack-Defense `Lead` / `Repeater` / `Catcher` / `Patcher` |
| `db/` | PostgreSQL Schema 与迁移、探索图存储、只读源继承查询、测评及通知持久化 |
| `llmpool/` / `llmrec/` | 多配置 LLM 健康度与 Failover 池 / 全量原生请求响应审计 |
| `traffic/` / `intercept/` | MITM HTTP 抓包与归档 / 高危操作审批规则与上下文 |
| `sidequestion/` / `notify/` | 异步旁路问答捕获 / 多渠道事件聚合投递 |
| `web/` | Next.js + React + Tailwind 前端控制台（支持静态导出并通过 `embedui` 嵌入二进制） |

---

## 部署与运行

### 环境要求
- **容器部署**：Docker & Docker Compose（内置 PostgreSQL 16）
- **源码构建 / 开发（可选）**：Go `1.26+`、Node.js `20+`

---

### 方式一：标准 Docker Compose 部署

1. **配置环境变量**

   ```bash
   cp .env.example .env
   ```

   编辑 `.env`，设置必填的 `POSTGRES_PASSWORD`；LLM Key 可填在环境变量中，也可留空并在首次登录后于控制台「系统 → LLM 配置」页面填写。

2. **构建前端内嵌资源与服务端镜像**

   ```bash
   cd web && npm ci && npm run build:static && cd ..
   rm -rf server/webui/dist && cp -r web/out server/webui/dist

   # 编译 Linux amd64 主二进制（arm64 请将 GOARCH 改为 arm64 并输出到 dist/arm64/p3y）
   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags embedui -ldflags='-s -w' -o dist/amd64/p3y ./cmd/p3y
   docker build -t p3y/p3y:latest .
   ```

3. **启动**

   ```bash
   docker compose up -d
   ```

   控制台访问 `http://localhost:8787`（内置抓包代理监听 `127.0.0.1:8788`）。

---

### 方式二：完整 CTF / AD / Benchmark 沙箱环境

启用隔离沙箱执行器 `p3y-box`、工具容器镜像以及 WireGuard / OpenVPN Sidecar（编排文件：`docker-compose.ctf-preview.yml`）：

1. **构建主镜像、`p3y-box` 与底层容器镜像**

   ```bash
   # 1) 构建主应用镜像 p3y/p3y:v0.91
   cd web && npm ci && npm run build:static && cd ..
   rm -rf server/webui/dist && cp -r web/out server/webui/dist
   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags embedui -ldflags='-s -w -X main.version=v0.91' -o dist/amd64/p3y ./cmd/p3y
   docker build -t p3y/p3y:v0.91 .

   # 2) 构建执行器 p3y-box 与 VPN / 工具镜像
   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags='-s -w' -o dist/amd64/p3y-box ./cmd/p3y-box
   docker build -f Dockerfile.ctf-runner -t p3y/p3y-box:0.9.0 .
   docker build -f Dockerfile.ctf-wg -t p3y/p3y-box-wg:0.9.0 .
   docker build -f Dockerfile.ctf-tools -t p3y/p3y-box-tools:20261113 .
   ```

2. **创建环境变量文件 `data/ctf-preview.env`**

   ```env
   P3Y_PREVIEW_DB_PASSWORD=change-me-strong-password
   P3Y_BOX_TOKEN=replace-with-at-least-24-chars-random-token
   P3Y_CTF_FLAG_PREFIXES=flag,ctf,p3y
   ```

3. **启动服务**

   ```bash
   docker compose --env-file data/ctf-preview.env -p p3y-preview -f docker-compose.ctf-preview.yml up -d
   ```

   控制台访问 `http://127.0.0.1:8789`。

---

### 方式三：本地源码开发与测试

1. **配置 PostgreSQL 连接串**

   ```bash
   export P3Y_PG_DSN="postgres://p3y:p3y@127.0.0.1:5432/p3y?sslmode=disable"
   ```

2. **启动开发服务**

   ```bash
   cd web && npm ci && cd ..

   # 一键拉起后端 (:8787 / 代理 :8788) 与前端热更新 (:5173)
   ./dev.sh
   ```

   如需本地联调沙箱执行器，可另开终端运行：

   ```bash
   go run ./cmd/p3y-box -addr 127.0.0.1:8790
   ```

   跨平台构建发布包可使用仓库内置脚本：`./build.sh` 或 `./build.sh --release`。

3. **运行测试与前端校验**

   ```bash
   # 后端测试（需将 P3Y_PG_DSN 指向独立的测试数据库）
   go test -p 1 -count=1 ./...

   # 前端类型与静态导出构建
   cd web && npx tsc --noEmit && npm run build:static
   ```
