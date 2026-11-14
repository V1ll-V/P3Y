<div align="center">

# P3Y · 智能攻防与 CTF 解题系统

基于 **Go 后端 + `p3y-box` 隔离沙箱 + Next.js 控制台** 构建的自主解题与 Attack-Defense 攻防系统

</div>

---

## 主要设计点

1. **Phase-0 零消耗静态初检（`Precheck`）与 `Tips` 避坑卡召回**
   - 任务创建或启动时以 0 LLM Token 完成附件静态识别，提取文件哈希、架构、ELF/PE 安全保护位（NX / Canary / PIE / RELRO 等）与远程靶标地址。
   - 依据题型与静态特征标签自动检索历史沉淀的跨题避坑卡（`TipCard`），开局即注入关键绕过经验与代码模板。

2. **三层渐进式状态看板（`Board`）与毫秒级读档回滚（`Savepoint` / `Rewind`）**
   - 共享状态树 `board_items` 区分 `Fact`（线索，严格按 L1 `Title` / L2 `Summary` / L3 `Detail` 按需加载）、`Step`（短冲刺任务）、`Savepoint`（已验证里程碑）与 `Deadend`（负向排除分支）。
   - `p3y-box` 支持容器工作区硬链接快照（`Savepoint`）与原子回滚（`Rewind`），回滚时自动在对应节点挂载 `Deadend` 约束，避免智能体重复陷入同一死胡同。

3. **多角色协同与神经符号验真（`Solver` / `Helper` / `Critic` + `check` / `PyREPL`）**
   - **Solver**：保持干净上下文沿主线推进；**Helper**：隔离执行局部脏活后即时销毁，不污染主上下文；**Critic**：在连续失败或高停滞时介入进行反向证伪，打破思维惯性。
   - **独立验真与持久化 REPL**：提供 `PyREPL` 常驻交互解释器与独立 `check` 验真工具，结合远程靶机探针（Banner / PoW / RTT 识别）与多轮 PTY 伪终端控制，减少纯文本猜测。

4. **全链路 Attack-Defense 自主攻防引擎（`p3y/ad`）**
   - **Lead（战术调度）**：基于战况事件实时计算 `easy_first`、`stop_loss`、`salvage_payload`、`verify_patch` 优先级建议。
   - **Repeater（0-LLM 定时批量打靶）**：后台周期调度注册武器，按配置并发或顺序打靶、提取动态 Flag 并可选自动提交，内置连续失败自动熔断机制。
   - **Catcher（流量镜像捕手）**：对 MITM 抓包流量及样本请求进行常见攻击特征扫描（CMDi、SQLi、SSTI、LFI、反序列化、格式化字符串），提取载荷反哺己方攻防决策。
   - **Patcher（红蓝对撞验证沙箱）**：在沙箱内依次校验补丁生效、服务 SLA 连通性（`check_cmd` exit 0）与已知 PoC 利用阻断（无 Flag 泄露）。

5. **赛后经验结晶（`Tips Crystallizer`）与因果剪枝战报**
   - 任务完成验收后自动触发 `CrystallizeTips`，将有效路径、已踩过的 `Deadend` 与可复用脚本抽象为跨题 `TipCard` 与 `BoardKit`。
   - Write-up / 复盘战报严格基于真实执行日志与证据链生成，自动剔除无效试错噪音。

---

## 结构优势

- **控制面与沙箱物理隔离**：主服务 `p3y` 不挂载宿主机 Docker Socket；所有容器调度与命令执行均通过独立守护进程 `p3y-box`（令牌鉴权）隔离完成，工具容器默认以受限资源与非特权权限运行。
- **Bind-Mount 持久卷零往返拷贝**：任务工作区直接绑定宿主机目录至容器 `/work`（原始附件只读挂载 `/work/.inputs`），消除传统每次执行全量打包/解包带来的秒级延迟、体积限制与并发竞态。
- **0-LLM 确定性底座降本增效**：`Precheck` 静态化验、AD `Repeater` 周期打靶、`Catcher` 特征扫描与 `Patcher` 红蓝双验全部运行在确定性代码路径上，将 LLM 调用集中在高价值分析与利用构造。
- **Per-Task WireGuard Sidecar 与流量链路联动**：支持按任务维度挂载独立 WireGuard VPN Sidecar 接入内网赛题环境，并支持内置 MITM 代理捕获 HTTP 流量用于检索与取证。
- **单二进制嵌入式部署与现代化控制台**：前端基于 Next.js（支持静态导出直接嵌入 Go 二进制），保留暗黑/多主题预设、状态看板树（支持 L3 详情展开与一键 `Rewind`）、「武库与套件（`/function/kits`）」以及 AD 实时控制台面板。

---

## 部署步骤

### 环境要求

- **容器运行**：Docker 与 Docker Compose（推荐部署方式）
- **数据库**：PostgreSQL 16（Docker Compose 已内置）
- **源码构建（可选）**：Go `1.26+`、Node.js `20+`

---

### 方式一：Docker Compose 一键部署（本地构建）

1. **准备环境变量**

   ```bash
   cp .env.example .env
   ```

   编辑 `.env`，设置 `POSTGRES_PASSWORD`（必填），按需填写 `ANTHROPIC_API_KEY` 或 `OPENAI_API_KEY`（也可留空，首次登录后在 Web 控制台「系统 → LLM 配置」填写）。

2. **构建前端静态资源与服务端二进制**

   ```bash
   # 构建并导出 Next.js 静态前端
   cd web && npm ci && npm run build:static && cd ..
   rm -rf server/webui/dist && cp -r web/out server/webui/dist

   # 编译 Linux amd64 主服务二进制（如为 arm64 请改为 GOARCH=arm64 及 dist/arm64）
   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags embedui -trimpath -o dist/amd64/p3y ./cmd/p3y
   docker build -t p3y/p3y:latest .
   ```

3. **启动服务**

   ```bash
   docker compose up -d
   ```

   启动后访问控制台：`http://localhost:8787`（内置流量抓包代理监听 `127.0.0.1:8788`）。

---

### 方式二：完整沙箱预览环境（含 `p3y-box` 执行器与工具镜像）

如需启用完整 CTF / AD 隔离容器沙箱与 WireGuard Sidecar，使用 `docker-compose.ctf-preview.yml`：

1. **构建主应用、`p3y-box` 与工具镜像**

   ```bash
   # 编译前端与主服务镜像（如方式一已构建可直接 tag 为 v0.9.0）
   cd web && npm ci && npm run build:static && cd ..
   rm -rf server/webui/dist && cp -r web/out server/webui/dist
   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags embedui -trimpath -o dist/amd64/p3y ./cmd/p3y
   docker build -t p3y/p3y:v0.9.0 .

   # 编译执行器二进制并构建沙箱/VPN/工具镜像
   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o dist/amd64/p3y-box ./cmd/p3y-box
   docker build -f Dockerfile.ctf-runner -t p3y/p3y-box:0.9.0 .
   docker build -f Dockerfile.ctf-wg -t p3y/p3y-box-wg:0.9.0 .
   docker build -f Dockerfile.ctf-tools -t p3y/p3y-box-tools:20261113 .
   ```

2. **配置预览环境变量 `data/ctf-preview.env`**

   ```env
   P3Y_PREVIEW_DB_PASSWORD=change-me-strong-password
   P3Y_BOX_TOKEN=replace-with-at-least-24-chars-random-token
   P3Y_CTF_FLAG_PREFIXES=flag,ctf,p3y
   ```

3. **启动编排**

   ```bash
   docker compose --env-file data/ctf-preview.env -p p3y-preview -f docker-compose.ctf-preview.yml up -d
   ```

   访问控制台：`http://localhost:8789`。

---

### 方式三：本地源码开发与验证

1. **启动 PostgreSQL 并配置连接串**

   ```bash
   export P3Y_PG_DSN="postgres://p3y:p3y@127.0.0.1:5432/p3y?sslmode=disable"
   ```

2. **启动前后端开发服务**

   ```bash
   # 安装前端依赖
   cd web && npm ci && cd ..

   # 方式 A：使用内置脚本同时拉起后端 (:8787 / 代理 :8788) 与前端热更新 (:5173)
   ./dev.sh

   # 方式 B：分终端启动（可选启动 p3y-box 沙箱守护进程）
   go run ./cmd/p3y-box -addr 127.0.0.1:8790
   go run ./cmd/p3y -addr :8787 -proxy 127.0.0.1:8788
   cd web && npm run dev
   ```

3. **运行测试与类型检查**

   ```bash
   # 后端全量测试（需设置 P3Y_PG_DSN 指向空测试库）
   go test -p 1 -count=1 ./...

   # 前端类型检查与生产构建
   cd web && npx tsc --noEmit && npm run build
   ```
