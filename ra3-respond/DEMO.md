# RA3 威胁响应系统 — 演示说明

一句话:**这是一个面向 5G 网络的自动化告警响应"控制平面"。上游检测到攻击后把告警交给它,它用 LLM(function calling)从预定义动作目录里挑选并排序处置措施,通过 MCP 协议把每个动作交给一次性 Docker 容器真实执行,全过程存库可审计。**

---

## 1. 它解决什么问题

上游(RA1)只负责"发现攻击",但**发现之后该怎么处置**是另一回事。传统做法是写死一堆 if-else 规则。RA3 换了思路:

- 把当前威胁的**具体指标**(如半开连接数、包速率、源 IP 数)+ 9 个可选动作,一起交给 LLM
- LLM 判断:**做哪些、按什么顺序、参数填多少、为什么**
- 系统再把这些决策**真正执行**(在隔离的 Docker 容器里),并存库

价值:处置策略是**指标驱动、可解释、可扩展**的,而不是死规则。

---

## 2. 一条告警进来,系统怎么处理(核心流程)

```
①  告警进来        client ──POST /report──▶  {attack_type, severity, metadata:{指标}}
        │
②  落库 + 决策      RA3 存 incident(pending)→ 决策引擎读指标 → 选动作
        │                (例:half_open=48000 → SYN cookie 开 120分钟;
        │                 critical → 强制告警运维; 每次必记审计日志)
        │
③  MCP 调用        RA3(MCP client)──▶ MCP server:逐个 CallToolRequest
        │
④  Docker 执行      MCP server 为每个动作 docker run 一个一次性容器
        │                (--network none, 内存受限, 用完 --rm 销毁)
        │
⑤  回传 + 落库      执行结果存 responses.execution_results;incident → resolved
        │
⑥  返回调用方       {selected_actions, execution_results, llm_reasoning}
```

**两个平面**:
- **决策平面**(LLM):决定"做什么"
- **执行平面**(MCP + Docker):真正"去做",且每个动作在隔离容器里跑

---

## 3. 技术栈

| 组件 | 技术 |
|------|------|
| API 服务 | FastAPI(async)+ PostgreSQL 16 + SQLAlchemy 2.0 |
| 决策引擎 | OpenAI 兼容 Responses API(function calling);演示时用内置 `mock` 规则,可无缝切真实模型 |
| 执行 | MCP(Model Context Protocol)server 暴露 9 个动作;每个动作在一次性 Docker 容器执行 |
| 编排 | Docker Compose 一键启动(db / server / mcp / executor / client) |

9 个动作:`enable_syn_cookie`、`rate_limit`、`block_ip`、`set_connection_timeout`、
`close_unnecessary_ports`、`enable_http_rate_limit`、`alert_operator`、`log_incident`、
`share_threat_intel`。

---

## 4. 现场演示:一条命令跑通全流程

先确保服务在跑:
```bash
docker compose up -d db mcp server
```

然后运行演示脚本(可换攻击类型):
```bash
./scripts/demo_flow.sh SYN_Flood
```

它会把**一条告警的完整处理过程**分 4 步打印出来。演示时按下面"看点"逐步讲解:

| 步骤 | 屏幕上显示 | 你要讲的点 |
|------|-----------|-----------|
| **STEP 1** 告警进来 | 选出的动作 + 每个动作的执行结果 + 决策理由 | "系统读到 half_open=xxx,于是选了 SYN cookie,并说明了理由" |
| **STEP 2** MCP 调用 | 多条 `CallToolRequest` | "每个动作都通过 MCP 协议被真实调用了一次" |
| **STEP 3** Docker 执行 | 多组 `create→start→die→destroy` | "每个动作在一个独立容器里执行,用完即销毁" |
| **STEP 4** 落库 | `status=resolved, actions_chosen == actions_executed` | "决策和执行结果都存进了数据库,可审计" |

**判断正确的标准**:4 步证据齐全,且 STEP 4 的 `actions_chosen == actions_executed`。

---

## 5. 想让观众更直观?对比不同攻击

依次跑几种攻击,展示"决策因威胁而异":
```bash
./scripts/demo_flow.sh SYN_Flood      # → enable_syn_cookie
./scripts/demo_flow.sh UDP_Flood      # → rate_limit(pps 随 packet_rate 变化)
./scripts/demo_flow.sh HTTP_Flood     # → enable_http_rate_limit (+ block_ip)
./scripts/demo_flow.sh SYN_Scan       # → block_ip + close_ports(low 级不告警运维)
```

同一套系统,对不同威胁给出不同且合理的处置——这就是"智能决策"的体现。

---

## 6. 也可以用浏览器演示(更可视化)

打开 **http://localhost:8000/docs**,在 `POST /report` 里 "Try it out" 填入告警,
点 Execute,直接看到返回的 `selected_actions` 和 `execution_results`。

---

## 7. 现在完成到什么程度

- ✅ 完整的告警 → 决策 → 执行 → 落库 闭环,一条命令可复现
- ✅ LLM function calling 决策(支持真实模型 / mock 离线两种)
- ✅ MCP 协议把决策与执行解耦
- ✅ 每个动作在一次性、隔离的 Docker 容器中执行
- ✅ 全过程持久化,可查询、可审计(`GET /incidents`)
- ✅ 错误处理:非法威胁类型、Normal 短路、LLM/DB/MCP 失败均有处理

> 说明:当前动作执行为"模拟处置"(打印效果 + 返回结构化结果),便于安全演示。
> 接真实防火墙/限速只需替换 `executor/handlers.py` 里的实现,架构不变。
