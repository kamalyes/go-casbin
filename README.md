# go-casbin 企业级权限管理系统

## 🎯 项目简介

go-casbin 是基于官方 Casbin v3 的**企业级权限接入层**，面向多租户 SaaS、多副本部署和网关高频鉴权场景；权限模型与匹配语义由官方引擎提供，本库补充网关决策原语、存储保护、域身份绑定与可观测能力，并提供 GORM / Kafka / NATS / Redis 四个独立适配器

业务方只需导入 `github.com/kamalyes/go-casbin`，即可使用本库的工程化能力，以及再导出的官方类型与构造器

### 核心特性

- 📦 **多种权限模型**：复用官方 PERM 模型，支持 ACL、RBAC、ABAC 与多租户域隔离
- 🚀 **内存决策与结果缓存**：基于官方 `SyncedCachedEnforcer`，复用结果缓存、策略分区索引与 matcher 编译缓存
- 🔀 **网关三路决策**：提供匿名放行、认证免鉴权和正常鉴权原语，前两类策略独立保存在内存中
- 🛡️ **存储故障保护**：内置熔断与重试，保护策略加载和持久化；内存鉴权无需等待存储
- 🔒 **独立全拒开关**：通过 `WithDenyAll(true)` / `SetDenyAll(true)` 拒绝正常鉴权请求，返回 `ErrDenyAll`
- 🏢 **多租户接入**：支持域身份绑定、按租户独立表或 Redis 键前缀，以及过滤加载
- 🔄 **多副本策略同步**：支持 `WatcherEx` 回调兜底与周期重载，通知持久化能力按中间件选择
- 📊 **监控与健康检查**：提供原子计数指标、决策耗时、熔断状态检查和结构化日志接口
- 🔧 **按需引入依赖**：根模块唯一直接第三方依赖为 Casbin；适配器各自独立成模块，按需安装

> 迁移与接入前可先阅读 [注意事项与设计决策](#注意事项与设计决策)，了解官方行为、适配器配置及性能取舍

## 💡 为什么采用企业级接入层

### 复用官方引擎

PERM 模型、matcher 语法、RBAC / ABAC 语义均由官方 Casbin v3 实现，标准 `model.conf` / `policy.csv` 可继续使用；从旧版自研引擎迁移时，需检查多策略段与 `eval` 表达式，具体差异见后文迁移说明

官方已有的 context 执行器、策略事务、结果缓存和策略分区索引，通过本包再导出的类型与构造器接入；企业级 `Enforcer` 内嵌 `SyncedCachedEnforcer`，其管理与 RBAC API 可通过方法提升直接调用

### 工程化能力对照

| 场景 | 官方接口或行为 | go-casbin 的接入能力 |
| --- | --- | --- |
| 关闭鉴权 | `EnableEnforce(false)` 表示全部放行 | 保持官方语义；应急全拒另用 `WithDenyAll(true)` / `SetDenyAll(true)` |
| 网关三路决策 | 业务方组织认证与鉴权流程 | 提供 `IsPublicPolicy` / `IsAuthSkipPolicy` 内存策略原语 |
| 存储故障保护 | 由业务方接入 | 提供熔断、重试及 `Guarded` 包装入口 |
| 指标与健康检查 | 由业务方接入 | 提供 `Monitor()` / `HealthCheck()` / `LogMetrics()` |
| 租户与域名绑定 | 由业务方组织策略 | 提供 `SyncTenantHostBindings` / `ResolveTenantByHost` |
| `WatcherEx` 回调 | `SetWatcher` 不自动安装通用回调 | 构造执行器时补充策略重载回调 |
| 无存储时加载策略 | `LoadPolicy` 可能触发空指针 panic | 返回 `ErrNoAdapter` |

`EnableEnforce(false)` 在本库中同样表示关闭鉴权、全部放行；带结果缓存时，切换后还需调用 `InvalidateCache()`，避免沿用旧决策；应急拒绝正常鉴权请求使用独立的 `DenyAll` 开关，详见 [官方行为说明](#注意事项与设计决策)

### 依赖设计

根模块的唯一直接第三方依赖为 `github.com/casbin/casbin/v3`，其传递依赖仍会进入依赖树；日志、熔断和重试由本包提供最小实现，不绑定 `go-toolbox` 或具体日志库

四个适配器只依赖官方接口、`adapter/base` 与各自客户端，不依赖根模块，也可供原生官方 Casbin 使用

## 🏗️ 架构设计

### 架构分层图

```mermaid
flowchart TB
    %% ==================== 业务接入层 ====================
    subgraph BIZ["业务接入层"]
        Gateway["网关<br/>高频鉴权入口"]
        BizApp["业务服务<br/>嵌入式 SDK"]
        AdminCLI["管理面 / CLI<br/>策略变更入口"]
    end

    %% ==================== 门面层 ====================
    subgraph FACADE["go-casbin 门面层 · 官方不提供的工程化能力"]
        direction TB
        Gate["全拒开关 WithDenyAll<br/>打开后正常鉴权返回 ErrDenyAll"]
        ThreeWay["三路决策原语<br/>IsPublicPolicy / IsAuthSkipPolicy<br/>内存态策略 · 带结果缓存 · 不落库"]
        Identity["域身份绑定<br/>租户 ↔ 域名 · 走独立 p2 段"]
        Guard["Guarded 存储保护<br/>熔断 + 重试 · 只包存储调用"]
        Obs["可观测<br/>决策指标 / 健康检查<br/>WithMetrics 可关"]
        ReExport["类型再导出<br/>业务方只 import 一个包"]
    end

    %% ==================== 官方引擎 ====================
    subgraph CORE["官方 casbin v3 引擎 · 直接复用，不重写"]
        direction TB
        Synced["SyncedCachedEnforcer<br/>并发安全 + 结果缓存<br/>版本号 O(1) 失效"]
        Index["PolicyIndex<br/>策略分区，只扫本请求分片"]
        Matcher["matcher<br/>AST 编译缓存 · govaluate"]
        RoleMgr["RoleManager<br/>角色继承 + HasLink 缓存"]
        Txn["策略管理 API<br/>增删改 / 批量 / 过滤"]
    end

    %% ==================== 适配器层 ====================
    subgraph ADP["适配器层 · 各自独立 module，不依赖根模块"]
        direction TB
        Base["adapter/base<br/>事件格式 · Notifier 骨架<br/>过滤归一化 · 日志接口"]
        Store["存储适配器<br/>gorm (MySQL/PG/SQLite) · redis<br/>persist.Adapter 族"]
        Notify["通知适配器<br/>kafka · nats · redis<br/>persist.WatcherEx"]
    end

    %% ==================== 外部 ====================
    subgraph EXT["存储与中间件"]
        DB[("MySQL / PostgreSQL<br/>SQLite")]
        Redis[("Redis")]
        MQ[["Kafka / NATS"]]
    end

    %% ==================== 读路径（决策）====================
    Gateway -->|"每请求"| ThreeWay
    BizApp -->|"Enforce / EnforceCtx"| Gate
    ThreeWay -->|"都未命中才真鉴权"| Gate
    Gate --> Obs
    Obs --> Synced
    Synced -->|"命中缓存 · 直接返回"| Gateway
    Synced -->|"miss"| Index
    Index --> Matcher
    Matcher --> RoleMgr

    %% ==================== 写路径（策略变更）====================
    AdminCLI --> Guard
    Identity --> Guard
    Guard --> Txn
    Txn --> Store
    Store --> DB
    Store --> Redis
    Txn -.->|"变更后广播"| Notify
    Notify --> MQ

    %% ==================== 同步回路 ====================
    MQ -.->|"其余副本收到"| Notify
    Notify -.->|"Dispatch · 过滤自环"| Base
    Base -.->|"回调 LoadPolicy"| Synced

    %% ==================== 启动加载 ====================
    Store -.->|"启动 / 分片懒加载<br/>LoadFilteredPolicy 条件下推"| Synced

    %% ==================== 依赖 ====================
    Base --- Store
    Base --- Notify
    ReExport -.->|"业务方拿到官方全部 API"| CORE
```

权限决策全程在内存中完成，0 次存储往返；策略加载和持久化才触达存储，`LoadPolicy` / `SavePolicy` 自动经过熔断与重试，其他管理 API 可用 `Guarded` 包裹

### 模块依赖图

依赖方向是刻意设计的：**根模块只依赖 casbin 官方，适配器只依赖 `adapter/base`、官方接口与各自客户端**；适配器没有编译期依赖指向根模块，因此整条链路对原生官方 casbin 同样可用

```mermaid
flowchart LR
    Upstream["casbin/casbin/v3<br/>官方"]

    Root["go-casbin<br/>根模块 · 门面层"]
    Monitor["go-casbin/monitor<br/>指标 + 健康检查<br/>零依赖、不打日志"]

    Base["adapter/base"]
    Gorm["adapter/gorm"]
    Kafka["adapter/kafka"]
    Nats["adapter/nats"]
    RedisA["adapter/redis"]

    GormLib["gorm.io/gorm"]
    Sarama["IBM/sarama"]
    NatsLib["nats-io/nats.go"]
    RedisLib["redis/go-redis"]

    Root --> Upstream
    Root --> Monitor

    Base --> Upstream
    Gorm --> Base
    Kafka --> Base
    Nats --> Base
    RedisA --> Base

    Gorm --> GormLib
    Kafka --> Sarama
    Nats --> NatsLib
    RedisA --> RedisLib

    Root -.->|"运行期注入<br/>只认官方接口"| Gorm
    Root -.-> Kafka
    Root -.-> Nats
    Root -.-> RedisA
```

实线是编译期依赖，虚线是运行期按官方 `persist.Adapter` / `persist.Watcher` 接口注入 —— 所以用哪个装哪个，不用的不会进你的依赖树

### 网关三路决策流程

```mermaid
flowchart LR
    Req["请求<br/>path + method"] --> P{"IsPublicPolicy<br/>匿名放行？"}
    P -->|"命中 · 93ns"| Allow1["放行<br/>不验 JWT"]
    P -->|"未命中 · 112ns"| Auth{"JWT 认证"}
    Auth -->|"失败"| Deny1["401"]
    Auth -->|"通过"| Skip{"IsAuthSkipPolicy<br/>免鉴权？"}
    Skip -->|"命中"| Allow2["放行<br/>不查权限"]
    Skip -->|"未命中"| Enf{"Enforce<br/>查权限"}
    Enf -->|"allow · 约 100ns"| Allow3["放行"]
    Enf -->|"deny"| Deny2["403"]
```

前两类策略只存在于内存，不写入适配器，每次启动从代码重新加载；三次策略判定合计约 324 ns，不含 JWT 认证耗时，基准条件见后文「性能优化」

网关需自行完成 JWT 认证；如需整体停服，应在三路决策前检查 `IsDenyAll()`，完整调用顺序见 [网关示例](examples/gateway/main.go)

### 核心组件

| 组件 | 位置 | 职责 |
| --- | --- | --- |
| `Enforcer` | [enforcer.go](enforcer.go) | 门面入口，内嵌官方 `SyncedCachedEnforcer`，官方 API 经方法提升直接可用 |
| 三路决策原语 | [publicpolicy.go](publicpolicy.go) | 匿名放行 / 认证免鉴权，独立带缓存的内存执行器 |
| 域身份绑定 | [identity.go](identity.go) | 租户 ↔ 域名的正向校验与反向查询，共用一份 `p2` 策略 |
| 熔断 / 重试 | [breaker.go](breaker.go) · [retry.go](retry.go) | 零依赖最小实现，只保护触达存储的调用 |
| 日志接口 | [logger.go](logger.go) | 4 个 ctx 版键值方法，`go-logger` 天然满足 |
| 可观测 | [monitor/](monitor/) | 原子计数指标 + 健康检查，不依赖任何日志库 |
| 通知骨架 | [adapter/base/](adapter/base/) | `WatcherEx` 全部广播方法 + 回调管理 + 自环过滤 |

### 仓库结构

```
go-casbin/
├── casbin.go          官方类型与构造器的再导出门面
├── enforcer.go        企业级 Enforcer（内嵌 *SyncedCachedEnforcer）
├── options.go         WithXxx 选项
├── publicpolicy.go    匿名放行 / 认证免鉴权原语
├── identity.go        域身份绑定（租户 ↔ 域名）
├── logger.go          最小日志接口（零依赖）
├── breaker.go         熔断器（零依赖）
├── retry.go           重试器（零依赖）
├── monitor/           指标与健康检查（不打日志、无依赖）
└── adapter/           各自独立的 go module
    ├── base/          公共骨架：事件格式、Notifier、过滤归一化、日志接口
    ├── gorm/          persist.Adapter + Batch/Updatable/Filtered + 分片索引对齐
    ├── kafka/         persist.WatcherEx，消息持久化 + 可回溯
    ├── nats/          persist.WatcherEx，可选 JetStream 持久化
    └── redis/         persist.Adapter + Pub/Sub WatcherEx
```

## 📖 权限模型对比：ACL vs RBAC vs ABAC vs PBAC

### 核心区别一览

| 模型 | 判断依据 | 典型表达 | 适用场景 |
| --- | --- | --- | --- |
| ACL | 用户与资源直接绑定 | `r.sub == p.sub && r.obj == p.obj && r.act == p.act` | 用户少、权限简单 |
| RBAC | 用户所属角色及角色权限 | `g(r.sub, p.sub) && keyMatch2(r.obj, p.obj) && r.act == p.act` | 角色明确的业务系统 |
| RBAC Domain | 域内角色与权限 | `g(r.sub, p.sub, r.dom) && r.dom == p.dom && ...` | 多租户 SaaS |
| ABAC 属性匹配 | 请求主体、资源或环境属性 | `r.sub == r.obj.Owner` | 资源所有者、属性条件判断 |
| ABAC 规则策略 / PBAC | 策略中保存的条件表达式 | `eval(p.sub_rule) && ...` | 需要动态管理条件规则 |

PBAC 在这里指由策略驱动的权限控制方式，ABAC 规则策略是其中一种实现；以上模型均复用官方引擎，本仓当前提供的模型文件为 [RBAC](resources/rbac_model.conf) 和 [多租户 RBAC + 域身份绑定](resources/rbac_with_domains_model.conf)

### 多租户与域身份绑定

多租户模型使用 `r / p / g / e / m` 进行常规权限判定，使用独立的 `r2 / p2 / e2 / m2` 处理租户与域名绑定；官方一次决策遍历一种策略类型，域身份绑定不能与普通权限策略混在同一条 matcher 中

- `SyncTenantHostBindings`：同步租户绑定的域名
- `EnforceTenantHostBinding`：校验租户、用户与域名的绑定
- `ResolveTenantByHost`：按域名反查租户
- `ListTenantHostBindings`：列出租户已绑定的域名

具体模型见 [rbac_with_domains_model.conf](resources/rbac_with_domains_model.conf)，迁移约束见 [注意事项与设计决策](#注意事项与设计决策)

## ⚡ 性能优化

以下沿用现有基准记录：Apple M4 / Go 1.26，`-benchtime=2s -count=3 -cpu=10` 取中位数；单次运行噪声约 ±25%，数字用于说明相对开销

### 决策热路径：这一层贵了多少

| | 耗时 | 相对官方 |
| --- | ---: | ---: |
| 官方 `SyncedCachedEnforcer`，缓存命中 | 64.8 ns | 基线 |
| 本层 `Enforce`，缓存命中 | 102.1 ns | +58% |
| 本层 `Enforce`，缓存命中 + `WithMetrics(false)` | 69.1 ns | **+6.6%** |
| 官方，缓存未命中（1000 条策略） | 204 µs | 基线 |
| 本层，缓存未命中（1000 条策略） | 207 µs | +1.4% |

把开销拆开看就清楚了：

| 分解项 | 成本 |
| --- | ---: |
| `time.Now()` + `time.Since()` | 42.9 ns（macOS；Linux 通常约 20 ns） |
| `monitor.RecordEnforce` 原子计数 | 2.3 ns |
| `ctx.Err()` 取消检查 | 0.2 ns |

**门面层的结构性开销约 4 ns，其余主要来自决策耗时采集**；缓存未命中时，决策本身需要几百微秒，这部分开销占比很小；缓存命中的高频路径可用 `WithMetrics(false)` 降低开销，代价是关闭决策指标，基于错误率的健康检查也将缺少数据

### 网关三路决策性能

| | 耗时 | 分配 |
| --- | ---: | ---: |
| 完整判定（公共未命中 → 免鉴权未命中 → 鉴权） | 324 ns | 17 |
| 其中 `IsPublicPolicy` 命中 | 93 ns | 6 |
| 其中 `IsPublicPolicy` 未命中 | 112 ns | 7 |
| 未配置公共策略时的短路 | 1.8 ns | 0 |

内存态策略执行器**必须开结果缓存**；最初使用不带缓存的 `SyncedEnforcer`，每个请求都要跑一遍完整 matcher：

| | 改之前 | 改之后 |
| --- | ---: | ---: |
| `IsPublicPolicy` 未命中 | 1971 ns / 32 allocs | 112 ns / 7 allocs |
| 完整三路判定 | 3852 ns / 61 allocs | **324 ns / 17 allocs** |

这两类策略在启动时加载，适合缓存重复路径与方法的判定结果；上述基准中，未开启缓存时大部分耗时都来自两个「判断要不要鉴权」的前置检查

### 存储适配器

不同策略规模的全量加载总耗时（`LoadPolicy`）：

| 规模 | gorm / SQLite | gorm / PostgreSQL | redis / miniredis |
| --- | ---: | ---: | ---: |
| 100 条 | 185 µs | 258 µs | 121 µs |
| 1000 条 | 1.61 ms | 1.61 ms | 854 µs |
| 10000 条 | 15.8 ms | 35.5 ms | 7.95 ms |

**过滤加载（多租户按需加载）在 SQL 后端才有质变**，因为条件能下推成 `WHERE` 并命中联合索引；Redis 的集合没有二级索引，只能整集合取回内存再筛：

| 1 万条策略里只加载一个租户 | 全量 | 过滤 | 提升 |
| --- | ---: | ---: | ---: |
| gorm / PostgreSQL | 35.5 ms | **154 µs** | 230× |
| gorm / SQLite | 15.8 ms | 1.12 ms | 14× |
| redis | 7.95 ms | 5.60 ms | 1.4× |

所以：**SQL 后端做多租户用过滤加载，Redis 后端请用按租户分 key 前缀**（`WithKeyPrefix`），过滤不会减少集合读取量

批量写入不是可选项，尤其在 PostgreSQL 上 —— 逐条写每次都是一个独立往返加一次刷盘：

| | 逐条 `AddPolicy` | `AddPolicies` 批量 1000 条 | 每条摊薄 |
| --- | ---: | ---: | ---: |
| gorm / PostgreSQL | 338 µs | 12.75 ms | 12.8 µs（26× 快） |
| gorm / SQLite | 18.3 µs | 10.19 ms | 10.2 µs（1.8× 快） |
| redis | 27.2 µs | 232 µs | 0.23 µs（117× 快） |

### 广播路径

| | 耗时 | 分配 |
| --- | ---: | ---: |
| `Update()` 一次通用广播 | 422 ns | 4 |
| `UpdateForAddPolicy` 单条 | 538 ns | 6 |
| `UpdateForAddPolicies` 1000 条 | 46.5 µs | 4 |
| `Dispatch` 处理远端事件 | 884 ns | 17 |
| `Dispatch` 丢弃自环事件 | 478 ns | 7 |

独立微基准中，生成事件 ID 的 `uuid.NewString()` 约 230 ns，JSON 编码 246 ns、解码 1205 ns；广播只发生在策略变更时，实际部署还包含网络往返，因此本地编解码不是当前优化重点

### 关于基准的几点说明

- Redis 的数字跑在 **miniredis**（进程内，无网络无 fsync）上，仅用于比较本包各条路径的相对开销；真实 Redis 还包含网络与持久化成本，不能直接套用这些延迟
- Redis 规则继续使用 JSON 编码，保证带逗号的字段也能无损还原；`decodeRule` 的本地开销不足以成为更换编码的依据
- Kafka 与 NATS 的连接、消费循环依赖真实网络；共用的本地事件处理已在 `adapter/base` 的广播基准中测量
- 行与规则的互转（`newRow` 3.2 ns、`policyArray` 23 ns）占加载成本较小；`indexName` 的哈希压缩路径约 179 ns，仅在索引命名时使用

### 跑基准

```bash
go test -run='^$' -bench=. -benchmem -benchtime=2s -count=3 -cpu=10 .
(cd adapter/base && go test -run='^$' -bench=. -benchmem .)
(cd adapter/redis && go test -run='^$' -bench=. -benchmem .)
(cd adapter/gorm && CASBIN_TEST_PG_DSN='...' go test -run='^$' -bench=. -benchmem .)
```

## 🚀 快速开始

### 安装

需要 Go 1.25.0 或更高版本

```bash
go get github.com/kamalyes/go-casbin
```

### 基础示例 - RBAC

以下示例从仓库根目录运行，使用随仓库提供的模型与策略文件：

```go
package main

import (
    "context"
    "fmt"
    "log"

    casbin "github.com/kamalyes/go-casbin"
)

func main() {
    e, err := casbin.NewEnforcer(
        casbin.WithModelPath("resources/rbac_model.conf"),
        casbin.WithPolicyPath("resources/rbac_policy.csv"),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer func() { _ = e.Close() }()

    ok, err := e.EnforceCtx(context.Background(), "alice", "/v1/users/42", "GET")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("alice 读取用户信息: %v\n", ok) // true

    // 官方 RBAC API 经方法提升直接可用
    roles, err := e.GetRolesForUser("alice")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("alice 的角色: %v\n", roles) // [admin]
}
```

在其他项目中使用时，请自行准备模型与策略文件，并按实际位置配置路径

### 常用配置

| 配置 | 用途 |
| --- | --- |
| `WithModel` / `WithModelPath` / `WithModelText` | 传入模型实例、文件路径或模型文本 |
| `WithAdapter` / `WithPolicyPath` | 接入策略存储或策略文件；适配器优先 |
| `WithWatcher` / `WithAutoLoad` | 接入变更通知或周期性全量重载 |
| `WithPublicPolicies` / `WithAuthSkipPolicies` | 配置匿名放行与认证免鉴权策略 |
| `WithBreaker` / `WithRetry` | 配置存储熔断与重试 |
| `WithDenyAll` | 配置正常鉴权的全拒开关，默认关闭 |
| `WithCache` / `WithMetrics` | 配置结果缓存与决策指标，默认均开启 |
| `WithLogger` / `WithMonitor` | 注入日志实现与监控实例 |

配置公共策略时只传路径与方法，例如 `[][]string{{"/v1/login", "POST"}}`；多租户模型还需传域，例如 `[][]string{{"public", "/v1/login", "POST"}}`，主体标记由本库补齐

### 适配器选型

| 适配器 | 类型 | 通知持久化 | 副本重启补齐 | 适用场景 |
| --- | --- | --- | --- | --- |
| [adapter/gorm](adapter/gorm/) | 存储 | — | — | MySQL / PostgreSQL / SQLite、多租户按表分片 |
| [adapter/redis](adapter/redis/) | 存储 + 通知 | 无 | ❌ | 已有 Redis、可接受轮询兜底 |
| [adapter/kafka](adapter/kafka/) | 通知 | 支持回溯 | 需稳定且独立的消费组与有效位点 | 可靠广播、跨机房部署 |
| [adapter/nats](adapter/nats/) | 通知 | 可选 JetStream | 需启用 JetStream 并配置稳定的 `Durable` | 轻量部署、按需持久化 |

适配器各自为独立 Go 模块，按需安装：

```bash
go get github.com/kamalyes/go-casbin/adapter/gorm
```

Kafka 的 `GroupID` 在副本间必须不同，才能让每个副本都收到广播；需要重启续接时还应保持各副本的组 ID 稳定

GORM 的分片索引名需带表名并控制在 PostgreSQL 的 63 字节限制内，适配器已统一处理；配置与实现细节见 [注意事项与设计决策](#注意事项与设计决策)

### 存储操作保护

`LoadPolicy` / `SavePolicy` / `LoadFilteredPolicyCtx` 自动经过已配置的熔断与重试；自行调用写库管理 API 时，可用 `Guarded` 包裹：

```go
err := e.Guarded(ctx, func() error {
    _, err := e.AddPolicy("admin", "/v1/reports/*", "GET")
    return err
})
```

## 📂 可运行示例

| 示例 | 说明 | 从仓库根目录运行 |
| --- | --- | --- |
| [gateway](examples/gateway/main.go) | 匿名放行 → 认证 → 认证免鉴权 → 正常鉴权，以及角色查询、健康检查与指标日志 | `(cd examples/gateway && go run .)` |

示例使用本地文件策略，无需数据库或消息中间件；JWT 的实际校验由接入网关完成

## 📚 详细文档

| 文档或源码 | 内容 |
| --- | --- |
| [注意事项与设计决策](#注意事项与设计决策) | 鉴权开关、结果缓存、内存策略、存储与广播约束 |
| [配置选项](options.go) | 模型、存储、通知、缓存、全拒开关与监控配置 |
| [执行器](enforcer.go) | 权限决策、存储保护、生命周期与可观测入口 |
| [网关策略](publicpolicy.go) | 公共策略与认证免鉴权策略 |
| [域身份绑定](identity.go) | 域名归一化、租户绑定与反查 |
| [官方类型再导出](casbin.go) | 官方执行器、模型、适配器与事务接口 |

### 注意事项与设计决策

#### 鉴权开关与结果缓存

`EnableEnforce` 保持官方实现与语义，本库通过内嵌执行器直接提供该方法：

| 调用 | 行为 |
| --- | --- |
| `EnableEnforce(false)` | 关闭权限校验，全部放行 |
| `EnableEnforce(true)` | 恢复按模型与策略鉴权 |
| `WithDenyAll(true)` / `SetDenyAll(true)` | `Enforce` / `EnforceCtx` 全部拒绝，返回 `ErrDenyAll` |

官方 `EnableEnforce` 不会失效结果缓存；切换后，已缓存请求可能仍返回旧结果，未缓存请求才采用新语义，调用方需检查 `InvalidateCache()` 的返回错误

`DenyAll` 在正常鉴权入口先于缓存判断，切换立即影响该入口；公共策略与认证免鉴权策略使用独立执行器，如需整个网关停服，应在三路决策之前检查 `IsDenyAll()`

相关回归用例：`TestOfficialEnableEnforceAllowsEverything`、`TestOfficialEnableEnforceDoesNotInvalidateCache`、`TestDenyAllTakesEffectImmediatelyEvenOnCachedRequests`

#### 独立内存策略与模型来源

公共策略与认证免鉴权策略分别使用独立的缓存执行器，避免混入正式策略集；它们不会被 `SavePolicy` 写入存储，也不会出现在主执行器的 `GetPolicy()` 结果中

配置这两类策略时，应使用 `WithModelPath` / `WithModelText` 提供可重新解析的模型来源；仅传入 `WithModel` 实例无法安全复制模型，会返回 `ErrNoPolicySource`

相关回归用例：`TestPublicPoliciesNeverReachTheMainPolicySet`、`TestInMemoryPoliciesNeedARebuildableModel`

#### 策略加载与 Watcher 回调

没有策略存储时，`LoadPolicy` / `SavePolicy` / `LoadFilteredPolicyCtx` 返回 `ErrNoAdapter`；远端广播到达时仅记录警告，避免无适配器加载触发 panic

官方 `SetWatcher` 对 `WatcherEx` 不自动安装通用回调；本库在构造时显式调用 `SetUpdateCallback`，远端变更统一触发全量 `LoadPolicy`；直接使用官方执行器时需自行安装回调，不能把支持细分事件等同于已经实现增量重载

相关回归用例：`TestStoreOperationsWithoutStoreReturnErrNoAdapter`、`TestPolicyChangeWithoutStoreDoesNotPanic`、`TestWatcherExGetsUpdateCallback`

#### 适配器与广播约束

| 场景 | 约束与处理 |
| --- | --- |
| Kafka 广播 | 每个副本使用不同 `GroupID`；留空会生成随机组 ID，需要重启续接时应显式配置稳定的副本组 ID |
| NATS 重启补齐 | 同时开启 `JetStream` 并配置稳定的 `Durable`；仅开启 JetStream 或使用普通 Pub/Sub 均不足以保证副本补齐 |
| 全量保存通知 | `UpdateForSavePolicy` 只发送变更信号与 `RuleCount`，接收方回源加载，避免大型策略快照超过 broker 消息上限 |
| GORM 分片索引 | 按表名生成独立索引名，超长名称以稳定短哈希压缩到 63 字节内，保留可区分的后缀 |
| 历史分片索引 | 冷启动可调用 `SyncAllShardIndexes(ctx, db, prefix)` 批量对齐，单表失败不中断其他分片 |
| GORM 精确删除 | 单条删除对未使用的规则列显式匹配空串，避免误删拥有相同前缀的更长规则 |
| GORM 清空字段 | 更新使用显式列值映射，避免结构体更新忽略零值 |
| GORM 加载错误 | 无法装入模型的策略行直接报错，避免静默丢失规则改变授权结果 |
| Redis 编码 | 规则使用 JSON 数组，保证带逗号的表达式可无损还原，并保持集合去重 |

### 从自研引擎版本迁移

1. **导入路径**：执行器入口改为根包 `github.com/kamalyes/go-casbin`，不再使用旧的 `/enforcer` 子包
2. **适配器接口**：旧版 `LoadPolicy() ([]string, error)` 改为官方的 `LoadPolicy(model.Model) error`，自研适配器需按官方接口调整
3. **域身份绑定独立成段**：声明 `r2 / p2 / e2 / m2`，判定时选择对应段，见 [多租户模型](resources/rbac_with_domains_model.conf)
4. **`eval` 请求段后缀**：`p2.sub_rule` 应使用 `r2.sub != ""`，旧数据中的 `r.sub` 需迁移，否则报 `No parameter 'r_sub' found`
5. **查询返回值**：`GetPolicy` 等官方 v3 查询 API 返回结果与 `error`，调用方需处理双返回值
6. **开关语义**：`EnableEnforce(false)` 保持官方的全部放行语义；全拒使用 `WithDenyAll(true)` / `SetDenyAll(true)`

## 🎯 学习路径

1. **入门**：阅读「项目简介」与「快速开始」，运行 [网关示例](examples/gateway/main.go)
2. **模型**：对照 [RBAC 模型](resources/rbac_model.conf) 和 [多租户模型](resources/rbac_with_domains_model.conf)，理解请求、策略、角色与域
3. **接入**：根据「适配器选型」选择存储与通知模块，阅读 [配置选项](options.go)
4. **部署与维护**：阅读 [注意事项与设计决策](#注意事项与设计决策)，检查副本同步、缓存、监控与模块测试

## 📊 监控与日志

### 结构化日志

`Logger` 仅要求四个带 context 的键值方法：`DebugContextKV`、`InfoContextKV`、`WarnContextKV`、`ErrorContextKV`；未配置时使用 `NopLogger`，不输出日志；`go-logger` 的 `*Logger` 满足该接口，可通过 `WithLogger` 直接注入

```go
// e 为已创建的执行器，ctx 为当前上下文
e.LogMetrics(ctx)
snapshot := e.Monitor().Snapshot()
status, checks := e.HealthCheck()
```

### 监控指标

| 快照字段 | 说明 |
| --- | --- |
| `EnforceTotal` | 进入底层权限决策的总次数 |
| `EnforceAllow` / `EnforceDeny` / `EnforceError` | 允许、拒绝与执行错误次数，互相区分 |
| `AvgLatency` / `MaxLatency` | 平均与最大决策耗时 |
| `AllowRate` / `ErrorRate` | 允许率与错误率，单位为百分比 |
| `PolicyUpdates` / `PolicyReloads` | 显式记录的策略变更与重载次数 |
| `BreakerRejects` | 存储熔断拒绝次数 |

通过 `e.Monitor().RecordPolicyUpdate()` / `RecordPolicyReload()` 显式记录业务侧变更与重载；Watcher 触发的成功重载会自动记录，直接调用官方管理 API 不会自动增加这些计数

公共策略与认证免鉴权策略使用独立执行器，不计入上述决策指标

`WithMetrics(false)` 关闭决策计时和计数，适用于已在外层埋点的高频路径；关闭期间不会产生新的决策指标，基于决策错误率的健康检查也无法反映这段时间的状态；快照可由业务方转换后接入现有指标系统

### 健康检查

`HealthCheck()` 聚合执行器状态、策略数量、决策错误率，以及已配置熔断器的状态，返回汇总状态和逐项结果；该检查读取本地状态，不主动探测数据库或消息中间件

## 🤝 贡献指南

### 本地开发与测试

仓库自带 `go.work`，包含根模块及 `adapter/base`、`adapter/gorm`、`adapter/kafka`、`adapter/nats`、`adapter/redis` 五个子模块，本地修改可直接联调

```bash
# 根目录的 ./... 不包含嵌套模块，需逐个运行
for m in . adapter/base adapter/gorm adapter/kafka adapter/nats adapter/redis; do
  (cd "$m" && GOWORK=off go build -mod=readonly ./... && GOWORK=off go vet -mod=readonly ./... && GOWORK=off go test -mod=readonly -race -cover ./...)
done
```

CI 复用统一 Go 版本与平台矩阵，并通过 `post-test-script` 对五个子模块分别执行 `GOWORK=off` 的 build / vet / race 测试；CodeQL 同样显式构建全部六个模块，避免 workspace 掩盖模块依赖缺失

### 真实数据库验证

GORM 用例默认运行 SQLite；设置 `CASBIN_TEST_PG_DSN` 后，还会在 PostgreSQL 上验证：

```bash
(cd adapter/gorm && CASBIN_TEST_PG_DSN='postgres://postgres:pass@127.0.0.1:5432/casbin_test?sslmode=disable' go test ./...)
```

索引回归检查应直接查询 `pg_indexes` / `sqlite_master`，避免仅用 `Migrator.HasIndex` 验证，因为超长索引名截断可能同时误导被测代码与验证接口

建议使用独立的 `casbin_test` 测试库；用例创建 `casbin_it_` 前缀的表，结束后清理自己创建的表；PostgreSQL 的标识符截断等行为需要真实后端验证，不能仅依赖 SQLite

Kafka 与 NATS 的连接、消费循环需要真实 broker 验证；共用事件格式、广播语义和自环过滤由 `adapter/base` 的测试覆盖

### 新适配器与发版

新增通知适配器时复用 `adapter/base.Notifier`，只实现连接、发送、消费循环和关闭，统一事件格式与回调语义

推送根模块版本 tag 后，`Tag Submodules` 工作流自动验证全部六个模块，并生成同版本子模块 tag：

```text
v0.3.0
├── adapter/base/v0.3.0
├── adapter/gorm/v0.3.0
├── adapter/kafka/v0.3.0
├── adapter/nats/v0.3.0
└── adapter/redis/v0.3.0
```

工作流生成只更新四个适配器 `require` 版本的发布提交，将它们对 `adapter/base` 的依赖固定为对应版本；五个子模块 tag 统一指向该提交，根 tag 与主分支保持原样

子模块 tag 使用原子推送，整组成功或整组失败；重复运行会跳过已有且一致的 tag，发现版本冲突则停止，已有 tag 不会被覆盖；自动化用例还会通过本地 Go 模块代理模拟真实下游安装，确认依赖不依靠开发用 `replace`

首次使用需先将工作流提交推送到远端，再推送根 tag；失败后可重跑工作流，或通过 `workflow_dispatch` 指定已推送的根版本补发，当前模块路径支持 v0 / v1

评估覆盖率时应检查未覆盖的函数，区分需要真实 broker 的连接逻辑与可在本地验证的公开接口；回归用例应能在移除对应修复后失败

提交变更时，请说明实际行为、相关模块及验证方式，并为需要回归保护的逻辑补充测试

## 📄 许可证

本项目采用 MIT 许可证
