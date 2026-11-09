/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\options.go
 * @Description: 执行器配置选项（链式 API）
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package casbin

import (
	"time"

	"github.com/kamalyes/go-casbin/monitor"
)

// Options 执行器配置项
// 所有字段均为私有，通过 WithXxx 选项函数设置
type Options struct {
	model      Model  // 已构建好的模型实例（优先级最高）
	modelPath  string // 模型文件路径
	modelText  string // 模型文本内容
	policyPath string // 策略文件路径（未设置 adapter 时启用文件适配器）

	adapter Adapter // 策略持久化适配器（优先于文件适配器）
	watcher Watcher // 分布式策略变更通知器

	logger  Logger           // 日志记录器（最小 ctx 接口，见 logger.go）
	metrics *monitor.Monitor // 指标与健康检查

	breaker *Breaker // 下游存储熔断器
	retry   *Retry   // 下游存储重试器

	autoSave       bool          // 策略变更是否自动落库
	denyAll        bool          // 全拒开关：true 时所有决策返回 ErrDenyAll（见 WithDenyAll）
	metricsEnabled bool          // 是否在决策热路径上采集指标
	cacheEnabled   bool          // 是否启用结果缓存
	cacheExpire    time.Duration // 结果缓存过期时间（0 表示不过期，仅按版本号失效）
	autoLoad       time.Duration // 周期性全量重载间隔（0 表示关闭）

	publicPolicies   [][]string          // 匿名放行策略（内存态，不落库）
	authSkipPolicies [][]string          // 认证免鉴权策略（内存态，不落库）
	normalizeHost    func(string) string // 域名归一化函数
	identitySuffix   string              // 域身份绑定所用模型段后缀（默认 "2"，即 r2/p2/e2/m2）
}

// defaultOptions 返回默认配置
func defaultOptions() *Options {
	return &Options{
		autoSave:       true,
		metricsEnabled: true,
		cacheEnabled:   true,
		normalizeHost:  NormalizeDomainHost,
		identitySuffix: DefaultIdentitySuffix,
	}
}

// Option 配置选项函数类型
type Option func(*Options)

// WithModel 直接注入已构建的模型实例
// 与 WithModelPath / WithModelText 三者必选其一，本项优先级最高
func WithModel(m Model) Option {
	return func(o *Options) { o.model = m }
}

// WithModelPath 设置模型文件路径（如 resources/rbac_model.conf）
// 语法与官方 casbin model.conf 完全一致，可直接迁移
func WithModelPath(path string) Option {
	return func(o *Options) { o.modelPath = path }
}

// WithModelText 设置模型文本内容，适用于模型动态生成的场景
func WithModelText(text string) Option {
	return func(o *Options) { o.modelText = text }
}

// WithPolicyPath 设置策略文件路径
// 仅在未使用 WithAdapter 时生效，内部启用官方文件适配器
func WithPolicyPath(path string) Option {
	return func(o *Options) { o.policyPath = path }
}

// WithAdapter 设置策略持久化适配器
// 任何实现官方 persist.Adapter 的实现均可接入（gorm / redis / 自研）
// 多租户场景下每个租户可使用独立适配器实例（独立表 / 独立前缀）
func WithAdapter(adapter Adapter) Option {
	return func(o *Options) { o.adapter = adapter }
}

// WithWatcher 设置分布式策略变更通知器
// 任何实现官方 persist.Watcher / WatcherEx 的实现均可接入（kafka / nats / redis）
// A 节点改策略后广播，B/C/D 节点收到后自动重载
func WithWatcher(w Watcher) Option {
	return func(o *Options) { o.watcher = w }
}

// WithLogger 设置日志记录器
// 参数是本包声明的最小接口（4 个 ctx 版键值方法），不绑定任何日志库；
// go-logger 的 *Logger 签名一致，可直接传入
func WithLogger(log Logger) Option {
	return func(o *Options) { o.logger = log }
}

// WithMonitor 设置指标采集与健康检查器
func WithMonitor(m *monitor.Monitor) Option {
	return func(o *Options) { o.metrics = m }
}

// WithMetrics 设置是否在决策热路径上采集指标，默认开启
//
// 关闭后 Enforce 不再计时也不再计数，Monitor() 的决策类指标恒为 0，
// 健康检查里基于错误率的那一项也就失去意义。
//
// 代价是实测出来的：计数本身只要约 2ns，但为了算耗时要付一对
// time.Now()/time.Since —— 在 macOS 上约 43ns，Linux 上通常约 20ns。
// 决策本身走缓存命中只有 60 多纳秒，所以这对调用在命中路径上是可观的比例；
// 相对一次完整的网关判定（约 300ns）则是一成左右。
// 只有确实在意这几十纳秒、且另有链路埋点的场景才需要关掉它。
func WithMetrics(enabled bool) Option {
	return func(o *Options) { o.metricsEnabled = enabled }
}

// WithBreaker 设置下游存储熔断器
// 仅作用于会触达存储的操作（LoadPolicy / SavePolicy / Guarded 包裹的调用）；
// Enforce 是纯内存决策、不触达存储，因此不经过熔断器
func WithBreaker(name string, config BreakerConfig) Option {
	return func(o *Options) { o.breaker = NewBreaker(name, config) }
}

// WithRetry 设置下游存储重试器（指数退避 + 抖动）
// 作用范围同 WithBreaker
func WithRetry(config RetryConfig) Option {
	return func(o *Options) { o.retry = NewRetry(config) }
}

// WithAutoSave 设置策略变更是否自动落库
func WithAutoSave(autoSave bool) Option {
	return func(o *Options) { o.autoSave = autoSave }
}

// WithDenyAll 打开全拒开关，所有 Enforce 一律返回 ErrDenyAll
//
// 这是应急用的 kill switch，默认关闭。适用场景是「宁可全拒，也不要在没有
// 有效策略的情况下放行」—— 比如策略源不可用、或要立刻切断某个环境的访问。
//
// 不要与官方的 EnableEnforce 混用，两者方向相反：
//
//	WithDenyAll(true) / SetDenyAll(true)   本包：全部拒绝，返回 ErrDenyAll
//	EnableEnforce(false)                   官方：全部放行（官方注释写明 all access will be allowed）
//
// 官方那个语义配得上它的名字 —— 「关闭鉴权」就是不鉴权，开发期不配策略也能把应用跑通。
// 本包不覆盖它，只是另给一个方向明确的开关，避免「想关鉴权结果把 API 全开了」。
func WithDenyAll(denyAll bool) Option {
	return func(o *Options) { o.denyAll = denyAll }
}

// WithCache 设置决策结果缓存
// 基于官方 SyncedCachedEnforcer，策略变更时按版本号 O(1) 整体失效
// expire 为可选过期时间，不传表示仅按版本号失效
func WithCache(enabled bool, expire ...time.Duration) Option {
	return func(o *Options) {
		o.cacheEnabled = enabled
		if len(expire) > 0 {
			o.cacheExpire = expire[0]
		}
	}
}

// WithAutoLoad 设置周期性全量重载间隔
// 适用于没有消息中间件、只能靠轮询兜底的部署；有 Watcher 时不必开启
func WithAutoLoad(interval time.Duration) Option {
	return func(o *Options) { o.autoLoad = interval }
}

// WithPublicPolicies 设置匿名放行策略
// 这些策略只存在于内存，不写入适配器，每次启动从代码重新加载
//
// 只需传入路径与方法（不含主体），系统自动补充 SubjectAnonymous 前缀：
//   - RBAC:        {"/v1/login", "POST"}
//   - RBAC Domain: {"public", "/v1/login", "POST"}
func WithPublicPolicies(policies [][]string) Option {
	return func(o *Options) {
		o.publicPolicies = prependSubject(SubjectAnonymous, policies)
	}
}

// WithAuthSkipPolicies 设置认证免鉴权策略
// 语义为「需要 JWT 但跳过权限校验」，同样只存在于内存，不写入适配器
//
// 只需传入路径与方法（不含主体），系统自动补充 SubjectAuthenticated 前缀
func WithAuthSkipPolicies(policies [][]string) Option {
	return func(o *Options) {
		o.authSkipPolicies = prependSubject(SubjectAuthenticated, policies)
	}
}

// WithDomainIdentitySuffix 设置域身份绑定所用的模型段后缀
// 默认 "2"，即在模型中声明 r2 / p2 / e2 / m2 四段；
// 官方 matcher 每次只遍历一种策略类型，因此域名绑定必须独立成段，不能和 p 混在一条 m 里
func WithDomainIdentitySuffix(suffix string) Option {
	return func(o *Options) {
		if suffix != "" {
			o.identitySuffix = suffix
		}
	}
}

// WithNormalizeHost 设置域名归一化函数
// 默认使用 NormalizeDomainHost（取 X-Forwarded-Host 首值、剥端口、去 IPv6 括号、小写、去尾点）
func WithNormalizeHost(fn func(string) string) Option {
	return func(o *Options) { o.normalizeHost = fn }
}
