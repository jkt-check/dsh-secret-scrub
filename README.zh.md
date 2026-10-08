# dsh-secret-scrub

[English](README.md) | 中文 | [更新日志](CHANGELOG.md)

不可逆的密钥脱敏守护插件，源自 [kaya-ai-terminal](https://github.com/jkt-check/kaya-ai-terminal) 项目的用户敏感信息保护策略，现独立开源（大陆官网：https://www.yunhouai.com；非大陆地区官网：https://www.yunhou.ai）。它在文本流向会话日志和模型请求的路上进行改写：当配置的规则命中形似密钥的片段——访问密钥、Bearer 令牌、私钥块——该片段会被不可逆地替换为 `[REDACTED:<category>]` 占位符，使持久日志和模型请求在被覆盖的位置只携带占位符。

## 安装

```sh
npm install dsh-secret-scrub
```

运行时依赖为 `@deepseek-ai/cordis`(peer）和 `@deepseek-ai/schemastery`。`@deepseek-ai/dsh-*` 系列 peer 包仅为类型依赖且可选。

## 在 dsh profile 中使用

本包声明了 `dsh.bundle.patch`，一条命令装完即用（默认 `balanced` 级别脱敏，无需任何凭据）：

```sh
# 1. 安装 dsh CLI
npm i -g @deepseek-ai/dsh

# 2. 把插件装到目标 profile 里（以 headless 为例）
dsh plugin --profile headless add dsh-secret-scrub
#    发布前想测试本地改动，可用 npm pack 生成的 tarball：
#    dsh plugin --profile headless add /path/to/dsh-secret-scrub-0.1.2.tgz

# 3. 重启该 profile 后，运行包含敏感信息的任务——密钥会在进入模型/会话日志前被脱敏
dsh --profile headless "echo AWS AKIAIOSFODNN7EXAMPLE"
```

`dsh plugin add` 会自动应用包内的 `cordis.patch.yml`（以 `balanced` 级别挂载插件）。想调整级别或追加自定义规则，可在 profile 补丁层 `~/.dsh/profiles/headless/cordis.patch.yml` 中覆盖同 id 的配置：

```yaml
- id: secret-scrub
  config:
    level: aggressive
    extra:
      - category: internal-token
        pattern: 'internal-[0-9]{4}'
```

## 作为独立 Cordis 插件使用

如果你不使用 dsh，也可以直接挂载到 Cordis Context 上：

```ts
import { Context } from '@deepseek-ai/cordis'
import * as SecretScrub from 'dsh-secret-scrub'

const ctx = new Context()
await ctx.plugin(SecretScrub, {
  level: 'aggressive',               // 脱敏深度:minimal | balanced(默认)| aggressive
  disabled: ['env-var-secret'],      // 仅限 tier 1/2 内置类目——tier 0 不可禁用
  extra: [
    { category: 'internal-token', pattern: 'internal-[0-9]{4}' },
  ],
})
```

插件挂载三个前置的 waterfall 监听器，先委托下游，再对链路最终采纳的内容脱敏：

- `agent/pre-step` 改写每个 step 采纳的用户消息，然后才进入会话日志和模型请求。用户消息按 `inputLevel` 脱敏——默认 `aggressive`，与 `level` 无关——即使工具输出保持较低级别，粘贴进来的 PII 和密钥也会按全量规则表处理。
- `tools/post-execute` 改写被接受的工具结果的纯文本内容。
- `tools/ptc-dispatch-log` 改写 `run_code` 子调用的 `tool/code-dispatch` 持久化副本。

| 字段 | 默认值 | 含义 |
|---|---|---|
| `level` | `balanced` | 工具输出的脱敏深度：`minimal` 只跑 tier 0,`balanced` 加 tier 1,`aggressive` 加 tier 2——PII 与高熵兜底 |
| `inputLevel` | `aggressive` | `agent/pre-step` 采纳的用户消息的脱敏深度，独立于 `level` |
| `disabled` | `[]` | 关闭指定的 tier 1/2 内置类目；tier-0 核心规则不可禁用，禁用会在加载时报错 |
| `extra` | `[]` | 部署方追加的规则，在所有级别下生效：全局唯一的小写连字符 `category` 加上以 `new RegExp(pattern, 'g')` 编译的 `pattern` |

无效配置在启动时即以明确的错误失败——未知或 tier-0 的 `disabled` 类目、无法编译的 `extra` 正则、不能出现在占位符中的类目 id、重复类目——绝不静默回退。

## 内置规则分级

`level` 选择生效的最高 tier。tier 0–1 为前缀锚定，tier 2 按形状匹配（规则见 [`src/rules.ts`](src/rules.ts)):

| Tier | 生效级别 | 类目 |
|---|---|---|
| 0 — 核心密钥 | 所有级别；不可禁用 | `private-key`、`private-key-truncated`（截断 PEM 护甲）、`api-key`（通用 apikey 赋值）、`aws-access-key`、`github-token`、`google-api-key`、`deepseek-key`、`openai-key`、`anthropic-key`、`gitlab-pat`、`rollbar-token`、`stripe-key`、`slack-token`、`slack-signing-secret`、`slack-webhook-url`、`npm-token`、`pypi-token`、`sendgrid-key`、`twilio-key`、`digitalocean-token`、`shopify-token`、`telegram-bot-token`、`tavily-key`、`age-secret-key`、`docker-pat`、`notion-token`、`supabase-token`、`linear-api-key`、`generic-sk-key`(`sk-`/`sk_` 兜底)、`url-credentials`（连接串 authority)、`url-access-token`(OAuth 回调令牌)、`generic-bearer`(Bearer 令牌与 JWT) |
| 1 — 赋值与云厂商密钥 | `balanced` 及以上 | `env-var-secret`（名称以 `_` 分段整体包含 KEY/SECRET/TOKEN/PASSWORD 的大写赋值）、`azure-storage-key`、`alibaba-access-key`、`key-assignment`（任意大小写的同类赋值形状，带取值过滤） |
| 2 — PII 与高熵兜底 | 仅 `aggressive` | `email`、`phone-cn`、`phone-intl`、`id-cn`、`credit-card`(Luhn 校验)、`ssn-us`、`high-entropy` |

## 直接使用引擎

纯脱敏引擎从 `dsh-secret-scrub/rules` 导出，不依赖 Cordis:

```ts
import { BUILTIN_RULES, scrubText } from 'dsh-secret-scrub/rules'

const { text, redactions } = scrubText('key: AKIAIOSFODNN7EXAMPLE', BUILTIN_RULES)
// text       → 'key: [REDACTED:aws-access-key]'
// redactions → { 'aws-access-key': 1 }
```

## 已知限制

脱敏是单向的、基于正则的。无前缀密钥、跨文本块拆分的密钥、编码形式（base64 包裹、URL 转义）按设计会绕过保守的规则形状。tier-2 规则匹配的是形状而非确凿的密钥，因此以误报换覆盖——任务说明中的邮箱会被当作密钥脱敏，哈希状文本（git SHA、SHA-256 摘要）在 `aggressive` 级别会命中 `high-entropy` 兜底。不要把本守护当作防止凭证泄漏的唯一手段。

## 开发

```sh
npm install
npm run typecheck
npm test
npm run build
```

## 许可证

[MIT](LICENSE) — Copyright (c) 2026 jkt-check
