# 余额查询接口 `GET /v1/balance`

抹茶公益站（本 fork）专用接口，上游 new-api 没有。实现在 `controller/matcha_balance.go`，路由接线在 `router/dashboard.go`。

## 用途

只凭调用模型用的那个 API Key，一次请求查到「这个 Key 现在还能花多少钱」。金额同时给出美元数值和原始额度整数，不需要客户端再去猜单位。

## 请求

```bash
curl https://router.matchacake.net/v1/balance \
  -H "Authorization: Bearer sk-xxxx"
```

- 方法与路径：`GET /v1/balance`，没有参数。
- 鉴权：`Authorization: Bearer sk-xxxx`，与调用模型是同一个 Key，走同一个令牌鉴权中间件（Key 上设置的 IP 白名单同样生效）。
- 限流：走全站的全局接口限流（默认每个 IP 180 秒 360 次），不占用模型请求的限流额度。
- 响应头带 `Cache-Control: no-store`，支持浏览器跨域调用。

## 返回

不限额 Key（且开启了「允许查询用户额度」）：

```json
{
  "object": "balance",
  "currency": "USD",
  "balance": 12.3456,
  "balance_quota": 6172800,
  "user": {
    "balance": 12.3456,
    "used": 5.6789,
    "balance_quota": 6172800,
    "used_quota": 2839450,
    "group": "default"
  },
  "token": {
    "name": "抹茶画室",
    "unlimited": true,
    "remaining": null,
    "remaining_quota": null,
    "used": 1.2345,
    "used_quota": 617250,
    "expires_at": null
  },
  "quota_per_unit": 500000,
  "cny_per_usd": 7
}
```

限额 Key：

```json
{
  "object": "balance",
  "currency": "USD",
  "balance": 0.2,
  "balance_quota": 100000,
  "user_hidden_reason": "limited_token",
  "token": {
    "name": "shared",
    "unlimited": false,
    "remaining": 0.2,
    "remaining_quota": 100000,
    "used": 0.05,
    "used_quota": 25000,
    "expires_at": 1893456000
  },
  "quota_per_unit": 500000,
  "cny_per_usd": 7
}
```

### 字段

所有金额字段的单位都是美元，保留到小数点后 6 位；带 `_quota` 后缀的是同一个量的原始额度整数，`美元 = 额度 ÷ quota_per_unit`。

| 字段 | 说明 |
| --- | --- |
| `object` | 固定为 `balance`。 |
| `currency` | 固定为 `USD`。 |
| `balance` | 这个 Key 现在实际还能花多少。不限额 Key 是账户可用余额；限额 Key 是 `min(账户可用余额, Key 剩余额度)`；最小为 0。Key 无权查看账户余额时为 `null`（见隐私规则）。 |
| `balance_quota` | `balance` 的原始额度整数，`balance` 为 `null` 时也是 `null`。 |
| `user` | 账户层面的数字，只在 Key 有权查看账户时出现。 |
| `user.balance` / `user.balance_quota` | 账户可用余额。账户透支时为负数（此时顶层 `balance` 为 0）。 |
| `user.used` / `user.used_quota` | 账户累计已用。 |
| `user.group` | 账户所在分组。 |
| `user_hidden_reason` | 只在没有 `user` 块时出现，说明原因：`limited_token`（限额 Key）或 `user_quota_query_disabled`（Key 关闭了「允许查询用户额度」）。 |
| `token.name` | Key 的名称。 |
| `token.unlimited` | Key 是否不限额。 |
| `token.remaining` / `token.remaining_quota` | Key 自己的剩余额度，不限额 Key 为 `null`。 |
| `token.used` / `token.used_quota` | 这个 Key 累计已用。 |
| `token.expires_at` | Key 的过期时间（Unix 秒），不过期为 `null`。 |
| `quota_per_unit` | 多少额度等于 1 美元。 |
| `cny_per_usd` | 站点充值价（元/美元），方便客户端显示「约合人民币」；站点没有配置充值价时省略。 |

## 隐私规则

有人会把限额 Key 分给别人用，不希望对方知道账户里有多少钱；控制台里每个 Key 也有「允许查询用户额度」开关。本接口两条都遵守：

- **限额 Key 永远不返回 `user` 块。** 持有者只能看到这个 Key 还能花多少（顶层 `balance`）以及 Key 自己的剩余与已用。
- **不限额 Key 只有在开启「允许查询用户额度」时才返回 `user` 块。** 开关关闭时 `balance` 为 `null`，`user_hidden_reason` 为 `user_quota_query_disabled`。新建的 Key 默认开启；开关上线之前创建的老 Key 默认关闭，需要在控制台编辑该 Key 打开一次。

一个无法避免的边界：限额 Key 的 `balance` 是 `min(账户余额, Key 剩余)`，所以当账户余额比 Key 的剩余额度还少时，`balance` 就等于账户余额。这与模型调用在余额不足时的报错信息透露的内容一致。

## 错误

鉴权失败由令牌中间件直接返回，格式与模型接口相同：

```json
{"error": {"code": "", "message": "Invalid token (request id: ...)", "type": "new_api_error"}}
```

| 状态码 | 情况 |
| --- | --- |
| 401 | 没带 Key、Key 不存在、已禁用、已过期；限额 Key 的额度用完后也是 401（与模型调用一致），所以限额 Key 查不到「剩余 0」。 |
| 403 | 账户被封禁；请求 IP 不在 Key 的 IP 白名单内；Key 的分组已不可用。 |
| 429 | 触发全局接口限流。 |
| 500 | 服务端查询失败。 |

## 实时性

- 余额直接读取当前数据，没有额外缓存。站点开启「批量更新」（`BATCH_UPDATE_ENABLED`）时，扣费会延迟写入，最多滞后 `BATCH_UPDATE_INTERVAL` 秒（默认 5 秒）；抹茶公益站没有开启。
- 进行中的请求会先预扣一部分额度，结束后按实际用量多退少补，所以有请求在跑时余额可能暂时偏低。
- 不包含「订阅套餐」额度。站点目前没有启用订阅套餐；启用后需要给本接口补上套餐额度。

## 与已有接口的区别

| 接口 | 鉴权 | 返回 | 问题 |
| --- | --- | --- | --- |
| `GET /api/user/self` | 控制台登录态 | 账户额度（原始整数） | API Key 不能用。 |
| `GET /v1/dashboard/billing/subscription`、`/usage` | API Key | 站点开启「显示令牌统计」时是 Key 的额度，否则是账户额度 | 不限额 Key 返回 1 亿的假数；返回的是总额而不是剩余；单位随站点显示设置变化。 |
| `GET /api/usage/token/` | API Key | Key 的额度，开启「允许查询用户额度」时附带账户额度（原始整数） | 只有原始整数；限额 Key 也会带出账户额度；20 分钟 20 次的严格限流。 |
