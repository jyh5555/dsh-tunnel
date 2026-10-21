# dsh-tunnel

给 `dsh web` 开一个公网地址，用哪种隧道由你决定，你可以用你自己的手机远程控制。

`dsh web` 默认只监听 `127.0.0.1`。想从手机、公司电脑或者别的城市连回来，直接挂一个
隧道是不行的 —— 它的 `/api` 接口有个 Host 校验，只放行回环地址、监听地址本身，或者
你显式声明的可信主机，而且这个校验在任何路由执行之前就跑完了。所以从公网域名过来的
请求一律 403，连登录页都到不了。

这个插件在中间放了一个反向代理，替 dsh web 完成它要求的几项改写，然后把「流量怎么
到达这个代理」交给你选。

## 目录

- [先说风险](#先说风险)
- [选项对比](#选项对比)
- [安装](#安装)
- [使用方法](#使用方法)
  - [Tailscale Funnel](#tailscale-funnel推荐)
  - [Cloudflare 临时隧道](#cloudflare-临时隧道)
  - [自定义命令](#自定义命令)
  - [关闭](#关闭)
- [访问密钥](#访问密钥)
- [实现原理](#实现原理)
- [配置文件](#配置文件)
- [常见问题](#常见问题)
- [开发](#开发)

---

## 先说风险

**这个插件会让一台电脑在公网上可达。** 装之前请把下面几件事想清楚。

### 隧道提供方能读到内容

流量在「访客」和「隧道边缘」之间是 TLS 加密的，但到了边缘会解密再转发给你。
所以 Cloudflare、Tailscale 或者任何你用的隧道服务，**在原理上可以看到明文** ——
包括你的对话、文件内容、终端输出。

这里没有任何应用层加密。如果你不能接受，出路有两条：用 Tailscale 的 `serve`
模式（不开放公网，只有加入你 tailnet 的设备能连，走 WireGuard，提供方解不开），
或者干脆别开。

### 拿到密钥的人就是一个完整的 dsh 用户

过了密钥这道门，对方能做的事情和坐在你电脑前的你基本一样：对话、跑工具、读写
工作目录里的文件、开终端。这是「远程访问」这个功能本身的意思，不是漏洞。

他消耗的模型额度算你的。

### 密钥泄漏了只能重置

没有账号系统、没有设备列表、没有「踢掉某一台设备」。
唯一的撤销方式是在面板里重置密钥 —— 那会让所有旧 Cookie 立刻失效，所有人都要重新进。

### 密钥第一次会经过隧道服务

首次访问时密钥放在表单里提交，不进 URL。但隧道提供方仍然能看到这个请求的内容，
也就是说**它能看到密钥**。这一点没法绕开：任何在边缘解密的方案都有这个问题。

### 这个代理监听在回环地址上

`host` 默认 `127.0.0.1`，别改成 `0.0.0.0`。改了以后局域网里任何人都能直连这个代理，
绕开隧道。插件本身不阻止你这么填，但没有任何理由这么干。

完整的威胁模型写在 [SECURITY.md](./SECURITY.md)。

---

## 选项对比

| | 费用 | 地址 | SSE | 需要什么 | 适合 |
|---|---|---|---|---|---|
| **Tailscale Funnel** | 免费 | 永久 `*.ts.net` | ✅ | Tailscale 账号 + `tailscale up` | 日常使用 |
| **Cloudflare 临时隧道** | 免费 | 每次重启变 | ❌ | 装了 `cloudflared` | 临时试一下 |
| **自定义命令** | 看你用什么 | 看你用什么 | 看你用什么 | 一个会打印 `https://` 地址的命令 | 已经有隧道的人 |
| **关闭** | — | — | — | — | 什么都不暴露 |

SSE 那一栏影响的是插件热更新：dsh web 用 `/plugins/events` 这个长连接推送插件改动。
Quick Tunnel 会把这条连接掐掉，所以远程那边改了插件不会自动刷新（对话、工具调用、
审批走的是 WebSocket，不受影响）。

### 一个真实的坑

Cloudflare 临时隧道要先连 `api.trycloudflare.com` 申请地址。如果你的网络需要代理、
或者 Cloudflare 在这条线路上不通，它会一直超时 —— 插件会重试三次然后告诉你这是网络
问题。这种情况换 Tailscale 通常就好了，因为它连的是完全不同的端点。

我在自己的网络上前前后后撞了七八次，最后是改用 Tailscale 才恢复的。

---

## 安装

```bash
dsh plugin install dsh-tunnel          # 发布到 npm 之后
dsh plugin install link:/abs/path      # 从本地源码装
```

装完**重启 dsh web**。插件会出现在两个地方：侧栏的「隧道」，以及「设置 → 隧道」。

> 侧栏那一行和设置页里的面板是同一个组件，改哪边都一样。

`provider` 默认是 `off`。**装上它不会暴露任何东西**，直到你自己去面板里选一个并提供者。

---

## 使用方法

### Tailscale Funnel（推荐）

一次性准备：

```bash
tailscale up
```

然后去 Tailscale 管理后台给你的 tailnet 打开 HTTPS 证书（在 DNS 页面里）。

接着在面板里选「Tailscale Funnel」，端口填 `8443`，点**启动隧道**。

Funnel 只接受 443、8443、10000 三个端口。代理默认就监听 8443，所以不用改。

好处是地址固定不变（`你的机器名.你的tailnet.ts.net`），重启电脑也不变，SSE 也正常。

### Cloudflare 临时隧道

```bash
winget install Cloudflare.cloudflared     # Windows
brew install cloudflared                  # macOS
# Linux 看官方下载页
```

不用注册账号。面板里选「Cloudflare 临时隧道」后点启动，几秒内会拿到一个
`xxx-yyy-zzz.trycloudflare.com` 的地址。

要知道两件事：地址每次重启都变；Quick Tunnel 不支持 SSE。

### 自定义命令

任何能在 stdout 或 stderr 打印出 `https://` 公网地址的命令都可以。参数里的 `{port}`
会被替换成代理实际监听的端口。

面板里这样填：

```
命令: bore
参数: local {port} --to bore.pub
```

`bore`、`frp`、`ngrok`、配了辅助脚本的 `ssh -R`、你自己服务器上跑的隧道，都能接进来。

插件会从输出里挑出第一个像样的地址。它会拒绝把 `api.trycloudflare.com` 这种控制面
主机当成隧道地址 —— 这个判断在早期版本里出过错，把一行报错当成了成功。

### 关闭

面板里选「关闭」然后点**保持不暴露**。代理会停掉，隧道会断掉，什么都不留。

这个状态下 dsh web 只在本机可用，和没装插件一样。

---

## 访问密钥

隧道地址是公网的，所以进门要一把钥匙。

**怎么进**：面板里会给出「登录入口」，形如 `https://你的地址/__tunnel`。打开它，
把面板里显示的密钥粘进去，点继续。

用的是 POST 表单，密钥在请求体里，**不进 URL** —— 不会留在浏览器历史里，不会出现在
隧道服务的访问日志里，也不会顺着 `Referer` 漏给别的站点。

早期版本用的是 `https://地址/?key=密钥` 这种链接。代理现在仍然接受这种形式，免得
你已经发出去的链接失效，但面板不再生成它。

**Cookie**：验证通过后会种一个 `HttpOnly`、`Secure`、`SameSite=Lax` 的 Cookie，
有效期 12 小时。

**重置密钥**：面板里点「重置密钥」。所有用旧密钥进去过的设备**立刻**失效 ——
Cookie 是密钥的 HMAC，密钥一换，旧 Cookie 全部对不上。

**防爆破**：同一个来源每分钟错 10 次就会被挡 60 秒（返回 429）。输对一次就清零。

### 两种权限

这是这个插件和「随便挂个隧道」最重要的区别。

| | 访客（有密钥） | 操作者（在本机） |
|---|---|---|
| 用 dsh web：对话、工具、文件、终端 | ✅ | ✅ |
| 看隧道是否在跑、公网地址 | ✅ | ✅ |
| 启动 / 停止隧道 | ❌ 403 | ✅ |
| 修改提供者配置 | ❌ 403 | ✅ |
| 看到明文密钥、控制令牌 | ❌ 不下发 | ✅ |

也就是说，**拿到链接的人不能把你的隧道关掉，也不能在这台机器上执行命令。**

通过隧道打开面板时，它会明说自己是只读的，并且把那些按了也只会 403 的按钮藏起来。

---

## 实现原理

代码在 [`lib/proxy.js`](lib/proxy.js)，不到 500 行，零依赖。下面每一条都是对着真实
运行的 dsh web 试出来的，不是推测。

### 为什么不能直接把隧道指向 dsh web

dsh web 的 `/api` 前面有个校验函数 `isTrustedApiRequest()`，它接受三种 Host：

```
Host: 127.0.0.1:47996          → 放行（只是没 Cookie，401）
Host: 192.168.1.106:47996      → 403
Host: abc.trycloudflare.com    → 403
```

而且这个校验在任何路由之前执行，所以没法从 dsh web 内部绕过。必须有个东西在它前面
把 `Host` 改掉。

### 代理做的四件事

**1. 把 `Host` 改成回环 authority**

每个转发的请求，`Host` 都改写成上游的 `127.0.0.1:端口`。

**2. 剥掉 `Origin`、`Referer` 和 `sec-fetch-*`**

同一个校验里，`sec-fetch-site: cross-site` 直接拒，`Origin` 和 Host 不同源也拒。
浏览器访问公网域名时，每个请求恰好都带着这些头。所以是**剥掉**，不是伪造一个。

**3. 注入 `dsh-auth-*` 会话 Cookie**

dsh web 对没有会话 Cookie 的请求一律 401。插件走的是官方给的路径：

```js
const signed = ctx.connection.authenticatedUrl(`${origin}/`)
const response = await fetch(signed, { redirect: 'manual' })
// → Set-Cookie: dsh-auth-…
```

这个 Cookie 是按**监听器的 authority** 签名的。dsh web 每次重启会换端口，旧 Cookie
就对不上了，所以插件每 15 秒重新取一次。

**4. WebSocket 原样转发**

`/api/remote.mux` 是对话、工具调用、审批走的长连接。这里用的是裸 socket 中继，
不是现成的库 —— 因为要保证 `Sec-WebSocket-Extensions` 原样透传。

丢了它，服务端就不启用 `permessage-deflate`，而浏览器仍按自己声明过的上下文解帧，
帧就错乱了。表现出来是「连上了，立刻又断开，一直重连」。

### 一个容易踩的路径坑

插件 bundle 的路径里有个**双问号**：

```
/plugins/??dsh-x/client.js,@deepseek-ai/dsh-y/client.js&rev=…
```

这是打包器的虚拟路径约定。`new URL(req.url, base)` 会在第一个 `?` 处切开，pathname
变成 `/plugins/`，少一个 `?` —— 上游 404，整个前端加载不出来。

所以代理转发的是原始路径字符串（`upstreamPath()`），只有绝对形式的请求行才去解析。

### 权限是怎么分开的

这是 0.2.0 才有的东西，也是最容易写错的部分。

问题在于：**dsh web 分不清「隧道来的访客」和「坐在电脑前的人」**。代理总是从
`127.0.0.1` 连上游，所以每个请求的 `remoteAddress` 都是回环。

办法是让代理给每个转发的请求盖一个头：

```
x-dsh-tunnel-hop: 1
```

关键在于**盖之前先把这个头从客户端请求里删掉**（它就在 `STRIP_REQUEST` 那个集合里）。
不然访客自己发一个同名头就能冒充本机。

插件看到这个标记，就按「只在远端」处理：

- `/status` 不下发 `controlToken`，不下发 `accessKey`，不下发命令行（命令行里可能
  带 token）
- `/start`、`/stop`、`/config`、`/key` 一律 403

面板本身也是根据 `status.remote` 决定渲染成只读还是完整界面。

### `custom` 为什么不是远程 shell

`custom` 提供者的本质就是 `spawn(command, args)`。这是功能，也是这个插件能做的
最危险的事。

三道限制：

1. 面板只能调整**已经存在于配置文件里**的命令，不能从零装一个
2. shell 本身（`cmd`、`pwsh`、`bash`、`sh`…）直接拒绝
3. 参数里不许有 shell 元字符（`; & | \` $ > <` 和换行）

第 2、3 条是纵深防御。第一道防线是访客根本到不了这个路由。

---

## 配置文件

改 profile 里的 `cordis.patch.yml`（参考
[`examples/profile-cordis.patch.yml`](examples/profile-cordis.patch.yml)）：

```yaml
- id: dsh-tunnel
  name: dsh-tunnel
  config:
    provider: "off"        # off | cloudflared | tailscale | custom
    port: 8443             # 代理监听端口，8443 在所有提供者下都可用
    host: "127.0.0.1"      # 保持回环
    accessKey: ""          # 留空 = 每次启动随机生成
    cloudflared:
      path: ""             # 留空 = 从 PATH 找
      extraArgs: []
    tailscale:
      path: ""             # 留空 = 从 PATH 找
      port: 8443           # 只能 443 / 8443 / 10000
    custom:
      command: ""          # 比如 "bore"
      args: []             # 比如 ["local", "{port}", "--to", "bore.pub"]
```

从面板里改的配置只存在于内存里，**不会写回这个文件**。想让它开机自动生效，得自己
把 `provider` 改好。

---

## 常见问题

**隧道起不来，报「Could not reach api.trycloudflare.com」**

网络问题，不是配置问题。你的网络到 Cloudflare 的控制面不通。换 Tailscale，或者检查
代理设置。

**手机上面板滑不动**

修过了（0.2.0）。如果你还是遇到，可能是宿主的布局变了。

**连上了但一直重连**

通常是 WebSocket 的扩展头被中间某层吃掉了。如果你用的是自定义命令，确认那条链路上
没有会改写 HTTP 头的代理。

**改了插件代码，远程没反应**

Quick Tunnel 不支持 SSE。用 Tailscale，或者重启 dsh web。

**远程面板是灰的，按钮点不动**

这是设计：你正在通过隧道访问，所以只能看不能改。要改配置请到那台电脑上操作。

---

## 开发

零运行时依赖 —— `lib/` 里每一个 `import` 都是 `node:` 内置模块。这是刻意的：会把你
机器暴露到公网的那个文件，应该能一口气读完；依赖链就是供应链。

```bash
npm run test:all          # 全部
npm test                  # 单元测试
npm run test:e2e          # 真代理 + 假上游，跑完整攻击链
npm run test:real         # 真代理接真实的 dsh web（需要它正在跑）
npm run test:attacks      # 五个攻击者视角的场景
npm run test:client       # 只读面板的契约
npm run test:integration  # 真实 apply() 配 mock ctx
npm run test:live         # 真的拉起 cloudflared
```

| 文件 | 覆盖 |
|---|---|
| `test/proxy.test.js` | 路径处理（含 `??` 那个坑）、密钥门、请求头改写、WebSocket 转发、密钥轮换 |
| `test/config.test.js` | 手写的 Standard Schema：默认值、范围、类型、未知字段 |
| `test/providers.test.js` | URL 提取、失败信息、子进程环境、控制面预检 |
| `test/security.test.js` | hop 标记不可伪造、`redactSnapshot` 边界、`custom` 校验、限流、密钥强度 |
| `test/e2e-viewer.mjs` | 真代理 + 假上游，把旧攻击链重放一遍 |
| `test/e2e-real-dsh.mjs` | 同一个代理接真实 dsh web：真围栏、真页面、真 `/api`、真 WebSocket |
| `test/attack-scenarios.mjs` | 五个叙事化攻击 |
| `test/client-contract.mjs` | 只读视图藏起了所有会 403 的控件 |
| `test/integration.mjs` | 真实 `apply()` 配 mock ctx |
| `test/smoke-after-restart.mjs` | 加载已部署的代码，看重启后实际是什么样 |
| `test/provider-live.mjs` | 真拉 cloudflared |

配置 schema 是手写实现 Standard Schema 的 `~standard.validate`。`schemastery` 被去掉
了，因为它为十几个默认值拖进了 `cosmokit` 一长串依赖。

客户端 bundle `lib/client.js` 也是手写的：`window.__ModuleLoader__.load({id, factory})`
就是全部协议，这个面板小到不值得引入构建管线。

### 这些测试都是踩出来的

下面每一条都是实际运行时撞上的，不是读代码想出来的：

1. **令牌死锁** —— `/status` 要控制令牌，而令牌只能从 `/status` 拿，面板永远加载不出来
2. **端口 0 被当成没填** —— `Number(port) || 8443` 把合法的 `0` 吞了，测试去抢了正在
   跑的真隧道的端口
3. **失败的启动看起来像成功** —— URL 提取器在 cloudflared 的报错行里匹配到了
   `api.trycloudflare.com`，把它当成了隧道地址
4. **重置密钥是摆设** —— HMAC 在构造时算死了，面板显示新密钥、代理还认旧的
5. **手机上滑不动** —— `main` 面板挂在 `overflow:hidden` 的 flex 列里，面板自己必须是
   滚动容器
6. **「插件」页被撑爆** —— `plugins.item` 是给带小配置表单的插件用的，整块操作台塞
   进去会把那一页拉得极长
7. **密钥能改成 `abc`** —— `/config` 接受任意字符串，一个请求就能把 144 bit 的门降级
8. **密钥走 URL** —— 会进隧道服务的日志，改成表单 POST

---

## 许可证

MIT。
