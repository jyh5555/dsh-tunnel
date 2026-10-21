/**
 * dsh-tunnel — 浏览器半（前端）。
 *
 * 手写 bundle，无构建步骤：`window.__ModuleLoader__.load({id, factory})`
 * 就是全部协议。factory 里只能 require shell 种子模块，所以这里用无 JSX 的
 * `h()` 调用而不是编译后的树 —— 一个隧道面板小到不值得引入构建管线，
 * 而且这样发布的包是能直接读的。
 *
 * 面板挂在「设置」页的 `settings.section` 槽位，位于「Agent 预设」下方。
 * 它显示当前状态、让用户选择隧道提供者，并给出可复制的公网地址与访问密钥。
 *
 * @module dsh-tunnel/client
 */

window.__ModuleLoader__.load({
  id: 'dsh-tunnel',
  factory: (require) => {
    const module = { exports: {} }
    const exports = module.exports
    Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' })

    const react = require('react')
    const h = react.createElement
    const { useState, useEffect, useCallback, useRef } = react

    /** Host 半注册的同源控制路由。 */
    const STATUS = '/dsh-tunnel/status'
    const START = '/dsh-tunnel/start'
    const STOP = '/dsh-tunnel/stop'
    const CONFIG = '/dsh-tunnel/config'
    const REGENERATE = '/dsh-tunnel/key'

    /** 面板打开时的轮询间隔：隧道状态不是高频信息，不必催。 */
    const POLL_MS = 4000

    /**
     * 各提供者的说明文案。
     *
     * 「需要什么」这一栏是刻意直白的：一个不满足前置条件的用户点「启动隧道」
     * 只会拿到一个错误，不如提前告诉他要去装什么、去登录什么。
     */
    const PROVIDER_COPY = {
      off: {
        title: '关闭',
        what: '不对外暴露任何东西。dsh web 只在本机可用。',
        needs: '',
      },
      cloudflared: {
        title: 'Cloudflare 临时隧道',
        what: '免费、免注册，立刻得到一个临时公网地址。',
        needs:
          '需要本机装有 cloudflared。地址每次重启都会变；Quick Tunnel 不支持 SSE，' +
          '所以插件热更新在远程不生效（对话、工具、审批走 WebSocket，不受影响）。' +
          '另外它要先连上 api.trycloudflare.com 才能申请到地址 —— ' +
          '如果你的网络需要代理、或者会拦 Cloudflare，它会一直超时；' +
          '这种情况下换成 Tailscale 会稳定得多。',
      },
      tailscale: {
        title: 'Tailscale Funnel',
        what: '免费、地址永久固定（xxx.ts.net），SSE 和 WebSocket 都正常。',
        needs:
          '需要一个 Tailscale 账号，并完成过一次 tailscale up；' +
          '还要在 tailnet 里开启 HTTPS 证书。Funnel 只支持 443 / 8443 / 10000 三个端口。',
      },
      custom: {
        title: '自定义命令',
        what: '任何能打印出公网 https:// 地址的命令都行。',
        needs:
          '命令启动后需要在 stdout 或 stderr 打印出公网地址。参数里写 {port} 会被替换成代理端口。',
      },
    }

    const css = `
.dt-root{max-width:760px;display:flex;flex-direction:column;gap:14px;color:inherit;font-size:13px}
.dt-card{border:1px solid var(--dsh-border,#30363d);border-radius:10px;padding:14px 16px;
background:var(--dsh-surface,#161b22)}
.dt-title{font-weight:600;font-size:14px;margin:0 0 8px;display:flex;align-items:center;gap:8px}
.dt-row{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:6px 0}
.dt-hint{color:var(--dsh-text-secondary,#8b949e);line-height:1.65;font-size:12.5px}
.dt-mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px;
background:var(--dsh-surface-2,#0d1117);border:1px solid var(--dsh-border,#30363d);
border-radius:6px;padding:6px 9px;word-break:break-all;flex:1;min-width:200px}
.dt-btn{border:1px solid var(--dsh-border,#30363d);border-radius:7px;padding:6px 12px;
background:var(--dsh-surface-2,#21262d);color:inherit;font:inherit;font-size:12.5px;cursor:pointer}
.dt-btn:hover:not(:disabled){background:var(--dsh-hover,#30363d)}
.dt-btn:disabled{opacity:.5;cursor:not-allowed}
.dt-btn-primary{background:#238636;border-color:#2ea043;color:#fff}
.dt-btn-primary:hover:not(:disabled){background:#2ea043}
.dt-btn-danger{background:#7d1c1c;border-color:#a83232;color:#fff}
.dt-tabs{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px}
.dt-tab{border:1px solid var(--dsh-border,#30363d);border-radius:7px;padding:6px 12px;
background:transparent;color:inherit;font:inherit;font-size:12.5px;cursor:pointer}
.dt-tab.on{background:#1f6feb;border-color:#1f6feb;color:#fff}
.dt-field{display:flex;flex-direction:column;gap:4px;margin:8px 0}
.dt-field label{font-size:12px;color:var(--dsh-text-secondary,#8b949e)}
.dt-field input{background:var(--dsh-surface-2,#0d1117);border:1px solid var(--dsh-border,#30363d);
border-radius:6px;padding:7px 9px;color:inherit;font:inherit;font-size:12.5px}
.dt-dot{width:8px;height:8px;border-radius:50%;display:inline-block;flex:none}
.dt-dot.on{background:#3fb950}.dt-dot.off{background:#6e7681}
.dt-err{color:#f85149;font-size:12.5px;line-height:1.6;margin-top:8px;word-break:break-word}
.dt-warn{color:#d29922;font-size:12.5px;line-height:1.6;margin-top:8px}
.dt-ok{color:#3fb950;font-size:12.5px;line-height:1.6;margin-top:8px}
`

    /** 每个页面只注入一次样式表，带 id 方便 HMR 清理。 */
    if (typeof document !== 'undefined' && !document.getElementById('dsh-tunnel-css')) {
      const style = document.createElement('style')
      style.id = 'dsh-tunnel-css'
      style.textContent = css
      document.head.appendChild(style)
    }

    /**
     * 与 Host 半通信。
     *
     * 控制令牌来自 status 响应，改动类操作必须原样带上：它证明调用方确实
     * 加载过这个面板，而不是本机某个别的进程在回环上碰运气。
     */
    const api = async (path, { method = 'GET', body, token } = {}) => {
      const response = await fetch(path, {
        method,
        headers: {
          ...(body ? { 'content-type': 'application/json' } : {}),
          ...(token ? { 'x-dsh-tunnel-token': token } : {}),
        },
        body: body ? JSON.stringify(body) : undefined,
      })
      const text = await response.text()
      let parsed
      try {
        parsed = text ? JSON.parse(text) : {}
      } catch {
        parsed = { error: text.slice(0, 200) }
      }
      if (!response.ok) throw new Error(parsed.error || `HTTP ${response.status}`)
      return parsed
    }

    /** 一行输入框，标签在上、输入在下。 */
    const Field = ({ label, value, placeholder, onChange, type = 'text' }) =>
      h('div', { className: 'dt-field' },
        h('label', null, label),
        h('input', {
          type,
          value: value || '',
          placeholder: placeholder || '',
          spellCheck: false,
          onChange: (event) => onChange(event.target.value),
        }))

    /** 「标签 + 等宽值 + 复制按钮」的一行。 */
    const CopyRow = ({ label, value }) => {
      const [copied, setCopied] = useState(false)
      const copy = () => {
        try {
          void navigator.clipboard.writeText(value)
          setCopied(true)
          setTimeout(() => setCopied(false), 1500)
        } catch {
          /* 剪贴板被拒时，文字本身仍可手动选中 */
        }
      }
      return h('div', { className: 'dt-row' },
        h('span', { className: 'dt-hint', style: { minWidth: 68 } }, label),
        h('code', { className: 'dt-mono' }, value),
        h('button', { className: 'dt-btn', type: 'button', onClick: copy }, copied ? '已复制' : '复制'))
    }

    /**
     * 面板本体。
     *
     * 全部 UI 都由同一个 status 对象驱动，所以不会出现「界面显示 A、宿主状态是 B」
     * 的情况 —— 是刻意不做本地乐观更新的。
     */
    const TunnelPanel = () => {
      const [status, setStatus] = useState(null)
      const [error, setError] = useState('')
      const [busy, setBusy] = useState('')
      const [selected, setSelected] = useState('off')
      const [draft, setDraft] = useState({ cloudflared: {}, tailscale: {}, custom: {} })
      const mounted = useRef(true)
      /** Whether the provider tabs have been seeded from the live snapshot. */
      const seeded = useRef(false)

      useEffect(() => () => { mounted.current = false }, [])

      const load = useCallback(async () => {
        try {
          const next = await api(STATUS)
          if (!mounted.current) return
          setStatus(next)
          setError('')
          // Seed the tab from what is actually running, but only once: after that
          // the user's own choice wins, otherwise clicking 「关闭」 to read its
          // description would snap back on the next poll.
          if (!seeded.current && next.provider !== 'off') {
            seeded.current = true
            setSelected(next.provider)
          }
        } catch (cause) {
          if (mounted.current) setError(String(cause.message || cause))
        }
      }, [])

      useEffect(() => {
        void load()
        const timer = setInterval(() => { void load() }, POLL_MS)
        return () => clearInterval(timer)
      }, [load])

      // 首次拿到状态时，用宿主里真实生效的值填进表单，而不是留占位符让用户重打一遍。
      useEffect(() => {
        if (!status) return
        setDraft((current) => ({
          cloudflared: Object.keys(current.cloudflared).length
            ? current.cloudflared
            : (status.config && status.config.cloudflared) || {},
          tailscale: Object.keys(current.tailscale).length
            ? current.tailscale
            : (status.config && status.config.tailscale) || {},
          custom: Object.keys(current.custom).length
            ? current.custom
            : (status.config && status.config.custom) || {},
        }))
      }, [status && status.provider])

      const act = async (key, run) => {
        setBusy(key)
        setError('')
        try {
          await run()
          await load()
        } catch (cause) {
          setError(String(cause.message || cause))
        } finally {
          setBusy('')
        }
      }

      const token = (status && status.controlToken) || ''
      const running = Boolean(status && status.publicUrl)

      // Who is looking at this panel.
      //
      // `remote` is set by the host when the page was reached through the tunnel.
      // A viewer may use dsh web but cannot control the tunnel: the server strips
      // the control token and the access key from that snapshot, so the buttons
      // below would only ever produce a 403. Better to say so than to fail.
      const remote = Boolean(status && status.remote)
      const readOnly = remote

      // Which provider is actually in effect. `tunnelProvider` names the running
      // tunnel; `provider` is only the configured default. Starting from the
      // panel does not rewrite the profile patch, so trusting `provider` made a
      // live tunnel read 「提供者：关闭」 next to 「已对外开放」.
      const effective = (status && (status.tunnelProvider || status.provider)) || 'off'
      // The patch value, for the "this won't survive a restart" note.
      const configured = (status && status.configuredProvider) || (status && status.provider) || 'off'
      const manual = running && configured !== effective && !readOnly

      const saveAndStart = (id) =>
        act('start', async () => {
          if (draft[id] && Object.keys(draft[id]).length) {
            await api(CONFIG, { method: 'POST', body: { [id]: draft[id] }, token })
          }
          await api(START, { method: 'POST', body: { provider: id }, token })
        })

      const copy = PROVIDER_COPY[selected] || PROVIDER_COPY.off

      const providerTab = (id) =>
        h('button', {
          key: id,
          type: 'button',
          className: 'dt-tab' + (selected === id ? ' on' : ''),
          disabled: readOnly,
          onClick: () => setSelected(id),
        }, PROVIDER_COPY[id].title)

      /** 只读模式下，操作区换成一句解释，而不是一片点不动的按钮。 */
      const readOnlyNotice = () =>
        h('div', { className: 'dt-card', style: { borderColor: '#8a6d1f' } },
          h('div', { className: 'dt-title' }, '当前是只读视图'),
          h('div', { className: 'dt-hint' },
            '你正通过公网隧道访问，所以这个面板只能看，不能改 —— ' +
            '否则任何拿到链接的人都能停掉隧道、或者在这台电脑上执行命令。' +
            '要调整设置，请直接在运行 dsh web 的那台电脑上打开本页。'))

      return h('div', { className: 'dt-root' },
        // ── 当前状态 ────────────────────────────────────────────────────────
        h('div', { className: 'dt-card' },
          h('div', { className: 'dt-title' },
            h('span', { className: 'dt-dot ' + (running ? 'on' : 'off') }),
            '隧道',
            h('span', { className: 'dt-hint', style: { marginLeft: 'auto' } },
              running ? '已对外开放' : '未对外开放')),
          status === null
            ? h('div', { className: 'dt-hint' }, '正在读取状态…')
            : h('div', null,
                h('div', { className: 'dt-hint' },
                  `提供者：${(PROVIDER_COPY[effective] || {}).title || effective} · ` +
                  `代理${status.proxyRunning ? '运行中' : '已停止'}（${status.host}:${status.port}）· ` +
                  `会话${status.hasSession ? '已就绪' : '准备中'} · ` +
                  `上游 ${status.upstream || '未知'}`),
                running
                  ? h('div', { style: { marginTop: 8 } },
                      h(CopyRow, { label: '公网地址', value: status.publicUrl }),
                      // The key is absent from a remote snapshot, so only offer
                      // the sign-in link where the key actually exists.
                      //
                      // The link points at the form, not at `/?key=…`: a key in a
                      // query string is in the URL, and the tunnel provider logs
                      // the URL before this process ever sees it. The form posts
                      // the key in a body instead.
                      status.accessKey
                        ? h(CopyRow, {
                            label: '登录入口',
                            value: `${status.publicUrl}/__tunnel`,
                          })
                        : null)
                  : null,
                status.tunnelCommand
                  ? h('div', { className: 'dt-hint', style: { marginTop: 6 } },
                      '实际执行的命令：', h('code', { className: 'dt-mono' }, status.tunnelCommand))
                  : null,
                status.lastError ? h('div', { className: 'dt-err' }, status.lastError) : null,
                manual
                  ? h('div', { className: 'dt-hint', style: { marginTop: 6 } },
                      '注意：这次是面板里手动开的，没有写进配置文件，' +
                      'dsh web 重启后不会自动恢复。想开机就开，把 profile 里的 ' +
                      `provider 改成 "${effective}"。`)
                  : null,
                error && error !== status.lastError ? h('div', { className: 'dt-err' }, error) : null,
                !status.hasSession
                  ? h('div', { className: 'dt-hint', style: { marginTop: 6 } },
                      '还没拿到 dsh web 的会话 Cookie。代理在这期间会返回 503，' +
                      '等 dsh web 启动完成就会自动恢复，通常几秒内。')
                  : null)),

        // ── 访问密钥 ────────────────────────────────────────────────────────
        // 远程视图拿不到密钥本身（服务端已经剥掉），所以这一块整段不渲染 ——
        // 显示一张空卡片比不显示更容易让人误以为密钥「没了」。
        readOnly
          ? readOnlyNotice()
          : h('div', { className: 'dt-card' },
              h('div', { className: 'dt-title' }, '访问密钥'),
              h('div', { className: 'dt-hint' },
                '任何能连到隧道地址的人都必须先出示这个密钥，它在转发之前就被检查，' +
                '所以扫到你域名的机器人也只会拿到 401。'),
              status
                ? h('div', { style: { marginTop: 8 } },
                    h(CopyRow, { label: '密钥', value: status.accessKey }),
                    h('div', { className: 'dt-row' },
                      h('button', {
                        className: 'dt-btn dt-btn-danger',
                        type: 'button',
                        disabled: busy !== '',
                        onClick: () => act('key', () => api(REGENERATE, { method: 'POST', token })),
                      }, busy === 'key' ? '重置中…' : '重置密钥'),
                      h('span', { className: 'dt-hint' },
                        '重置后，所有用过旧密钥的设备都需要重新授权。')))
                : null),

        // ── 提供者选择 ──────────────────────────────────────────────────────
        // 只读视图下整张卡片不渲染：所有控件都会 403，留着只会误导。
        readOnly
          ? null
          : h('div', { className: 'dt-card' },
          h('div', { className: 'dt-title' }, '隧道提供者'),
          h('div', { className: 'dt-tabs' },
            ['off', 'cloudflared', 'tailscale', 'custom'].map(providerTab)),
          h('div', { className: 'dt-hint' }, copy.what),
          copy.needs ? h('div', { className: 'dt-warn' }, copy.needs) : null,

          selected === 'cloudflared'
            ? h('div', null,
                h(Field, {
                  label: 'cloudflared 路径（留空则从 PATH 里找）',
                  value: draft.cloudflared.path,
                  placeholder: 'C:\\Windows\\cloudflared.exe',
                  onChange: (value) =>
                    setDraft({ ...draft, cloudflared: { ...draft.cloudflared, path: value } }),
                }))
            : null,

          selected === 'tailscale'
            ? h('div', null,
                h(Field, {
                  label: 'tailscale 路径（留空则从 PATH 里找）',
                  value: draft.tailscale.path,
                  placeholder: 'C:\\Program Files\\Tailscale\\tailscale.exe',
                  onChange: (value) =>
                    setDraft({ ...draft, tailscale: { ...draft.tailscale, path: value } }),
                }),
                h(Field, {
                  label: 'Funnel 端口（只能是 443 / 8443 / 10000）',
                  value: String(draft.tailscale.port || (status && status.port) || 8443),
                  onChange: (value) =>
                    setDraft({ ...draft, tailscale: { ...draft.tailscale, port: value } }),
                }))
            : null,

          selected === 'custom'
            ? h('div', null,
                h(Field, {
                  label: '命令',
                  value: draft.custom.command,
                  placeholder: 'bore',
                  onChange: (value) =>
                    setDraft({ ...draft, custom: { ...draft.custom, command: value } }),
                }),
                h(Field, {
                  label: '参数（空格分隔，{port} 会被替换成代理端口）',
                  value: Array.isArray(draft.custom.args)
                    ? draft.custom.args.join(' ')
                    : draft.custom.args || '',
                  placeholder: 'local {port} --to bore.pub',
                  onChange: (value) =>
                    setDraft({
                      ...draft,
                      custom: { ...draft.custom, args: value.split(/\s+/).filter(Boolean) },
                    }),
                }))
            : null,

          h('div', { className: 'dt-row', style: { marginTop: 12 } },
            h('button', {
              className: 'dt-btn dt-btn-primary',
              type: 'button',
              disabled:
                busy !== '' ||
                (selected === effective && running),
              onClick: () => saveAndStart(selected),
            }, busy === 'start'
              ? '正在启动…'
              : selected === 'off'
                ? '保持不暴露'
                : '启动隧道'),
            h('button', {
              className: 'dt-btn',
              type: 'button',
              disabled: busy !== '' || (!(status && status.proxyRunning) && !running),
              onClick: () => act('stop', () => api(STOP, { method: 'POST', token })),
            }, busy === 'stop' ? '正在停止…' : '全部停止'),
            status && status.starting
              ? h('span', { className: 'dt-hint' }, '正在等待隧道返回公网地址…')
              : null)),

        // ── 能力边界 ────────────────────────────────────────────────────────
        h('div', { className: 'dt-card' },
          h('div', { className: 'dt-title' }, '这个插件不做的事'),
          h('div', { className: 'dt-hint' },
            '这里没有中继服务器，也没有端到端加密。流量是访客与隧道边缘之间的 TLS，' +
            '所以隧道提供方能看到明文。如果这关系重大，请用你自己搭的隧道，或者干脆不开。' +
            '另外也没有账号体系、设备列表和远程踢人 —— 这道门只有一把共享密钥。')))
    }
    /**
     * 侧栏入口的图标。
     *
     * 侧栏一行由两半组成：`main` panel 决定「这是一页、叫什么名字、排第几」，
     * `sidebar.panellist` 提供这一行左侧的图标。只注册 `main` 会得到一行没有图标的
     * 空白条目，只注册 panellist 则连行都不会出现。
     */
    const SidebarIcon = ({ size = 16 }) => {
      const s = Number(size) || 16
      return h('svg', {
        width: s,
        height: s,
        viewBox: '0 0 24 24',
        fill: 'none',
        stroke: 'currentColor',
        strokeWidth: 1.7,
        strokeLinecap: 'round',
        strokeLinejoin: 'round',
        'aria-hidden': 'true',
      },
        // 一条从方框穿出去的线 = 隧道
        h('rect', { x: 3, y: 9, width: 8, height: 6, rx: 1.5 }),
        h('path', { d: 'M11 12h4' }),
        h('circle', { cx: 19, cy: 12, r: 2.4 }),
      )
    }

    /**
     * `main` panel 的页面内容。
     *
     * ## 为什么这里必须自己滚动
     *
     * 侧栏面板挂在 `.centerCol` 里，而那个容器是 `display:flex; flex-direction:
     * column; overflow:hidden` —— 它**不会**替内容滚动，超出的部分直接被裁掉，
     * 连滚动条都不出现。所以 main 面板的根元素必须**既是列容器、又是滚动容器**
     * （`height:100%` + `min-height:0` + `overflow:auto`），这是产品里每个 main
     * 面板的共同形状。
     *
     * 设置页和「插件」页不一样：它们的宿主容器自带 `overflow-y:auto`，
     * 面板在那里**不该**再声明高度，否则会出现两个滚动条。所以这里不复用
     * `TunnelPanel`，而是给它套一层滚动外壳 —— 同一份内容，两种容器语义。
     */
    const TunnelPage = () =>
      h('div', {
        style: {
          height: '100%',
          minHeight: 0,
          overflowY: 'auto',
          overflowX: 'hidden',
          // 手机上惯性滚动要能穿过面板，而不是把整页带走
          overscrollBehavior: 'contain',
          WebkitOverflowScrolling: 'touch',
          boxSizing: 'border-box',
          // 底部留出手机手势条的安全区，否则最后一行按钮贴着屏幕边缘
          padding: '24px 28px calc(24px + env(safe-area-inset-bottom, 0px))',
        },
      },
        h('div', { style: { margin: '0 auto', maxWidth: 860, width: '100%' } },
          h(TunnelPanel)))

    /**
     * 入口注册。
     *
     * 只注册**两处**，都是「一个入口一页」的形态：
     *   - 侧栏「插件 / 用量统计」下面一行 —— 主入口；
     *   - 设置页「隧道」栏目 —— 侧栏收起时仍能进去。
     *
     * 早先在 `plugins.item` 也注册过一张卡，现已去掉：那个槽位是给「有配置表单
     * 要填」的插件用的，页面会把入口渲染成整块内联内容塞进「插件」页的列表里。
     * 隧道面板是一整个操作台（状态、密钥、提供者选择），塞进去只会把插件页撑得
     * 又长又乱，而且和上面那两处重复。
     *
     * 每一处都单独 try/catch：任何一处失败都只丢一个入口，
     * 绝不拖累整个 web app（客户端插件抛异常会让 dsh web 起不来）。
     */
    exports.inject = ['slots']

    exports.apply = (ctx) => {
      /** 注册一个槽位，吞掉所有异常；返回 disposer 或 undefined。 */
      const safe = (slot, options, component) => {
        try {
          return ctx.slots.inject(slot, () => {
            const dispose = ctx.slots.register({ name: slot, ...options }, component)
            return typeof dispose === 'function' ? dispose : undefined
          })
        } catch {
          return undefined
        }
      }

      // ① 侧栏一行：`main` panel 提供这一页，`sidebar.panellist` 提供图标。
      //    order 越小越靠上；插件(0) / 用量统计 都在前面，这里排在它们后面。
      try {
        ctx.slots.inject('main', () => {
          const dispose = ctx.slots.register(
            {
              name: 'main',
              key: 'dsh-tunnel',
              order: 20,
              label: () => '隧道',
              locale: undefined,
            },
            TunnelPage,
          )
          return typeof dispose === 'function' ? dispose : undefined
        })
        ctx.slots.inject('sidebar.panellist', () => {
          const dispose = ctx.slots.register(
            {
              name: 'sidebar.panellist',
              id: 'dsh-tunnel',
              order: 20,
              label: () => '隧道',
            },
            SidebarIcon,
          )
          return typeof dispose === 'function' ? dispose : undefined
        })
      } catch {
        /* 老宿主没有 main 槽位：设置页入口仍在 */
      }

      // ② 设置页栏目。宿主容器自己会滚动（`.wCInkW_options{overflow-y:auto}`），
      //    所以这里直接给面板本体，不要再套 TunnelPage 的滚动外壳。
      safe(
        'settings.section',
        { id: 'dsh-tunnel', order: 40, label: () => '隧道' },
        TunnelPanel,
      )

      // ③ 不再注册 `plugins.item`：「插件」页不该出现隧道卡片。
    }

    return module.exports
  },
})
