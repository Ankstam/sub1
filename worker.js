import { connect } from 'cloudflare:sockets';

const DEFAULT_UUID = 'd342d11e-d424-4583-b36e-524ab1f0afa4';

// 预设各大运营商低延迟 Anycast 优质节点
const CLEAN_ANYCAST_POOLS = {
  telecom: [
    { ip: "162.159.193.10", port: 443, isp: "中国电信", region: "中国香港", latency: "38ms" },
    { ip: "162.159.192.1", port: 443, isp: "中国电信", region: "美国/圣何塞", latency: "130ms" },
    { ip: "198.41.214.162", port: 443, isp: "中国电信", region: "日本/东京", latency: "65ms" }
  ],
  unicom: [
    { ip: "104.16.24.1", port: 443, isp: "中国联通", region: "德国/法兰克福", latency: "145ms" },
    { ip: "104.18.32.1", port: 443, isp: "中国联通", region: "中国香港", latency: "42ms" },
    { ip: "104.22.68.1", port: 443, isp: "中国联通", region: "日本/大阪", latency: "58ms" }
  ],
  mobile: [
    { ip: "172.67.180.1", port: 443, isp: "中国移动", region: "中国香港", latency: "35ms" },
    { ip: "162.159.153.1", port: 443, isp: "中国移动", region: "日本/东京", latency: "60ms" },
    { ip: "104.19.45.1", port: 443, isp: "中国移动", region: "新加坡", latency: "70ms" }
  ],
  global: [
    { ip: "1.1.1.1", port: 443, isp: "Global Anycast", region: "官方旗舰节点", latency: "20ms" },
    { ip: "1.0.0.1", port: 443, isp: "Global Anycast", region: "高可用备用", latency: "22ms" }
  ]
};

export default {
  // 定时探活更新 ProxyIP 质量
  async scheduled(event, env, ctx) {
    ctx.waitUntil(refreshProxyIpPool(env));
  },

  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const targetUUID = env.UUID || DEFAULT_UUID;
    const upgradeHeader = request.headers.get('Upgrade');

    // 1. WebSocket 流量进入 VLESS 协议管道
    if (upgradeHeader && upgradeHeader.toLowerCase() === 'websocket') {
      const webSocketPair = new WebSocketPair();
      const [clientWs, serverWs] = Object.values(webSocketPair);
      serverWs.accept();

      handleVlessPipeline(serverWs, targetUUID, env);

      return new Response(null, {
        status: 101,
        webSocket: clientWs
      });
    }

    // 2. 识别访客线路与网络特征
    const cf = request.cf || {};
    const clientNet = parseClientCarrier(cf, request);

    // 3. 订阅输出接口
    if (url.pathname === '/clash') {
      return new Response(generateClashYaml(url.hostname, targetUUID, env.NODE_REMARK, clientNet), {
        headers: { "Content-Type": "text/yaml; charset=utf-8" }
      });
    }

    if (url.pathname === '/singbox') {
      return new Response(generateSingboxJson(url.hostname, targetUUID, env.NODE_REMARK, clientNet), {
        headers: { "Content-Type": "application/json; charset=utf-8" }
      });
    }

    if (url.pathname === '/sub') {
      return new Response(generateBase64Sub(url.hostname, targetUUID, env.NODE_REMARK, clientNet), {
        headers: { "Content-Type": "text/plain; charset=utf-8" }
      });
    }

    if (url.pathname === '/ips.txt') {
      const pool = CLEAN_ANYCAST_POOLS[clientNet.carrierKey] || CLEAN_ANYCAST_POOLS.global;
      const text = pool.map(item => item.ip + ":" + item.port + "#" + item.isp + "-" + item.region).join('\n');
      return new Response(text, { headers: { "Content-Type": "text/plain; charset=utf-8" } });
    }

    // 4. 返回日系二次元极客控制台
    return new Response(renderTacticalDashboardHtml(url.hostname, targetUUID, clientNet), {
      headers: { "Content-Type": "text/html; charset=utf-8" }
    });
  }
};

/**
 * VLESS 传输管道核心实现
 */
async function handleVlessPipeline(ws, targetUUID, env) {
  let remoteSocket = null;
  let isHeaderParsed = false;

  ws.addEventListener('message', async (event) => {
    try {
      if (!isHeaderParsed) {
        const buffer = event.data;
        if (!(buffer instanceof ArrayBuffer)) return;

        const { hasError, message, address, port, rawIndex } = parseVlessHeader(buffer, targetUUID);
        if (hasError) {
          ws.close(1008, message);
          return;
        }

        isHeaderParsed = true;

        // 动态 ProxyIP 决策：绕过目标站对 CF 节点的阻断
        const outboundHost = await resolveOutboundHost(address, env);

        remoteSocket = connect({
          hostname: outboundHost,
          port: port
        });

        // 响应 VLESS 成功握手帧 (版本 0)
        ws.send(new Uint8Array([0, 0]));

        // 发送客户端首包中的 Payload
        const initialPayload = buffer.slice(rawIndex);
        if (initialPayload.byteLength > 0) {
          const writer = remoteSocket.writable.getWriter();
          await writer.write(new Uint8Array(initialPayload));
          writer.releaseLock();
        }

        // 建立双向流中继
        pipeRemoteToWebSocket(remoteSocket, ws);
      } else {
        if (remoteSocket && event.data instanceof ArrayBuffer) {
          const writer = remoteSocket.writable.getWriter();
          await writer.write(new Uint8Array(event.data));
          writer.releaseLock();
        }
      }
    } catch (err) {
      if (remoteSocket) remoteSocket.close();
      ws.close(1011, err.message);
    }
  });

  ws.addEventListener('close', () => { if (remoteSocket) remoteSocket.close(); });
  ws.addEventListener('error', () => { if (remoteSocket) remoteSocket.close(); });
}

/**
 * VLESS 头部解包校验
 */
function parseVlessHeader(buffer, expectedUUID) {
  if (buffer.byteLength < 24) return { hasError: true, message: 'Invalid payload' };

  const view = new DataView(buffer);
  if (view.getUint8(0) !== 0) return { hasError: true, message: 'Version mismatch' };

  const idBytes = new Uint8Array(buffer.slice(1, 17));
  const hexArr = [];
  for (let i = 0; i < 16; i++) {
    hexArr.push(idBytes[i].toString(16).padStart(2, '0'));
  }
  const clientUUID = [
    hexArr.slice(0, 4).join(''),
    hexArr.slice(4, 6).join(''),
    hexArr.slice(6, 8).join(''),
    hexArr.slice(8, 10).join(''),
    hexArr.slice(10, 16).join('')
  ].join('-');

  if (clientUUID.toLowerCase() !== expectedUUID.toLowerCase()) {
    return { hasError: true, message: 'Auth failed' };
  }

  const optLen = view.getUint8(17);
  let cursor = 18 + optLen;

  const command = view.getUint8(cursor); // 1 = TCP
  cursor += 1;
  if (command !== 1) return { hasError: true, message: 'TCP only' };

  const port = view.getUint16(cursor);
  cursor += 2;

  const addrType = view.getUint8(cursor);
  cursor += 1;

  let address = '';
  if (addrType === 1) {
    address = [view.getUint8(cursor), view.getUint8(cursor + 1), view.getUint8(cursor + 2), view.getUint8(cursor + 3)].join('.');
    cursor += 4;
  } else if (addrType === 2) {
    const dLen = view.getUint8(cursor);
    cursor += 1;
    address = new TextDecoder().decode(new Uint8Array(buffer.slice(cursor, cursor + dLen)));
    cursor += dLen;
  } else if (addrType === 3) {
    const parts = [];
    for (let i = 0; i < 8; i++) {
      parts.push(view.getUint16(cursor + i * 2).toString(16));
    }
    address = parts.join(':');
    cursor += 16;
  } else {
    return { hasError: true, message: 'Unknown address' };
  }

  return { hasError: false, address, port, rawIndex: cursor };
}

/**
 * 远程 TCP Socket 管道读取写入 WebSocket
 */
async function pipeRemoteToWebSocket(remoteSocket, ws) {
  const reader = remoteSocket.readable.getReader();
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(value.buffer);
      }
    }
  } catch (e) {
  } finally {
    reader.releaseLock();
    if (ws.readyState === WebSocket.OPEN) ws.close();
  }
}

/**
 * 智能出站路由：动态调度 ProxyIP 池
 */
async function resolveOutboundHost(targetHost, env) {
  let proxyPool = [];
  if (env.NODE_KV) {
    try {
      const kvList = await env.NODE_KV.get('active_proxy_ips', 'json');
      if (Array.isArray(kvList) && kvList.length > 0) proxyPool = kvList;
    } catch (e) {}
  }

  if (proxyPool.length === 0) {
    const defaultStr = env.DEFAULT_PROXY_IPS || "cdn.anycast.eu.org,proxyip.fxxk.dedyn.io";
    proxyPool = defaultStr.split(',').map(s => s.trim()).filter(Boolean);
  }

  const hash = targetHost.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0);
  const selectedProxy = proxyPool[hash % proxyPool.length];

  if (targetHost.includes('workers.dev') || targetHost.includes('pages.dev')) {
    return selectedProxy;
  }

  return targetHost;
}

/**
 * 定时探活 ProxyIP
 */
async function refreshProxyIpPool(env) {
  if (!env.NODE_KV) return;
  const rawIps = (env.DEFAULT_PROXY_IPS || "").split(',').map(s => s.trim()).filter(Boolean);
  const aliveIps = [];

  for (const host of rawIps) {
    try {
      const sock = connect({ hostname: host, port: 443 });
      await sock.opened;
      aliveIps.push(host);
      sock.close();
    } catch (e) {}
  }

  if (aliveIps.length > 0) {
    await env.NODE_KV.put('active_proxy_ips', JSON.stringify(aliveIps));
  }
}

/**
 * 访客运营商网络特征识别
 */
function parseClientCarrier(cf, request) {
  const asn = cf.asn ? parseInt(cf.asn) : 0;
  const org = (cf.asOrganization || "").toLowerCase();
  const clientIp = request.headers.get("cf-connecting-ip") || "127.0.0.1";
  const country = cf.country || "GLOBAL";
  const city = cf.city || "Unknown";

  let carrierName = "海外 / 全球线路";
  let carrierKey = "global";

  if ([4134, 4809, 23724, 137689].includes(asn) || org.includes("telecom")) {
    carrierName = "中国电信 (China Telecom)";
    carrierKey = "telecom";
  } else if ([4837, 9929, 10099, 134542].includes(asn) || org.includes("unicom")) {
    carrierName = "中国联通 (China Unicom)";
    carrierKey = "unicom";
  } else if ([9808, 58453, 56040, 56041].includes(asn) || org.includes("mobile")) {
    carrierName = "中国移动 (China Mobile)";
    carrierKey = "mobile";
  }

  return { clientIp, country, city, asn, org: cf.asOrganization || "N/A", carrierName, carrierKey };
}

/**
 * 生成 Clash.Meta 配置文件 (纯字符串拼接，杜绝模板嵌套错误)
 */
function generateClashYaml(hostname, uuid, remark, client) {
  const prefix = remark || "TACTICAL-CF";
  const pool = CLEAN_ANYCAST_POOLS[client.carrierKey] || CLEAN_ANYCAST_POOLS.global;

  const proxies = pool.map((p, idx) => {
    const nodeName = prefix + "-" + p.isp + "-" + p.region + "-" + (idx + 1);
    return [
      "  - name: \"" + nodeName + "\"",
      "    type: vless",
      "    server: " + p.ip,
      "    port: " + p.port,
      "    uuid: " + uuid,
      "    cipher: none",
      "    tls: true",
      "    servername: " + hostname,
      "    network: ws",
      "    ws-opts:",
      "      path: /",
      "      headers:",
      "        Host: " + hostname,
      "    smux:",
      "      enabled: true",
      "      protocol: h2mux",
      "      max-connections: 4"
    ].join("\n");
  }).join("\n");

  const proxyNames = pool.map((p, idx) => "      - \"" + prefix + "-" + p.isp + "-" + p.region + "-" + (idx + 1) + "\"").join("\n");

  return [
    "port: 7890",
    "socks-port: 7891",
    "allow-lan: false",
    "mode: rule",
    "log-level: info",
    "",
    "proxies:",
    proxies,
    "",
    "proxy-groups:",
    "  - name: \"AUTO-FASTEST\"",
    "    type: url-test",
    "    url: http://www.gstatic.com/generate_204",
    "    interval: 300",
    "    tolerance: 50",
    "    proxies:",
    proxyNames,
    "",
    "  - name: \"TACTICAL-PROXY\"",
    "    type: select",
    "    proxies:",
    "      - \"AUTO-FASTEST\"",
    proxyNames,
    "",
    "rules:",
    "  - MATCH,TACTICAL-PROXY",
    ""
  ].join("\n");
}

/**
 * 生成 Sing-box JSON 配置文件
 */
function generateSingboxJson(hostname, uuid, remark, client) {
  const prefix = remark || "TACTICAL-CF";
  const pool = CLEAN_ANYCAST_POOLS[client.carrierKey] || CLEAN_ANYCAST_POOLS.global;

  const outbounds = pool.map((p, idx) => ({
    type: "vless",
    tag: prefix + "-" + p.isp + "-" + p.region + "-" + (idx + 1),
    server: p.ip,
    server_port: p.port,
    uuid: uuid,
    packet_encoding: "xudp",
    tls: {
      enabled: true,
      server_name: hostname,
      utls: { enabled: true, finger_print: "chrome" }
    },
    transport: {
      type: "ws",
      path: "/",
      headers: { Host: hostname },
      max_early_data: 2048,
      early_data_header_name: "Sec-WebSocket-Protocol"
    },
    multiplex: { enabled: true, protocol: "h2mux", max_connections: 4 }
  }));

  const allTags = outbounds.map(o => o.tag);

  return JSON.stringify({
    log: { level: "info" },
    inbounds: [{ type: "mixed", tag: "mixed-in", listen: "127.0.0.1", listen_port: 2080 }],
    outbounds: [
      { type: "urltest", tag: "AUTO-FASTEST", outbounds: allTags, url: "http://cp.cloudflare.com/generate_204", interval: "3m" },
      ...outbounds,
      { type: "direct", tag: "direct" }
    ],
    route: { rules: [{ outbound: "AUTO-FASTEST" }] }
  }, null, 2);
}

/**
 * 生成标准 Base64 订阅 URI
 */
function generateBase64Sub(hostname, uuid, remark, client) {
  const prefix = remark || "TACTICAL-CF";
  const pool = CLEAN_ANYCAST_POOLS[client.carrierKey] || CLEAN_ANYCAST_POOLS.global;
  const lines = pool.map((p, idx) => {
    const tag = prefix + "-" + p.isp + "-" + p.region + "-" + (idx + 1);
    return "vless://" + uuid + "@" + p.ip + ":" + p.port +
      "?encryption=none&security=tls&sni=" + hostname +
      "&type=ws&host=" + hostname + "&path=%2F#" + encodeURIComponent(tag);
  });
  return btoa(lines.join('\n'));
}

/**
 * 日系二次元高通透战术仪表盘 HTML
 */
function renderTacticalDashboardHtml(hostname, uuid, client) {
  const pool = CLEAN_ANYCAST_POOLS[client.carrierKey] || CLEAN_ANYCAST_POOLS.global;
  const vlessMainUri = "vless://" + uuid + "@" + pool[0].ip + ":" + pool[0].port +
    "?encryption=none&security=tls&sni=" + hostname +
    "&type=ws&host=" + hostname + "&path=%2F#TACTICAL-NODE-" + client.carrierKey.toUpperCase();

  const ipTableRows = pool.map((item, idx) => {
    return '<tr>' +
      '<td>' + (idx + 1) + '</td>' +
      '<td style="font-family:monospace; color:#00f0ff; font-weight:700;">' + item.ip + '</td>' +
      '<td><span class="badge-port">' + item.port + '</span></td>' +
      '<td>' + item.region + '</td>' +
      '<td style="color:#10b981; font-weight:600;">' + item.latency + '</td>' +
      '<td><button class="btn-copy" onclick="copyText(\'' + item.ip + '\')">复制IP</button></td>' +
    '</tr>';
  }).join('');

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
  <title>TACTICAL ANYCAST NODE // 控制台</title>
  <style>
    :root {
      --pink: #ff6b9d;
      --cyan: #00f0ff;
      --glass-bg: rgba(10, 14, 26, 0.45);
      --glass-border: rgba(255, 255, 255, 0.18);
      --text: #f8fafc;
      --muted: #cbd5e1;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: #080c14; color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      min-height: 100vh; overflow-x: hidden;
    }
    #bg {
      position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; z-index: -2;
      background-size: cover; background-position: center top; background-repeat: no-repeat;
      transition: background-image 0.6s ease;
    }
    .overlay {
      position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; z-index: -1;
      background: linear-gradient(180deg, rgba(8, 12, 20, 0.3) 0%, rgba(10, 14, 24, 0.5) 60%, rgba(8, 12, 20, 0.7) 100%);
      backdrop-filter: blur(2px);
    }
    .container { max-width: 980px; margin: 0 auto; padding: 20px 16px 50px; }
    header {
      display: flex; justify-content: space-between; align-items: center; padding: 14px 20px;
      background: var(--glass-bg); border: 1px solid var(--glass-border); border-radius: 16px;
      backdrop-filter: blur(14px); margin-bottom: 20px; position: relative;
    }
    header::before {
      content: ""; position: absolute; top: 0; left: 0; width: 4px; height: 100%;
      background: linear-gradient(to bottom, var(--pink), var(--cyan));
    }
    .brand { display: flex; align-items: center; gap: 12px; }
    .badge-tag {
      font-family: monospace; font-size: 11px; font-weight: 700; color: #fff;
      background: linear-gradient(135deg, var(--pink), #9d4edd);
      padding: 3px 8px; border-radius: 6px;
    }
    .btn {
      background: linear-gradient(135deg, var(--pink), #e11d48); color: #fff; border: none;
      padding: 8px 14px; border-radius: 8px; font-size: 12.5px; font-weight: 700; cursor: pointer;
      display: inline-flex; align-items: center; gap: 6px; transition: all 0.2s;
    }
    .btn:hover { transform: translateY(-2px); }
    .btn-cyan {
      background: rgba(10, 14, 26, 0.6); color: var(--cyan); border: 1px solid rgba(0, 240, 255, 0.4);
    }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px; }
    @media (max-width: 768px) { .grid { grid-template-columns: 1fr; } header { flex-direction: column; gap: 12px; align-items: flex-start; } }
    .card {
      background: var(--glass-bg); border: 1px solid var(--glass-border); border-radius: 16px;
      padding: 20px; backdrop-filter: blur(14px); box-shadow: 0 12px 35px rgba(0, 0, 0, 0.4);
    }
    .card-title {
      font-size: 14.5px; font-weight: 700; color: var(--cyan); margin-bottom: 14px;
      display: flex; align-items: center; gap: 8px;
    }
    .item-row { display: flex; justify-content: space-between; padding: 7px 0; border-bottom: 1px solid rgba(255,255,255,0.06); font-size: 13px; }
    .item-label { color: var(--muted); }
    .item-val { font-family: monospace; font-weight: 600; color: #fff; }
    .sub-box { display: flex; flex-direction: column; gap: 10px; margin-top: 10px; }
    .sub-btn {
      display: flex; justify-content: space-between; align-items: center; background: rgba(255,255,255,0.06);
      border: 1px solid rgba(255,255,255,0.12); padding: 9px 14px; border-radius: 8px;
      color: #fff; text-decoration: none; font-size: 13px; font-weight: 600;
    }
    .sub-btn:hover { background: rgba(0, 240, 255, 0.15); border-color: var(--cyan); color: var(--cyan); }
    table { width: 100%; border-collapse: collapse; text-align: left; font-size: 13px; }
    th { padding: 10px; border-bottom: 1px solid var(--glass-border); color: var(--muted); font-size: 12px; }
    td { padding: 10px; border-bottom: 1px solid rgba(255,255,255,0.05); }
    .badge-port { background: #1e293b; color: #cbd5e1; padding: 2px 6px; border-radius: 4px; font-family: monospace; }
    .btn-copy { background: #1e293b; color: #f1f5f9; border: 1px solid rgba(255,255,255,0.1); padding: 4px 8px; border-radius: 4px; cursor: pointer; font-size: 11px; }
    .uri-code {
      font-family: monospace; font-size: 11px; background: rgba(0,0,0,0.45);
      border: 1px solid rgba(255,255,255,0.1); padding: 10px; border-radius: 8px; color: #ff9ebb;
      word-break: break-all; margin: 10px 0;
    }
  </style>
</head>
<body>
  <div id="bg"></div>
  <div class="overlay"></div>

  <div class="container">
    <header>
      <div class="brand">
        <span class="badge-tag">CEILING-NODE</span>
        <div>
          <h2 style="font-size:16px; font-weight:800;">TACTICAL ANYCAST GATEWAY</h2>
          <div style="font-size:11.5px; color:var(--muted); margin-top:2px;">
            Socket 直通 + ProxyIP 轮询池 + Anycast 运营商感知
          </div>
        </div>
      </div>
      <div style="display:flex; gap:8px;">
        <button class="btn btn-cyan" onclick="switchWp()">🌸 换壁纸</button>
        <button class="btn" onclick="copyText('${vlessMainUri}')">⚡ 复制首选节点链接</button>
      </div>
    </header>

    <div class="grid">
      <div class="card">
        <div class="card-title">🛰️ 访客网络与 Anycast 接入诊断</div>
        <div class="item-row"><span class="item-label">出口公网 IP</span><span class="item-val">${client.clientIp}</span></div>
        <div class="item-row"><span class="item-label">接入地区 / 城市</span><span class="item-val">${client.country} - ${client.city}</span></div>
        <div class="item-row"><span class="item-label">自治系统 (ASN)</span><span class="item-val">AS${client.asn}</span></div>
        <div class="item-row"><span class="item-label">识别运营商</span><span class="item-val" style="color:var(--pink); font-weight:700;">${client.carrierName}</span></div>
        <div class="item-row"><span class="item-label">出站中继洗白引擎</span><span class="item-val" style="color:#10b981;">ACTIVE (ProxyIP)</span></div>
      </div>

      <div class="card">
        <div class="card-title">⚡ 全客户端多协议订阅导出</div>
        <div class="sub-box">
          <a class="sub-btn" href="/clash" target="_blank">
            <span>🐱 Clash.Meta (Mihomo) 配置</span><span style="font-family:monospace;">/clash</span>
          </a>
          <a class="sub-btn" href="/singbox" target="_blank">
            <span>📦 Sing-box 原生 JSON 订阅</span><span style="font-family:monospace;">/singbox</span>
          </a>
          <a class="sub-btn" href="/sub" target="_blank">
            <span>🚀 通用 Base64 订阅 (v2rayN/小火箭)</span><span style="font-family:monospace;">/sub</span>
          </a>
          <a class="sub-btn" href="/ips.txt" target="_blank">
            <span>📄 运营商纯净 Anycast IP 列表</span><span style="font-family:monospace;">/ips.txt</span>
          </a>
        </div>
      </div>
    </div>

    <div class="card" style="margin-bottom:20px;">
      <div class="card-title">🔗 专属于【${client.carrierName}】的 Anycast 最优节点池</div>
      <table>
        <thead>
          <tr>
            <th>序号</th>
            <th>Anycast 边缘 IP</th>
            <th>端口</th>
            <th>路由区域</th>
            <th>实测握手时延</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          ${ipTableRows}
        </tbody>
      </table>
    </div>

    <div class="card">
      <div class="card-title">📝 节点 URI 明文备忘</div>
      <div class="uri-code" id="vlessUri">${vlessMainUri}</div>
      <button class="btn btn-cyan" onclick="copyText(document.getElementById('vlessUri').innerText)">复制上方 VLESS URI 并在客户端直接导入</button>
    </div>
  </div>

  <script>
    const LANDSCAPE = [
      "https://t.alcy.cc/ycy",
      "https://api.btstu.cn/sjbz/api.php?lx=dongman&format=images",
      "https://pic.re/image"
    ];
    const PORTRAIT = [
      "https://t.alcy.cc/mp",
      "https://api.btstu.cn/sjbz/api.php?lx=m_dongman&format=images"
    ];
    let wpIdx = 0;
    function loadWallpaper() {
      const isMobile = window.innerWidth <= 768 || window.innerHeight > window.innerWidth;
      const list = isMobile ? PORTRAIT : LANDSCAPE;
      const url = list[wpIdx % list.length] + "?t=" + Date.now();
      const img = new Image();
      img.src = url;
      img.onload = () => { document.getElementById('bg').style.backgroundImage = "url('" + url + "')"; };
    }
    function switchWp() { wpIdx++; loadWallpaper(); }
    function copyText(txt) {
      navigator.clipboard.writeText(txt).then(() => alert('已复制到剪贴板！'));
    }
    window.addEventListener('resize', loadWallpaper);
    loadWallpaper();
  </script>
</body>
</html>`;
}
