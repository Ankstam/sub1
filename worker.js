import { connect } from 'cloudflare:sockets';

const DEFAULT_UUID = 'd342d11e-d424-4583-b36e-524ab1f0afa4';

// 专属于中国大陆各主流运营商的低时延 Anycast 节点池
const CLEAN_POOLS = {
  mobile: [
    { ip: "172.67.180.1", port: 443, isp: "中国移动", region: "中国香港 (CMI极佳)" },
    { ip: "162.159.153.1", port: 443, isp: "中国移动", region: "日本/东京" },
    { ip: "104.19.45.1", port: 443, isp: "中国移动", region: "新加坡" }
  ],
  telecom: [
    { ip: "162.159.193.10", port: 443, isp: "中国电信", region: "中国香港" },
    { ip: "198.41.214.162", port: 443, isp: "中国电信", region: "日本/东京 (CN2友好)" },
    { ip: "162.159.192.1", port: 443, isp: "中国电信", region: "美国/圣何塞" }
  ],
  unicom: [
    { ip: "104.18.32.1", port: 443, isp: "中国联通", region: "中国香港" },
    { ip: "104.22.68.1", port: 443, isp: "中国联通", region: "日本/大阪" },
    { ip: "104.16.24.1", port: 443, isp: "中国联通", region: "德国/法兰克福" }
  ],
  global: [
    { ip: "1.1.1.1", port: 443, isp: "Global Anycast", region: "亚太旗舰节点" },
    { ip: "1.0.0.1", port: 443, isp: "Global Anycast", region: "官方备用节点" }
  ]
};

export default {
  async fetch(request, env) {
    try {
      const targetUUID = (env.UUID || DEFAULT_UUID).toLowerCase();
      const upgradeHeader = request.headers.get('Upgrade');

      // 1. WebSocket 流量进入 VLESS 数据管道
      if (upgradeHeader && upgradeHeader.toLowerCase() === 'websocket') {
        return await handleVlessStream(request, targetUUID, env.PROXYIP);
      }

      // 2. 识别访客所属运营商与地域
      const cf = request.cf || {};
      const clientNet = parseCarrier(cf, request);
      const url = new URL(request.url);

      // 3. 多协议订阅导出
      if (url.pathname === '/sub') {
        return new Response(generateBase64Sub(url.hostname, targetUUID, clientNet), {
          headers: { 'Content-Type': 'text/plain; charset=utf-8' }
        });
      }

      if (url.pathname === '/clash') {
        return new Response(generateClashYaml(url.hostname, targetUUID, clientNet), {
          headers: { 'Content-Type': 'text/yaml; charset=utf-8' }
        });
      }

      // 4. 默认返回交互控制台
      return new Response(renderDashboardHtml(url.hostname, targetUUID, clientNet), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    } catch (err) {
      return new Response(err.stack || err.message, { status: 500 });
    }
  }
};

/**
 * 标准单流双向中继管道 (无并发锁竞争，原生支持大带宽吞吐)
 */
async function handleVlessStream(request, targetUUID, customProxyIP) {
  const webSocketPair = new WebSocketPair();
  const [clientWs, serverWs] = Object.values(webSocketPair);
  serverWs.accept();

  let remoteSocket = null;
  let isHeaderResolved = false;

  const wsStream = new ReadableStream({
    start(controller) {
      serverWs.addEventListener('message', (e) => controller.enqueue(e.data));
      serverWs.addEventListener('close', () => controller.close());
      serverWs.addEventListener('error', (err) => controller.error(err));
    }
  });

  wsStream.pipeTo(new WritableStream({
    async write(chunk) {
      if (!(chunk instanceof ArrayBuffer)) return;

      if (isHeaderResolved) {
        if (remoteSocket) {
          const writer = remoteSocket.writable.getWriter();
          await writer.write(new Uint8Array(chunk));
          writer.releaseLock();
        }
        return;
      }

      // 解析 VLESS 头部
      const parsed = parseVlessHeader(chunk, targetUUID);
      if (parsed.hasError) {
        serverWs.close(1008, parsed.message);
        return;
      }

      isHeaderResolved = true;

      // 如果目标是 CF 自身网络，切至 ProxyIP 防回环；其余全网目标 100% 直连出站
      let outboundTarget = parsed.address;
      if (isCloudflareDomain(parsed.address) && customProxyIP) {
        outboundTarget = customProxyIP;
      }

      remoteSocket = connect({
        hostname: outboundTarget,
        port: parsed.port
      });

      // 发送 VLESS 握手成功响应 [0, 0]
      serverWs.send(new Uint8Array([0, 0]));

      // 推送首包携带的后续载荷
      if (parsed.rawPayload && parsed.rawPayload.byteLength > 0) {
        const writer = remoteSocket.writable.getWriter();
        await writer.write(new Uint8Array(parsed.rawPayload));
        writer.releaseLock();
      }

      // 将远程 TCP 响应直打回 WebSocket
      pipeRemoteToClient(remoteSocket, serverWs);
    },
    close() {
      if (remoteSocket) remoteSocket.close();
    },
    abort() {
      if (remoteSocket) remoteSocket.close();
    }
  })).catch(() => {
    if (serverWs.readyState === WebSocket.OPEN) {
      serverWs.close(1011, "Stream Error");
    }
  });

  return new Response(null, {
    status: 101,
    webSocket: clientWs
  });
}

function parseVlessHeader(buffer, targetUUID) {
  if (buffer.byteLength < 24) return { hasError: true, message: 'Data length invalid' };

  const view = new DataView(buffer);
  if (view.getUint8(0) !== 0) return { hasError: true, message: 'Version error' };

  // 提取并比对 UUID
  const idBytes = new Uint8Array(buffer.slice(1, 17));
  const hex = [];
  for (let i = 0; i < 16; i++) {
    hex.push(idBytes[i].toString(16).padStart(2, '0'));
  }
  const clientUUID = [
    hex.slice(0, 4).join(''),
    hex.slice(4, 6).join(''),
    hex.slice(6, 8).join(''),
    hex.slice(8, 10).join(''),
    hex.slice(10, 16).join('')
  ].join('-').toLowerCase();

  if (clientUUID !== targetUUID) {
    return { hasError: true, message: 'UUID Auth failed' };
  }

  const optLen = view.getUint8(17);
  let cursor = 18 + optLen;

  const command = view.getUint8(cursor);
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
    const domainLen = view.getUint8(cursor);
    cursor += 1;
    address = new TextDecoder().decode(new Uint8Array(buffer.slice(cursor, cursor + domainLen)));
    cursor += domainLen;
  } else if (addrType === 3) {
    const parts = [];
    for (let i = 0; i < 8; i++) {
      parts.push(view.getUint16(cursor + i * 2).toString(16));
    }
    address = parts.join(':');
    cursor += 16;
  } else {
    return { hasError: true, message: 'Address type unsupported' };
  }

  return {
    hasError: false,
    address,
    port,
    rawPayload: buffer.slice(cursor)
  };
}

async function pipeRemoteToClient(remoteSocket, ws) {
  const reader = remoteSocket.readable.getReader();
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(value);
      }
    }
  } catch (e) {
  } finally {
    reader.releaseLock();
    if (ws.readyState === WebSocket.OPEN) ws.close();
  }
}

function isCloudflareDomain(host) {
  const h = (host || '').toLowerCase();
  return h.includes('cloudflare.com') || h.includes('workers.dev') || h.includes('pages.dev');
}

function parseCarrier(cf, request) {
  const asn = cf.asn ? parseInt(cf.asn) : 0;
  const org = (cf.asOrganization || "").toLowerCase();
  const clientIp = request.headers.get("cf-connecting-ip") || "127.0.0.1";
  const city = cf.city || "Unknown";

  let carrierName = "海外 / 全球线路";
  let carrierKey = "global";

  if ([9808, 58453, 56040, 56041].includes(asn) || org.includes("mobile")) {
    carrierName = "中国移动 (China Mobile)";
    carrierKey = "mobile";
  } else if ([4134, 4809, 23724, 137689].includes(asn) || org.includes("telecom")) {
    carrierName = "中国电信 (China Telecom)";
    carrierKey = "telecom";
  } else if ([4837, 9929, 10099, 134542].includes(asn) || org.includes("unicom")) {
    carrierName = "中国联通 (China Unicom)";
    carrierKey = "unicom";
  }

  return { clientIp, city, asn, carrierName, carrierKey };
}

function generateBase64Sub(hostname, uuid, client) {
  const pool = CLEAN_POOLS[client.carrierKey] || CLEAN_POOLS.global;
  const lines = pool.map((item, idx) => {
    const remark = encodeURIComponent(`TACTICAL-${client.carrierKey.toUpperCase()}-${idx + 1}`);
    return `vless://${uuid}@${item.ip}:${item.port}?encryption=none&security=tls&sni=${hostname}&type=ws&host=${hostname}&path=%2F#${remark}`;
  });
  return btoa(lines.join('\n'));
}

function generateClashYaml(hostname, uuid, client) {
  const pool = CLEAN_POOLS[client.carrierKey] || CLEAN_POOLS.global;
  const proxies = pool.map((p, idx) => {
    return [
      `  - name: "CF-${p.isp}-${idx + 1}"`,
      `    type: vless`,
      `    server: ${p.ip}`,
      `    port: ${p.port}`,
      `    uuid: ${uuid}`,
      `    cipher: none`,
      `    tls: true`,
      `    servername: ${hostname}`,
      `    network: ws`,
      `    ws-opts:`,
      `      path: /`,
      `      headers:`,
      `        Host: ${hostname}`
    ].join('\n');
  }).join('\n');

  const names = pool.map((p, idx) => `      - "CF-${p.isp}-${idx + 1}"`).join('\n');

  return [
    `port: 7890`,
    `mode: rule`,
    `proxies:`,
    proxies,
    `proxy-groups:`,
    `  - name: "AUTO"`,
    `    type: url-test`,
    `    url: http://www.gstatic.com/generate_204`,
    `    interval: 300`,
    `    proxies:`,
    names,
    `rules:`,
    `  - MATCH,AUTO`
  ].join('\n');
}

function renderDashboardHtml(hostname, uuid, client) {
  const pool = CLEAN_POOLS[client.carrierKey] || CLEAN_POOLS.global;
  const firstNode = pool[0];
  const primaryUri = `vless://${uuid}@${firstNode.ip}:${firstNode.port}?encryption=none&security=tls&sni=${hostname}&type=ws&host=${hostname}&path=%2F#TACTICAL-${client.carrierKey.toUpperCase()}-01`;

  const rows = pool.map((p, i) => `
    <tr>
      <td>${i + 1}</td>
      <td style="font-family:monospace; color:#00f0ff; font-weight:700;">${p.ip}</td>
      <td>${p.port}</td>
      <td>${p.region}</td>
      <td><button class="btn-copy" onclick="copyVal('${p.ip}')">复制IP</button></td>
    </tr>
  `).join('');

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>TACTICAL ANYCAST NODE</title>
  <style>
    :root { --pink: #ff6b9d; --cyan: #00f0ff; --glass: rgba(10, 14, 26, 0.45); --border: rgba(255, 255, 255, 0.16); }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    body { background-color: #080c14; color: #f8fafc; min-height: 100vh; }
    #bg { position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; z-index: -2; background-size: cover; background-position: center top; transition: background-image 0.5s ease; }
    .overlay { position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; z-index: -1; background: linear-gradient(180deg, rgba(8,12,20,0.35) 0%, rgba(10,14,24,0.65) 100%); }
    .container { max-width: 900px; margin: 0 auto; padding: 20px 16px; }
    .card { background: var(--glass); border: 1px solid var(--border); border-radius: 14px; padding: 20px; backdrop-filter: blur(14px); margin-bottom: 16px; box-shadow: 0 10px 30px rgba(0,0,0,0.4); }
    .title { font-size: 14px; font-weight: 700; color: var(--cyan); margin-bottom: 12px; }
    .row { display: flex; justify-content: space-between; padding: 7px 0; border-bottom: 1px solid rgba(255,255,255,0.06); font-size: 13px; }
    .btn { background: linear-gradient(135deg, var(--pink), #e11d48); color: #fff; border: none; padding: 8px 16px; border-radius: 8px; font-weight: 700; cursor: pointer; font-size: 13px; }
    .btn-copy { background: #1e293b; color: #cbd5e1; border: 1px solid rgba(255,255,255,0.15); padding: 3px 8px; border-radius: 4px; cursor: pointer; font-size: 11px; }
    .uri-box { font-family: monospace; font-size: 11px; color: #ffa3c2; word-break: break-all; background: rgba(0,0,0,0.5); padding: 10px; border-radius: 6px; margin: 10px 0; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; text-align: left; }
    th, td { padding: 8px 10px; border-bottom: 1px solid rgba(255,255,255,0.08); }
    th { color: #94a3b8; font-size: 12px; }
  </style>
</head>
<body>
  <div id="bg"></div>
  <div class="overlay"></div>
  <div class="container">
    <div class="card" style="display:flex; justify-content:space-between; align-items:center;">
      <div>
        <h2 style="font-size:16px; color:#fff;">TACTICAL GATEWAY</h2>
        <div style="font-size:12px; color:#94a3b8; margin-top:2px;">链路状态：单流 Socket 直通</div>
      </div>
      <button class="btn" onclick="copyVal('${primaryUri}')">复制移动优选链接</button>
    </div>

    <div class="card">
      <div class="title">🛰️ 运营商诊断</div>
      <div class="row"><span>访客出口 IP</span><span style="font-family:monospace;">${client.clientIp}</span></div>
      <div class="row"><span>归属区域</span><span>${client.city}</span></div>
      <div class="row"><span>识别线路</span><span style="color:var(--pink); font-weight:700;">${client.carrierName}</span></div>
    </div>

    <div class="card">
      <div class="title">🎯 专属 Anycast 优选节点列表</div>
      <table>
        <thead><tr><th>#</th><th>优选 IP</th><th>端口</th><th>路由方向</th><th>操作</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>

    <div class="card">
      <div class="title">⚡ VLESS URI 明文</div>
      <div class="uri-box" id="uriTxt">${primaryUri}</div>
      <button class="btn" style="background:#1e293b; border:1px solid var(--cyan); color:var(--cyan);" onclick="copyVal(document.getElementById('uriTxt').innerText)">复制节点链接导入客户端</button>
    </div>
  </div>
  <script>
    const BG_URL = window.innerWidth <= 768 ? "https://t.alcy.cc/mp" : "https://t.alcy.cc/ycy";
    document.getElementById('bg').style.backgroundImage = "url('" + BG_URL + "?t=" + Date.now() + "')";
    function copyVal(t) { navigator.clipboard.writeText(t).then(() => alert('已成功复制到剪贴板！')); }
  </script>
</body>
</html>`;
}
