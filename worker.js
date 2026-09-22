import { connect } from 'cloudflare:sockets';

const DEFAULT_UUID = 'd342d11e-d424-4583-b36e-524ab1f0afa4';

export default {
  async fetch(request, env) {
    try {
      const targetUUID = (env.UUID || DEFAULT_UUID).toLowerCase();
      const upgradeHeader = request.headers.get('Upgrade');

      // 1. 非 WebSocket 握手，返回就绪提示
      if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
        const url = new URL(request.url);
        return new Response(`VLESS Gateway Online // SNI: ${url.hostname}`, {
          headers: { 'Content-Type': 'text/plain; charset=utf-8' }
        });
      }

      // 2. 处理 VLESS over WebSocket
      return await handleVlessConnection(request, targetUUID);
    } catch (err) {
      return new Response(err.stack || err.message, { status: 500 });
    }
  }
};

/**
 * VLESS 传输管道核心实现
 */
async function handleVlessConnection(request, targetUUID) {
  const webSocketPair = new WebSocketPair();
  const [clientWs, serverWs] = Object.values(webSocketPair);
  serverWs.accept();

  // 关键修复 1：提取客户端可能通过 Sec-WebSocket-Protocol 携带的 Early Data
  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';

  // 构建统一可读流，优先注入 Early Data，再接入持续收到的数据包
  const readableStream = new ReadableStream({
    start(controller) {
      if (earlyDataHeader) {
        try {
          const earlyBuf = base64ToArrayBuffer(earlyDataHeader);
          controller.enqueue(earlyBuf);
        } catch (e) {}
      }

      serverWs.addEventListener('message', (event) => {
        controller.enqueue(event.data);
      });

      serverWs.addEventListener('close', () => {
        safeClose(serverWs);
        controller.close();
      });

      serverWs.addEventListener('error', (err) => {
        controller.error(err);
      });
    }
  });

  let remoteSocketWrapper = { value: null };
  let isDnsSession = false;

  // 管道消费循环
  readableStream.pipeTo(new WritableStream({
    async write(chunk, controller) {
      if (!(chunk instanceof ArrayBuffer)) return;

      // 如果已确立为 DNS 53 查询会话
      if (isDnsSession) {
        return handleUdpDns(chunk, serverWs);
      }

      // 如果 TCP 已经建立，后续收到的数据直接打入远端
      if (remoteSocketWrapper.value) {
        const writer = remoteSocketWrapper.value.writable.getWriter();
        await writer.write(new Uint8Array(chunk));
        writer.releaseLock();
        return;
      }

      // 解析首包 VLESS 头部
      const parsed = parseVlessHeader(chunk, targetUUID);
      if (parsed.hasError) {
        controller.error(parsed.message);
        safeClose(serverWs);
        return;
      }

      // 处理 UDP 53 DNS 流量
      if (parsed.isUdp) {
        if (parsed.port === 53) {
          isDnsSession = true;
          return handleUdpDns(parsed.rawPayload, serverWs);
        } else {
          controller.error('Only port 53 UDP is supported');
          safeClose(serverWs);
          return;
        }
      }

      // 建立对端 TCP 连接并回传数据
      handleTcpOutbound(remoteSocketWrapper, parsed.address, parsed.port, parsed.rawPayload, serverWs);
    },
    close() {
      safeClose(serverWs);
    },
    abort() {
      safeClose(serverWs);
    }
  })).catch(() => {
    safeClose(serverWs);
  });

  // 关键修复 2：如果存在 Early Data 协商头，必须在 101 状态中原样回传
  const responseHeaders = {};
  if (earlyDataHeader) {
    responseHeaders['Sec-WebSocket-Protocol'] = earlyDataHeader;
  }

  return new Response(null, {
    status: 101,
    webSocket: clientWs,
    headers: responseHeaders
  });
}

/**
 * 建立 TCP 出站连接并启动数据流互转
 */
async function handleTcpOutbound(remoteSocketWrapper, address, port, initialData, serverWs) {
  try {
    const tcpSocket = connect({
      hostname: address,
      port: port
    });
    remoteSocketWrapper.value = tcpSocket;

    // 发送客户端在首包中携带的业务数据
    if (initialData && initialData.byteLength > 0) {
      const writer = tcpSocket.writable.getWriter();
      await writer.write(new Uint8Array(initialData));
      writer.releaseLock();
    }

    // 关键修复 3：VLESS 响应头 [0, 0] 必须与远端返回的首批数据拼接在同一个数据帧内下发
    let hasSentHeader = false;
    const vlessHeader = new Uint8Array([0, 0]);

    tcpSocket.readable.pipeTo(new WritableStream({
      async write(chunk, controller) {
        if (serverWs.readyState !== WebSocket.OPEN) {
          controller.error('WebSocket closed');
          return;
        }

        if (!hasSentHeader) {
          hasSentHeader = true;
          const combined = new Uint8Array(vlessHeader.byteLength + chunk.byteLength);
          combined.set(vlessHeader, 0);
          combined.set(chunk, vlessHeader.byteLength);
          serverWs.send(combined.buffer);
        } else {
          serverWs.send(chunk);
        }
      },
      close() {
        safeClose(serverWs);
      },
      abort() {
        safeClose(serverWs);
      }
    })).catch(() => {
      safeClose(serverWs);
    });
  } catch (err) {
    safeClose(serverWs);
  }
}

/**
 * 快速处理 UDP DNS 查询 (通过 1.1.1.1 DoH 代理)
 */
async function handleUdpDns(chunk, serverWs) {
  try {
    if (chunk.byteLength <= 2) return;
    const dnsQuery = chunk.slice(2);

    const res = await fetch('https://1.1.1.1/dns-query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/dns-message' },
      body: dnsQuery
    });

    const dnsAnswer = await res.arrayBuffer();
    const len = dnsAnswer.byteLength;

    // VLESS UDP 包装协议: [0x00, 0x00 状态头][2 字节大端长度][DNS 实际结果]
    const respPacket = new Uint8Array(4 + len);
    respPacket[0] = 0;
    respPacket[1] = 0;
    respPacket[2] = (len >> 8) & 0xff;
    respPacket[3] = len & 0xff;
    respPacket.set(new Uint8Array(dnsAnswer), 4);

    if (serverWs.readyState === WebSocket.OPEN) {
      serverWs.send(respPacket.buffer);
    }
  } catch (e) {}
}

/**
 * 校验并解构 VLESS 请求头
 */
function parseVlessHeader(buffer, targetUUID) {
  if (buffer.byteLength < 24) return { hasError: true, message: 'Payload too short' };

  const view = new DataView(buffer);
  if (view.getUint8(0) !== 0) return { hasError: true, message: 'Version error' };

  // 提取 UUID
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
  const isUdp = command === 2;

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
    isUdp,
    address,
    port,
    rawPayload: buffer.slice(cursor)
  };
}

function base64ToArrayBuffer(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function safeClose(ws) {
  try {
    if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CLOSING) {
      ws.close();
    }
  } catch (e) {}
}

