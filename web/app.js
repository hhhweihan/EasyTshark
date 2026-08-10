// EasyTshark Web 前端逻辑（纯原生 JS，无构建链）。
// 只通过 /api/* 与后端门面交互；会话/统计的聚合在前端做（与原生 GUI 的 ensureAnalytics 同逻辑）。
'use strict';

// ---------- 全局状态 ----------
const state = {
    all: [],            // 当前基础报文集（快照 或 显示过滤结果）
    filtered: null,     // 显示过滤命中的子集；null 表示未过滤
    protoCategory: 0,   // 0全部 1ARP 2ICMP 3ICMPv6
    page: 0,
    pageSize: 100,
    selectedFrame: null,
    live: { active: false, since: 0, timer: null },
    totalBytes: 0,
    statName: 'ip',
};

// ---------- API 助手 ----------
async function getJSON(url) {
    const r = await fetch(url);
    const data = await r.json().catch(() => ({ error: '响应不是合法 JSON' }));
    if (!r.ok || data.error) throw new Error(data.error || ('HTTP ' + r.status));
    return data;
}
async function postJSON(url, body) {
    const r = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body || {}),
    });
    const data = await r.json().catch(() => ({ error: '响应不是合法 JSON' }));
    if (!r.ok || data.error) throw new Error(data.error || ('HTTP ' + r.status));
    return data;
}
const $ = (id) => document.getElementById(id);
function setStatus(msg) { $('statMsg').textContent = '状态: ' + msg; }

// ---------- 展示小工具（对齐 GUI）----------
function protocolClass(proto) {
    const p = (proto || '').toUpperCase();
    if (p.includes('TCP')) return '#8cbfff';
    if (p.includes('UDP')) return '#73d9bf';
    if (p.includes('DNS')) return '#ffb85a';
    if (p.includes('HTTP')) return '#8ce673';
    if (p.includes('TLS') || p.includes('SSL')) return '#cc99ff';
    if (p.includes('SSH')) return '#b3ccf2';
    if (p.includes('ICMP')) return '#ff8cb3';
    if (p.includes('ARP')) return '#f2e673';
    return '#cccccc';
}
function isPrivateIp(ip) {
    if (!ip) return false;
    if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('127.')) return true;
    if (ip.startsWith('172.')) {
        const o = parseInt(ip.split('.')[1], 10);
        if (o >= 16 && o <= 31) return true;
    }
    if (ip === '::1' || ip.startsWith('fe80') || ip.startsWith('fc') || ip.startsWith('fd')) return true;
    return false;
}
function fmtTime(epoch) {
    if (!epoch || epoch <= 0) return '';
    const d = new Date(epoch * 1000);
    const p = (n) => String(n).padStart(2, '0');
    const ms = String(Math.round((epoch - Math.floor(epoch)) * 1000)).padStart(3, '0');
    return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${ms}`;
}
function matchesCategory(p, cat) {
    switch (cat) {
        case 1: return (p.protocol || '').includes('ARP');
        case 2: return p.protocol === 'ICMP';
        case 3: return (p.protocol || '').includes('ICMPv6');
        default: return true;
    }
}
function escapeHtml(s) {
    return String(s == null ? '' : s).replace(/[&<>"]/g, (c) =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

// ---------- 报文列表 ----------
function currentBase() { return state.filtered !== null ? state.filtered : state.all; }
function currentView() { return currentBase().filter((p) => matchesCategory(p, state.protoCategory)); }

function renderPackets() {
    const view = currentView();
    const totalPages = Math.max(1, Math.ceil(view.length / state.pageSize));
    if (state.page >= totalPages) state.page = totalPages - 1;
    if (state.page < 0) state.page = 0;

    const begin = state.live.active ? 0 : state.page * state.pageSize;
    const end = state.live.active ? view.length : Math.min(view.length, begin + state.pageSize);
    const rows = view.slice(begin, end).map(rowHtml).join('');
    $('packetsBody').innerHTML = rows;

    $('packetsCount').textContent = `共 ${view.length} 条` + (state.filtered !== null ? '（已过滤）' : '');
    $('pageInfo').textContent = `第 ${state.page + 1} / ${totalPages} 页`;
    $('pager').style.display = state.live.active ? 'none' : 'flex';

    if (state.live.active && $('autoScroll').checked) {
        const sc = document.querySelector('#tab-packets .table-scroll');
        sc.scrollTop = sc.scrollHeight;
    }
}
function endpoint(ip, mac) { return ip || mac || ''; }
function rowHtml(p) {
    const sel = p.frame_number === state.selectedFrame ? ' class="selected"' : '';
    const priv = (ip) => isPrivateIp(ip) ? '<span class="tag-private">[内网]</span>' : '';
    return `<tr${sel} data-frame="${p.frame_number}">`
        + `<td>${p.frame_number}</td>`
        + `<td>${fmtTime(p.time)}</td>`
        + `<td>${escapeHtml(endpoint(p.src_ip, p.src_mac))}${priv(p.src_ip)}</td>`
        + `<td>${escapeHtml(p.src_location)}</td>`
        + `<td>${p.src_port || ''}</td>`
        + `<td>${escapeHtml(endpoint(p.dst_ip, p.dst_mac))}${priv(p.dst_ip)}</td>`
        + `<td>${escapeHtml(p.dst_location)}</td>`
        + `<td>${p.dst_port || ''}</td>`
        + `<td class="proto" style="color:${protocolClass(p.protocol)}">${escapeHtml(p.protocol)}</td>`
        + `<td>${p.len}</td>`
        + `<td>${escapeHtml(p.info)}</td>`
        + `</tr>`;
}

$('packetsBody').addEventListener('click', (e) => {
    const tr = e.target.closest('tr[data-frame]');
    if (!tr) return;
    if (state.live.active) { setStatus('实时抓包中，停止后可查看协议详情/十六进制'); return; }
    selectPacket(parseInt(tr.dataset.frame, 10));
});

async function selectPacket(frame) {
    state.selectedFrame = frame;
    renderPackets();
    $('detailTree').textContent = '（正在解析协议详情...）';
    $('hexDump').textContent = '';
    try {
        const hex = await getJSON(`/api/hex/${frame}`);
        $('hexTitle').textContent = `十六进制 (帧 ${frame}, ${hex.hex.length / 2} 字节)`;
        $('hexDump').textContent = formatHex(hex.hex);
    } catch (e) { $('hexDump').textContent = '（取十六进制失败：' + e.message + '）'; }
    try {
        const d = await getJSON(`/api/detail/${frame}`);
        renderDetail(d.detail);
    } catch (e) { $('detailTree').textContent = '（无协议详情 / 解析失败：' + e.message + '）'; }
}

function formatHex(hexstr) {
    const bytes = [];
    for (let i = 0; i < hexstr.length; i += 2) bytes.push(parseInt(hexstr.substr(i, 2), 16));
    let out = '';
    for (let off = 0; off < bytes.length; off += 16) {
        let line = off.toString(16).padStart(4, '0') + '  ';
        let ascii = '';
        for (let i = 0; i < 16; i++) {
            if (off + i < bytes.length) {
                const b = bytes[off + i];
                line += b.toString(16).padStart(2, '0') + ' ';
                ascii += (b >= 32 && b < 127) ? String.fromCharCode(b) : '.';
            } else { line += '   '; }
        }
        out += line + ' ' + ascii + '\n';
    }
    return out;
}

// 协议分层树：有子节点的可折叠，叶子显示 label: value。
function renderDetail(root) {
    if (!root || !root.children || root.children.length === 0) {
        $('detailTree').textContent = '（无协议详情）';
        return;
    }
    const ul = document.createElement('ul');
    for (const proto of root.children) ul.appendChild(detailNode(proto));
    $('detailTree').innerHTML = '';
    $('detailTree').appendChild(ul);
}
function detailNode(node) {
    const li = document.createElement('li');
    if (node.children && node.children.length) {
        const span = document.createElement('span');
        span.className = 'node open';
        span.textContent = node.label;
        const child = document.createElement('ul');
        for (const c of node.children) child.appendChild(detailNode(c));
        span.addEventListener('click', () => {
            const open = span.classList.toggle('open');
            child.style.display = open ? '' : 'none';
        });
        li.appendChild(span);
        li.appendChild(child);
    } else {
        const span = document.createElement('span');
        span.className = 'leaf';
        span.innerHTML = escapeHtml(node.label) + (node.value ? ': <span class="val">' + escapeHtml(node.value) + '</span>' : '');
        li.appendChild(span);
    }
    return li;
}

// ---------- 数据刷新 ----------
async function refreshSnapshot() {
    const data = await getJSON('/api/packets');
    state.all = data.packets || [];
    state.filtered = null;
    state.selectedFrame = null;
    state.page = 0;
    state.totalBytes = state.all.reduce((s, p) => s + (p.len || 0), 0);
    $('detailTree').textContent = '（选中一个报文查看详情）';
    $('hexDump').textContent = '';
    $('hexTitle').textContent = '十六进制';
    renderPackets();
    renderSessions();
    renderStats();
    updateStatusBar();
}
function updateStatusBar() {
    const n = state.live.active ? state.all.length : (state.filtered !== null ? state.filtered.length : state.all.length);
    $('statTotal').textContent = '数据包总数: ' + state.all.length;
    $('statBytes').textContent = '总字节数: ' + state.totalBytes;
}

// ---------- 载入 pcap ----------
$('btnLoad').addEventListener('click', async () => {
    const path = $('pcapPath').value.trim();
    if (!path) { setStatus('请输入 PCAP 路径'); return; }
    setStatus('正在解析 pcap...');
    try {
        const r = await postJSON('/api/load', { path });
        await refreshSnapshot();
        setStatus(`已解析，共 ${r.count} 个数据包`);
    } catch (e) { setStatus('载入失败：' + e.message); }
});

// ---------- 显示过滤 ----------
$('btnFilter').addEventListener('click', doFilter);
$('filterExpr').addEventListener('keydown', (e) => { if (e.key === 'Enter') doFilter(); });
async function doFilter() {
    const expr = $('filterExpr').value.trim();
    if (!expr) return;
    setStatus('正在按表达式过滤...');
    try {
        const data = await postJSON('/api/filter', { expr });
        state.filtered = data.packets || [];
        state.page = 0;
        state.selectedFrame = null;
        renderPackets();
        setStatus(`过滤命中 ${state.filtered.length} 个报文`);
    } catch (e) { setStatus('过滤失败：' + e.message); }
}
$('btnClearFilter').addEventListener('click', () => {
    state.filtered = null;
    state.page = 0;
    state.selectedFrame = null;
    renderPackets();
    setStatus('已清除过滤');
});
$('protoCategory').addEventListener('change', (e) => {
    state.protoCategory = parseInt(e.target.value, 10);
    state.page = 0;
    renderPackets();
});

// ---------- 分页 ----------
$('btnPrev').addEventListener('click', () => { state.page--; renderPackets(); });
$('btnNext').addEventListener('click', () => { state.page++; renderPackets(); });
$('pageSize').addEventListener('change', (e) => { state.pageSize = parseInt(e.target.value, 10); state.page = 0; renderPackets(); });

// ---------- 结构化查询 ----------
$('btnQuery').addEventListener('click', async () => {
    const cond = {};
    if ($('qMac').value.trim()) cond.mac_address = $('qMac').value.trim();
    if ($('qIp').value.trim()) cond.ip_address = $('qIp').value.trim();
    if ($('qPort').value.trim()) cond.port = $('qPort').value.trim();
    if ($('qLoc').value.trim()) cond.location = $('qLoc').value.trim();
    if (Object.keys(cond).length === 0) { setStatus('未指定任何查询条件'); return; }
    setStatus('查询中...');
    try {
        const data = await postJSON('/api/query', cond);
        const rows = (data.packets || []).map((p) =>
            `<tr><td>${p.frame_number}</td><td>${escapeHtml(p.src_ip)}</td><td>${p.src_port || ''}</td>`
            + `<td>${escapeHtml(p.dst_ip)}</td><td>${p.dst_port || ''}</td>`
            + `<td class="proto" style="color:${protocolClass(p.protocol)}">${escapeHtml(p.protocol)}</td>`
            + `<td>${escapeHtml(p.src_location || p.dst_location)}</td><td>${escapeHtml(p.info)}</td></tr>`).join('');
        $('queryBody').innerHTML = rows;
        setStatus(`查询到 ${data.total} 条`);
    } catch (e) { setStatus('查询失败：' + e.message); }
});

// ---------- 实时抓包 ----------
$('btnRefreshAdapters').addEventListener('click', async () => {
    setStatus('获取网卡...');
    try {
        const list = await getJSON('/api/adapters');
        const sel = $('adapterSelect');
        sel.innerHTML = '<option value="">选择网卡</option>' +
            list.map((a) => `<option value="${escapeHtml(a.name)}">${escapeHtml(a.name)} (${escapeHtml(a.remark)})</option>`).join('');
        setStatus(`已刷新网卡，共 ${list.length} 个`);
    } catch (e) { setStatus('刷新网卡失败：' + e.message); }
});
$('btnStart').addEventListener('click', async () => {
    const adapter = $('adapterSelect').value;
    if (!adapter) { setStatus('请选择网卡'); return; }
    try {
        await postJSON('/api/capture/start', { adapter });
        state.all = []; state.filtered = null; state.selectedFrame = null;
        state.totalBytes = 0; state.live.active = true; state.live.since = 0;
        $('btnStart').disabled = true; $('btnStop').disabled = false;
        $('liveIndicator').style.display = '';
        renderPackets();
        setStatus('实时抓包中: ' + adapter);
        state.live.timer = setInterval(pollLive, 800);
    } catch (e) { setStatus('启动抓包失败：' + e.message); }
});
$('btnStop').addEventListener('click', async () => {
    clearInterval(state.live.timer); state.live.timer = null;
    setStatus('停止抓包并解析...');
    try {
        await postJSON('/api/capture/stop', {});
        state.live.active = false;
        $('btnStart').disabled = false; $('btnStop').disabled = true;
        $('liveIndicator').style.display = 'none';
        await refreshSnapshot();
        setStatus(`抓包完成，共 ${state.all.length} 个数据包`);
    } catch (e) { setStatus('停止失败：' + e.message); }
});
async function pollLive() {
    try {
        const data = await getJSON('/api/packets?since=' + state.live.since);
        const batch = data.packets || [];
        if (batch.length) {
            state.live.since += batch.length;
            state.all.push(...batch);
            state.totalBytes += batch.reduce((s, p) => s + (p.len || 0), 0);
            renderPackets();
            updateStatusBar();
        }
    } catch (e) { /* 抓包途中偶发失败，忽略，下轮再试 */ }
}

// ---------- tshark 路径 ----------
$('btnApplyTshark').addEventListener('click', async () => {
    const path = $('tsharkPath').value.trim();
    if (!path) return;
    try {
        const r = await postJSON('/api/tshark', { path });
        $('tsharkState').textContent = r.available ? '✓ 可用' : '✗ 未找到 tshark';
        $('tsharkState').style.color = r.available ? '#8ce673' : '#ff7373';
    } catch (e) { setStatus('设置 tshark 失败：' + e.message); }
});

// ---------- 会话聚合（前端计算，对齐 GUI 的 ensureAnalytics）----------
function renderSessions() {
    const cat = parseInt($('sessionCategory').value, 10);
    const map = new Map();
    for (const p of state.all) {
        if (!p.src_ip || !p.dst_ip) continue;
        const a = p.src_ip + ':' + p.src_port, b = p.dst_ip + ':' + p.dst_port;
        const key = a < b ? a + '|' + b : b + '|' + a;
        let si = map.get(key);
        if (!si) { si = { a: a < b ? a : b, b: a < b ? b : a, transport: p.transport || '', protocols: new Set(), packets: 0, bytes: 0 }; map.set(key, si); }
        if (p.protocol) si.protocols.add(p.protocol);
        si.packets++; si.bytes += p.len || 0;
    }
    const has = (si, n) => [...si.protocols].some((x) => x.includes(n));
    const match = (si) => {
        switch (cat) {
            case 1: return si.transport === 'TCP';
            case 2: return si.transport === 'UDP';
            case 3: return has(si, 'DNS');
            case 4: return has(si, 'HTTP');
            case 5: return has(si, 'TLS') || has(si, 'SSL');
            case 6: return has(si, 'SSH');
            default: return true;
        }
    };
    const list = [...map.values()].filter(match).sort((x, y) => y.packets - x.packets);
    $('sessionCount').textContent = `共 ${list.length} 个会话`;
    $('sessionsBody').innerHTML = list.map((si) =>
        `<tr><td>${escapeHtml(si.a)}</td><td>${escapeHtml(si.b)}</td><td>${escapeHtml(si.transport)}</td>`
        + `<td>${escapeHtml([...si.protocols].join(','))}</td><td>${si.packets}</td><td>${si.bytes}</td></tr>`).join('');
}
$('sessionCategory').addEventListener('change', renderSessions);

// ---------- 统计聚合 ----------
function renderStats() {
    const ip = new Map(), proto = new Map(), loc = new Map();
    const bump = (m, name, len) => { if (!name) return; const c = m.get(name) || { name, packets: 0, bytes: 0 }; c.packets++; c.bytes += len || 0; m.set(name, c); };
    for (const p of state.all) {
        bump(proto, p.protocol, p.len);
        bump(ip, p.src_ip, p.len); bump(ip, p.dst_ip, p.len);
        bump(loc, p.src_location, p.len); bump(loc, p.dst_location, p.len);
    }
    state._stats = {
        ip: [...ip.values()].sort((a, b) => b.packets - a.packets),
        proto: [...proto.values()].sort((a, b) => b.packets - a.packets),
        loc: [...loc.values()].sort((a, b) => b.packets - a.packets),
    };
    drawStats();
}
function drawStats() {
    const items = (state._stats && state._stats[state.statName]) || [];
    $('statNameCol').textContent = state.statName === 'ip' ? 'IP 地址' : (state.statName === 'proto' ? '协议' : '归属地 / 国家');
    $('statsBody').innerHTML = items.map((c) =>
        `<tr><td>${escapeHtml(c.name)}</td><td>${c.packets}</td><td>${c.bytes}</td></tr>`).join('');
}
document.querySelectorAll('.stat-tab').forEach((b) => b.addEventListener('click', () => {
    document.querySelectorAll('.stat-tab').forEach((x) => x.classList.remove('active'));
    b.classList.add('active');
    state.statName = b.dataset.stat;
    drawStats();
}));

// ---------- 分页 Tab 切换 ----------
document.querySelectorAll('.tab').forEach((tab) => tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((t) => t.classList.remove('active'));
    document.querySelectorAll('.tabpage').forEach((p) => p.classList.remove('active'));
    tab.classList.add('active');
    $('tab-' + tab.dataset.tab).classList.add('active');
}));

// ---------- 初始化 ----------
(async function init() {
    try {
        const t = await getJSON('/api/tshark');
        $('tsharkPath').value = t.path;
        $('tsharkState').textContent = t.available ? '✓ 可用' : '✗ 未找到 tshark';
        $('tsharkState').style.color = t.available ? '#8ce673' : '#ff7373';
    } catch (e) { /* 忽略 */ }
    try { await refreshSnapshot(); } catch (e) { /* 尚无数据，正常 */ }
    setStatus('就绪');
})();
