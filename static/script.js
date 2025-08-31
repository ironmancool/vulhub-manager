// === 修正版：修復篩選功能、避免重複掃描、移除運行中容器 ===

let allEnvironments = [];
let filteredEnvironments = [];
let currentPage = 1;
const itemsPerPage = 20;

// 初始化
document.addEventListener('DOMContentLoaded', () => {
    // 只用快取，不重新掃描
    loadFromCache();
    
    // 綁定事件監聽器
    document.getElementById('btnRescan')?.addEventListener('click', forceRescan);
    document.getElementById('searchInput')?.addEventListener('input', searchEnv);
    document.getElementById('categoryFilter')?.addEventListener('change', filterByCategory);
    document.getElementById('exploitFilter')?.addEventListener('change', filterByExploit);
    document.getElementById('runningFilter')?.addEventListener('change', filterByRunning);
    document.getElementById('downloadedFilter')?.addEventListener('change', filterByDownloaded);
});

// 只從快取載入（不重新掃描）
async function loadFromCache() {
    showLoading(true);
    try {
        const response = await fetch('/api/scan?cache=true');
        allEnvironments = await response.json();
        filteredEnvironments = allEnvironments.slice();
        
        currentPage = 1;
        displayEnvironments(filteredEnvironments);
        updateCategoryFilter();
        updateStats();
        updatePagination();
    } catch (error) {
        console.error('載入快取失敗:', error);
        document.getElementById('envList').innerHTML = '<div class="empty">載入失敗，請點擊重新掃描</div>';
    } finally {
        showLoading(false);
    }
}

// 強制重新掃描（清除快取並重建）
async function forceRescan() {
    if (!confirm('確定要重新掃描所有環境嗎？這會清除快取並重新檢查所有環境。')) {
        return;
    }
    
    showLoading(true);
    try {
        // 呼叫強制重新整理 API
        const refreshResponse = await fetch('/api/refresh-cache', { method: 'POST' });
        const refreshResult = await refreshResponse.json();
        
        if (!refreshResult.success) {
            throw new Error(refreshResult.error || '重新掃描失敗');
        }
        
        // 重新載入資料
        const response = await fetch('/api/scan?cache=false');
        allEnvironments = await response.json();
        filteredEnvironments = allEnvironments.slice();

        currentPage = 1;
        displayEnvironments(filteredEnvironments);
        updateCategoryFilter();
        updateStats();
        updatePagination();
        showNotification(`掃描完成，共找到 ${refreshResult.count} 個環境`, 'success');
    } catch (error) {
        console.error('掃描失敗:', error);
        showNotification('重新掃描失敗: ' + error.message, 'error');
    } finally {
        showLoading(false);
    }
}

// 相容舊的 scanEnvironments 函數
async function scanEnvironments(useCache = false) {
    if (useCache) {
        await loadFromCache();
    } else {
        await forceRescan();
    }
}

// 顯示環境列表
function displayEnvironments(envs) {
    const list = document.getElementById('envList');
    try {
        if (!Array.isArray(envs)) throw new Error('scan 回傳不是陣列');

        filteredEnvironments = envs.slice();

        const total = envs.length;
        const start = (currentPage - 1) * itemsPerPage;
        const end = Math.min(start + itemsPerPage, total);
        const pageItems = envs.slice(start, end);

        list.innerHTML = '';

        if (pageItems.length === 0) {
            list.innerHTML = '<div class="empty">沒有符合條件的環境</div>';
            return;
        }

        for (const env of pageItems) {
            const category = (env && env.category) || (env?.name?.split('/')[0] || 'unknown');
            const cve = (env && env.cve) || (env?.name?.split('/').slice(-1)[0] || 'unknown');
            const status = (env && env.status) || 'unknown';
            const portsObj = (env && env.ports && typeof env.ports === 'object') ? env.ports : {};
            const portEntries = Object.entries(portsObj);
            const firstPort = portEntries.length ? String(portEntries[0][1]) : '';

            const card = document.createElement('div');
            card.className = 'env-card';

            // header
            const header = document.createElement('div');
            header.className = 'env-header';

            const title = document.createElement('div');
            title.className = 'env-title';
            title.textContent = `${category} / ${cve}`;

            const statusEl = document.createElement('div');
            statusEl.className = 'env-status ' + (status === 'running' ? 'running' : (status === 'stopped' ? 'stopped' : 'unknown'));
            statusEl.textContent = (status === 'running' ? 'running' : (status === 'stopped' ? 'stopped' : 'unknown'));

            header.appendChild(title);
            header.appendChild(statusEl);

            // meta
            const meta = document.createElement('div');
            meta.className = 'env-meta';

            // 前兩個 ports
            for (const [svc, port] of portEntries.slice(0, 2)) {
                const tag = document.createElement('span');
                tag.className = 'tag tag-port';
                tag.textContent = `📌 ${svc}:${port}`;
                meta.appendChild(tag);
            }
            if (portEntries.length > 2) {
                const more = document.createElement('span');
                more.className = 'tag';
                more.textContent = `+${portEntries.length - 2} ports`;
                meta.appendChild(more);
            }

            // exploit 標籤
            if (env && env.has_exploit) {
                const exp = document.createElement('span');
                exp.className = 'tag tag-exploit';
                exp.textContent = '💣 Has Exploit';
                meta.appendChild(exp);
            }

            // Docker 映像標籤
            if (env && env.has_docker_images) {
                const dockerTag = document.createElement('span');
                dockerTag.className = 'tag tag-docker';
                dockerTag.textContent = '🐳 已有映像';
                meta.appendChild(dockerTag);
            }

            // 路徑標籤
            const pathTag = document.createElement('span');
            pathTag.className = 'tag';
            pathTag.textContent = `📁 ${env?.name || ''}`;
            meta.appendChild(pathTag);

            // actions
            const actions = document.createElement('div');
            actions.className = 'env-actions';

            const btnStartStop = document.createElement('button');
            if (status === 'running') {
                btnStartStop.className = 'btn btn-danger';
                btnStartStop.textContent = '⏹ 停止';
                btnStartStop.onclick = () => stopEnv(env.name);
            } else {
                btnStartStop.className = 'btn btn-success';
                btnStartStop.textContent = '▶️ 啟動';
                btnStartStop.onclick = () => startEnv(env.name);
            }
            actions.appendChild(btnStartStop);

            if (status === 'running' && firstPort) {
                const btnOpen = document.createElement('button');
                btnOpen.className = 'btn btn-primary';
                btnOpen.textContent = '🌐 開啟';
                btnOpen.onclick = () => openEnv(firstPort);
                actions.appendChild(btnOpen);
            }

            // 如果有 Exploit，添加查看按鈕
            if (env && env.has_exploit) {
                const btnExploit = document.createElement('button');
                btnExploit.className = 'btn';
                btnExploit.textContent = '💣 Exploit';
                btnExploit.onclick = () => showExploit(env.name);
                actions.appendChild(btnExploit);
            }

            const btnDetail = document.createElement('button');
            btnDetail.className = 'btn';
            btnDetail.textContent = '📖 詳情';
            btnDetail.onclick = () => showDetail(env.name);
            actions.appendChild(btnDetail);

            card.appendChild(header);
            card.appendChild(meta);
            card.appendChild(actions);
            list.appendChild(card);
        }

        renderPagination(total);
    } catch (e) {
        console.error('渲染列表發生錯誤：', e);
        list.innerHTML = `<div class="empty">渲染錯誤：${e.message}</div>`;
    }
}

// 分頁
function renderPagination(total) {
    const totalPages = Math.max(1, Math.ceil(total / itemsPerPage));
    const pag = document.getElementById('pagination');
    if (!pag) return;

    let html = '';

    // 上一頁
    html += `
      <button class="btn-page ${currentPage === 1 ? 'disabled' : ''}"
              onclick="changePage(${Math.max(1, currentPage - 1)})"
              ${currentPage === 1 ? 'disabled' : ''}>← 上一頁</button>`;

    // 頁碼
    const maxVisiblePages = 7;
    let startPage = Math.max(1, currentPage - 3);
    let endPage = Math.min(totalPages, startPage + maxVisiblePages - 1);
    if (endPage - startPage < maxVisiblePages - 1) {
        startPage = Math.max(1, endPage - maxVisiblePages + 1);
    }

    if (startPage > 1) {
        html += `<button class="btn-page" onclick="changePage(1)">1</button>`;
        if (startPage > 2) html += `<span class="page-ellipsis">...</span>`;
    }
    for (let i = startPage; i <= endPage; i++) {
        html += `<button class="btn-page ${i === currentPage ? 'active' : ''}" onclick="changePage(${i})">${i}</button>`;
    }
    if (endPage < totalPages) {
        if (endPage < totalPages - 1) html += `<span class="page-ellipsis">...</span>`;
        html += `<button class="btn-page" onclick="changePage(${totalPages})">${totalPages}</button>`;
    }

    // 下一頁
    html += `
      <button class="btn-page ${currentPage === totalPages ? 'disabled' : ''}"
              onclick="changePage(${Math.min(totalPages, currentPage + 1)})"
              ${currentPage === totalPages ? 'disabled' : ''}>下一頁 →</button>`;

    // 跳頁
    html += `
      <div class="page-jump">
        跳至 <input type="number" id="pageJumpInput" min="1" max="${totalPages}" value="${currentPage}"
                    onkeypress="if(event.key==='Enter') jumpToPage()">
        <button class="btn-page" onclick="jumpToPage()">Go</button>
      </div>`;

    pag.innerHTML = html;
}

function changePage(page) {
    const totalPages = Math.max(1, Math.ceil(filteredEnvironments.length / itemsPerPage));
    if (page < 1 || page > totalPages) return;
    currentPage = page;
    displayEnvironments(filteredEnvironments);
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function jumpToPage() {
    const input = document.getElementById('pageJumpInput');
    const page = parseInt(input.value, 10);
    if (!isNaN(page)) changePage(page);
}

function updatePagination() {
    const totalPages = Math.max(1, Math.ceil(filteredEnvironments.length / itemsPerPage));
    if (currentPage > totalPages && totalPages > 0) currentPage = totalPages;
}

async function updateStats() {
    try {
        const response = await fetch('/api/stats');
        const stats = await response.json();
        document.getElementById('stats').innerHTML = `
            <div class="stat-item"><div class="stat-value">${stats.total}</div><div class="stat-label">總環境</div></div>
            <div class="stat-item"><div class="stat-value">${stats.running}</div><div class="stat-label">運行中</div></div>
            <div class="stat-item"><div class="stat-value">${stats.with_exploit}</div><div class="stat-label">有 Exploit</div></div>
            <div class="stat-item"><div class="stat-value">${stats.with_images || 0}</div><div class="stat-label">已有映像</div></div>
            <div class="stat-item"><div class="stat-value">${Object.keys(stats.categories).length}</div><div class="stat-label">分類數</div></div>
        `;
    } catch (error) {
        console.error('更新統計失敗:', error);
    }
}

function updateCategoryFilter() {
    const categories = [...new Set(allEnvironments.map(e => e.category))].sort();
    const select = document.getElementById('categoryFilter');
    if (!select) return;
    select.innerHTML = '<option value="">所有分類</option>' +
        categories.map(c => `<option value="${c}">${c}</option>`).join('');
}

// === 搜尋 / 篩選 ===
let searchTimeout;
function searchEnv() {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => performSearch(), 300);
}

function filterByCategory() {
    performSearch();
}

function filterByExploit() {
    performSearch();
}

function filterByRunning() {
    performSearch();
}

function filterByDownloaded() {
    performSearch();
}

function performSearch() {
    const q = (document.getElementById('searchInput')?.value || '').toLowerCase();
    const category = document.getElementById('categoryFilter')?.value || '';
    const onlyExploit = !!document.getElementById('exploitFilter')?.checked;
    const onlyRunning = !!document.getElementById('runningFilter')?.checked;
    const onlyDownloaded = !!document.getElementById('downloadedFilter')?.checked;

    filteredEnvironments = allEnvironments.filter(env => {
        if (q && !(env.name.toLowerCase().includes(q) ||
                   (env.cve || '').toLowerCase().includes(q) ||
                   (env.category || '').toLowerCase().includes(q))) return false;
        if (category && env.category !== category) return false;
        if (onlyExploit && !env.has_exploit) return false;
        if (onlyRunning && env.status !== 'running') return false;
        // 使用 has_docker_images 來判斷是否已有映像
        if (onlyDownloaded && !env.has_docker_images) return false;
        return true;
    });

    currentPage = 1;
    displayEnvironments(filteredEnvironments);
    updatePagination();
}

// === 啟停 ===
async function startEnv(name) {
    try {
        // 檢查是否缺映像（這個很快，可以顯示遮罩）
        showLoading(true);
        const ci = await fetch(`/api/check-images?name=${encodeURIComponent(name)}`).then(r => r.json());
        showLoading(false);
        
        if (!ci.success) throw new Error(ci.error || "check-images 失敗");
        const missing = ci.missing || [];
        if (missing.length > 0) {
            // 下載映像時不用遮罩，已經有進度視窗了
            showProgressModal();
            appendProgress(`[Info] 需要下載的映像：\n- ${missing.join("\n- ")}`);
            await pullWithProgress(name);
        }

        // 啟動容器時顯示遮罩
        showLoading(true);
        const resp = await fetch('/api/start', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({name})
        });
        const result = await resp.json();
        showLoading(false);

        if (!result.success) {
            if (result.port_conflict) {
                let message = `端口已被佔用`;
                if (result.conflicting_containers && result.conflicting_containers.length > 0) {
                    message += `\n佔用的容器: ${result.conflicting_containers.join(', ')}`;
                }
                message += '\n\n建議：\n1. 停止佔用端口的容器\n2. 或修改 docker-compose.yml 使用其他端口';
                alert(message);
            } else {
                showNotification('啟動失敗: ' + (result.error || '未知錯誤'), 'error');
            }
            hideProgressModal();
            return;
        }

        updateEnvStatus(name, 'running');
        showNotification('環境啟動成功', 'success');

        // 等服務就緒（這個也可能要等一段時間，但不顯示遮罩）
        const wait = await fetch(`/api/wait-ready?name=${encodeURIComponent(name)}&timeout=20`).then(r=>r.json());
        if (wait.success && wait.ready && wait.port) {
            hideProgressModal();
            openEnv(String(wait.port));
        } else {
            hideProgressModal();
            showNotification('已啟動，但無法確認服務就緒（可稍候再開）', 'warning');
        }
    } catch (e) {
        showLoading(false);
        hideProgressModal();
        showNotification('啟動失敗: ' + e.message, 'error');
    }
}

async function stopEnv(name) {
    showLoading(true);
    try {
        const response = await fetch('/api/stop', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({name})
        });
        const result = await response.json();
        if (result.success) {
            showNotification('環境已停止', 'success');
            updateEnvStatus(name, 'stopped');
        } else {
            showNotification('停止失敗: ' + (result.error || '未知錯誤'), 'error');
        }
    } catch (error) {
        showNotification('停止失敗: ' + error.message, 'error');
    } finally {
        showLoading(false);
    }
}

function updateEnvStatus(name, status) {
    const env = allEnvironments.find(e => e.name === name);
    if (env) env.status = status;
    const filteredEnv = filteredEnvironments.find(e => e.name === name);
    if (filteredEnv) filteredEnv.status = status;
    displayEnvironments(filteredEnvironments);
    updateStats();
}

// === 詳情與 Exploit ===
async function showDetail(name) {
    showLoading(true);
    try {
        const [envResponse, readmeResponse] = await Promise.all([
            fetch(`/api/env/${name}`),
            fetch(`/api/readme/${name}`)
        ]);
        const env = await envResponse.json();
        const readme = await readmeResponse.json();

        let content = `
            <h2>${env.name}</h2>
            <div class="env-meta" style="margin: 1rem 0;">
                <span class="tag">分類: ${env.category}</span>
                <span class="tag">CVE: ${env.cve}</span>
                ${env.exploit_files && env.exploit_files.length > 0 ? 
                    `<span class="tag tag-exploit">Exploits: ${env.exploit_files.join(', ')}</span>` : ''}
            </div>
        `;

        if (env.images && env.images.length > 0) {
            content += '<h3>截圖</h3>';
            env.images.forEach(img => {
                content += `<img src="${img.data}" class="screenshot" alt="${img.name}" loading="lazy">`;
            });
        }

        content += '<h3>說明文檔</h3>';
        content += `<div class="readme-content">${readme.html || ''}</div>`;

        content += '<h3>Docker Compose 配置</h3>';
        content += `<pre class="code-block">${escapeHtml(env.compose || '')}</pre>`;

        const cont = document.getElementById('modalContent');
        cont.innerHTML = content;
        cont.style.maxHeight = '75vh';
        cont.style.overflow = 'auto';

        const modal = document.getElementById('detailModal');
        modal.style.display = 'block';
        modal.style.overflowY = 'auto';
    } catch (error) {
        showNotification('載入詳情失敗: ' + error.message, 'error');
    } finally {
        showLoading(false);
    }
}

async function showExploit(name) {
    showLoading(true);
    try {
        const response = await fetch(`/api/exploit/${name}`);
        const exploits = await response.json();

        if (!Array.isArray(exploits) || exploits.length === 0) {
            showNotification('沒有找到 Exploit', 'warning');
            return;
        }

        let content = `<h2>Exploit - ${name}</h2>
        <div style="background:#fef3c7; color:#78350f; padding:12px; border-radius:8px; margin:10px 0;">
            ⚠️ <strong>警告</strong>：僅供學術研究與授權測試使用，使用者需自負法律責任
        </div>`;

        exploits.forEach(exploit => {
            content += `
                <div style="border:1px solid #e5e7eb; border-radius:8px; padding:12px; margin:12px 0;">
                    <h3 style="margin-top:0;">${exploit.filename}</h3>
                    <div style="margin: 8px 0;">
                        <span class="tag">大小: ${exploit.size} bytes</span>
                        <span class="tag">行數: ${exploit.lines}</span>
                        <span class="tag">路徑: ${exploit.path}</span>
                    </div>
                    ${exploit.usage ? `<div style="background:#f3f4f6; padding:8px; border-radius:6px; margin:8px 0;">
                        <strong>使用說明：</strong> ${escapeHtml(exploit.usage)}
                    </div>` : ''}
                    <h4>程式碼：</h4>
                    <pre class="code-block" style="max-height:400px; overflow:auto;">${escapeHtml(exploit.content)}</pre>
                </div>
            `;
        });

        const cont = document.getElementById('modalContent');
        cont.innerHTML = content;
        cont.style.maxHeight = '75vh';
        cont.style.overflow = 'auto';

        const modal = document.getElementById('detailModal');
        modal.style.display = 'block';
        modal.style.overflowY = 'auto';
    } catch (error) {
        showNotification('載入 Exploit 失敗: ' + error.message, 'error');
    } finally {
        showLoading(false);
    }
}

// === 其它小工具 ===
function openEnv(port) {
    window.open(`http://localhost:${port}`, '_blank');
}

function closeModal() {
    const m = document.getElementById('detailModal');
    if (m) m.style.display = 'none';
}

window.onclick = function(event) {
    const modal = document.getElementById('detailModal');
    if (event.target === modal) modal.style.display = 'none';
};

function showLoading(show) {
    const el = document.getElementById('loading');
    if (el) el.style.display = show ? 'flex' : 'none';
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    document.body.appendChild(notification);
    setTimeout(() => notification.classList.add('show'), 10);
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => document.body.removeChild(notification), 300);
    }, 3000);
}

function escapeHtml(text) {
    if (text == null) return '';
    const map = {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'};
    return String(text).replace(/[&<>"']/g, m => map[m]);
}

// === 下載進度 Modal & SSE ===
function showProgressModal() {
    const m = document.getElementById('progressModal');
    if (m) {
        const log = document.getElementById('progressLog');
        if (log) log.textContent = '';
        m.style.display = 'block';
    }
}

function hideProgressModal() {
    const m = document.getElementById('progressModal');
    if (m) m.style.display = 'none';
}

function appendProgress(line) {
    const el = document.getElementById('progressLog');
    if (!el) return;
    el.textContent += (line + '\n');
    el.scrollTop = el.scrollHeight;
}

function pullWithProgress(name) {
    return new Promise((resolve, reject) => {
        const es = new EventSource(`/api/pull-stream?name=${encodeURIComponent(name)}`);
        es.addEventListener('log', (ev) => appendProgress(ev.data));
        es.addEventListener('done', () => { 
            es.close(); 
            appendProgress('[OK] 映像下載完成'); 
            resolve(); 
        });
        es.onerror = () => { 
            es.close(); 
            appendProgress('[Error] 下載中斷'); 
            reject(new Error('pull 失敗')); 
        };
    });
}