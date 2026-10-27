let events = [];
let selectedEventId = null;
let currentTab = 'payload';
let activeSecret = '';

document.addEventListener('DOMContentLoaded', () => {
    initSSE();
    updateReceiverUrlDisplay();
});

function updateReceiverUrlDisplay() {
    const origin = window.location.origin;
    const url = `${origin}/webhook`;
    const el = document.getElementById('receiverUrlDisplay');
    if (el) el.innerText = url;
}

function initSSE() {
    const es = new EventSource('/events');

    es.onmessage = (e) => {
        try {
            const data = JSON.parse(e.data);
            if (data.type === 'init') {
                activeSecret = data.secret || '';
                const secretInp = document.getElementById('secretInput');
                if (secretInp) secretInp.value = activeSecret;
                events = data.logs || [];
                renderEventList();
                if (events.length > 0 && !selectedEventId) {
                    selectEvent(events[0].id);
                }
            } else if (data.type === 'secret_updated') {
                activeSecret = data.data.secret || '';
                const secretInp = document.getElementById('secretInput');
                if (secretInp) secretInp.value = activeSecret;
                showToast('Webhook secret updated');
            } else if (data.type === 'new_event') {
                const newEvt = data.data;
                events.unshift(newEvt);
                if (events.length > 50) events.pop();
                renderEventList();
                // Select new event automatically
                selectEvent(newEvt.id);
            }
        } catch (err) {
            console.error('SSE parse error:', err);
        }
    };

    es.onerror = (err) => {
        console.warn('SSE connection disconnected, attempting reconnect...');
    };
}

function updateKpiCards() {
    const totalEl = document.getElementById('kpiTotalEvents');
    const verifiedEl = document.getElementById('kpiVerifiedEvents');
    const rejectedEl = document.getElementById('kpiRejectedEvents');
    const lastTimeEl = document.getElementById('kpiLastEventTime');

    if (totalEl) totalEl.innerText = events.length;
    if (verifiedEl) verifiedEl.innerText = events.filter(e => e.is_signature_valid).length;
    if (rejectedEl) rejectedEl.innerText = events.filter(e => !e.is_signature_valid).length;
    if (lastTimeEl) {
        if (events.length > 0) {
            const d = new Date(events[0].received_at);
            lastTimeEl.innerText = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        } else {
            lastTimeEl.innerText = 'None Yet';
        }
    }
}

function renderEventList() {
    const feed = document.getElementById('eventFeed');
    const badge = document.getElementById('eventCountBadge');
    if (badge) badge.innerText = `${events.length} event${events.length === 1 ? '' : 's'}`;

    updateKpiCards();

    if (events.length === 0) {
        feed.innerHTML = `
            <div class="empty-state" id="emptyState">
                <div class="empty-icon"><i class="fa-solid fa-satellite-dish"></i></div>
                <h4>Awaiting Webhook Events...</h4>
                <p>Configure a webhook in the Inavate Portal pointing to this endpoint (or via ngrok) or click <strong>"Send Valid Event"</strong> above to test locally.</p>
            </div>
        `;
        clearInspector();
        return;
    }

    let html = '';
    events.forEach(evt => {
        const isSelected = evt.id === selectedEventId;
        const timeFormatted = new Date(evt.received_at).toLocaleTimeString();
        const statusClass = `status-${evt.verification_status || 'verified'}`;
        const statusLabel = formatStatusLabel(evt.verification_status);

        html += `
            <div class="event-card-item ${isSelected ? 'active' : ''}" onclick="selectEvent('${escapeHtml(evt.id)}')">
                <div class="item-top">
                    <span class="event-type-badge">${escapeHtml(evt.event_type || 'unknown')}</span>
                    <span class="event-time">${timeFormatted}</span>
                </div>
                <div class="item-mid">
                    <span class="mono" style="font-size:0.75rem; color:var(--text-dark); font-weight:600;">${escapeHtml(evt.id)}</span>
                    <span class="status-badge ${statusClass}">
                        ${evt.is_signature_valid ? '<i class="fa-solid fa-shield-check"></i>' : '<i class="fa-solid fa-triangle-exclamation"></i>'}
                        ${statusLabel}
                    </span>
                </div>
            </div>
        `;
    });

    feed.innerHTML = html;
}

function selectEvent(id) {
    selectedEventId = id;
    renderEventList();
    renderInspector();
}

function clearInspector() {
    selectedEventId = null;
    const badge = document.getElementById('inspectingEventIdBadge');
    if (badge) badge.innerText = '—';
    const content = document.getElementById('inspectorContent');
    if (content) {
        content.innerHTML = `
            <div class="inspector-placeholder">
                <i class="fa-solid fa-hand-pointer"></i>
                <p>Select a webhook event from the left panel to inspect parameters, security verification logs, and raw payload data.</p>
            </div>
        `;
    }
}

function syntaxHighlightJson(json) {
    const escaped = escapeHtml(json);
    return escaped.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
        let style = 'color:#D97706;'; // amber number
        if (/^"/.test(match)) {
            if (/:$/.test(match)) {
                style = 'color:#1E40AF; font-weight:600;'; // blue key
            } else {
                style = 'color:#059669;'; // green string
            }
        } else if (/true|false/.test(match)) {
            style = 'color:#7C3AED; font-weight:600;'; // purple boolean
        } else if (/null/.test(match)) {
            style = 'color:#94A3B8; font-style:italic;'; // gray null
        }
        return `<span style="${style}">${match}</span>`;
    });
}

function renderInspector() {
    const evt = events.find(e => e.id === selectedEventId);
    if (!evt) {
        clearInspector();
        return;
    }

    const badge = document.getElementById('inspectingEventIdBadge');
    if (badge) badge.innerText = evt.id;
    const content = document.getElementById('inspectorContent');
    if (!content) return;

    if (currentTab === 'payload') {
        const prettyJson = JSON.stringify(evt.parsed_payload || JSON.parse(evt.raw_payload || '{}'), null, 2);
        const highlightedJson = syntaxHighlightJson(prettyJson);
        content.innerHTML = `
            <div class="inspector-section">
                <div class="section-label">
                    <span>Parsed JSON Payload</span>
                    <button type="button" class="btn btn-xs btn-outline" onclick="copyToClipboard('${escapeJsString(prettyJson)}')">
                        <i class="fa-solid fa-copy"></i> Copy JSON
                    </button>
                </div>
                <pre class="code-viewer"><code>${highlightedJson}</code></pre>
            </div>
        `;
    } else if (currentTab === 'headers') {
        let headersRows = '';
        for (const [k, v] of Object.entries(evt.headers || {})) {
            const isSignature = k.toLowerCase().includes('signature');
            const isTimestamp = k.toLowerCase().includes('timestamp');
            headersRows += `
                <tr>
                    <td class="mono" style="font-weight:${isSignature || isTimestamp ? '700' : '500'}; color:${isSignature || isTimestamp ? 'var(--primary-color)' : 'inherit'};">${escapeHtml(k)}</td>
                    <td class="mono" style="word-break:break-all; color:var(--text-dark);">${escapeHtml(v)}</td>
                </tr>
            `;
        }
        content.innerHTML = `
            <div class="inspector-section">
                <div class="section-label">HTTP Request Delivery Headers</div>
                <table class="header-table">
                    <thead>
                        <tr>
                            <th style="width:240px;">Header Key</th>
                            <th>Header Value</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${headersRows || '<tr><td colspan="2">No headers recorded</td></tr>'}
                    </tbody>
                </table>
            </div>
        `;
    } else if (currentTab === 'crypto') {
        const timeDiff = evt.time_diff_seconds != null ? `${evt.time_diff_seconds}s` : 'Unknown';
        const isTimeOk = evt.time_diff_seconds != null && evt.time_diff_seconds <= 300;

        content.innerHTML = `
            <div class="inspector-section">
                <div class="section-label">Cryptographic Verification Breakdown</div>
                <div class="audit-checklist">
                    <div class="audit-item ${isTimeOk ? 'pass' : 'fail'}">
                        <i class="fa-solid ${isTimeOk ? 'fa-circle-check' : 'fa-circle-xmark'}"></i>
                        <span><strong>Replay Attack Prevention:</strong> Timestamp drift is <strong>${timeDiff}</strong> (threshold: &le; 300s).</span>
                    </div>
                    <div class="audit-item ${evt.is_signature_valid ? 'pass' : 'fail'}">
                        <i class="fa-solid ${evt.is_signature_valid ? 'fa-circle-check' : 'fa-circle-xmark'}"></i>
                        <span><strong>HMAC-SHA256 Match:</strong> Computed signature matches <code>X-Inavate-Signature</code> header.</span>
                    </div>
                    <div class="audit-item ${evt.is_signature_valid ? 'pass' : 'fail'}">
                        <i class="fa-solid ${evt.is_signature_valid ? 'fa-circle-check' : 'fa-circle-xmark'}"></i>
                        <span><strong>Constant-Time Compare:</strong> Verified using <code>subtle.ConstantTimeCompare</code> to prevent timing attacks.</span>
                    </div>
                </div>

                <div style="margin-top:20px;">
                    <div class="section-label">Signature Comparison Details</div>
                    <table class="header-table">
                        <tr>
                            <td style="width:200px; font-weight:600;">Header Signature:</td>
                            <td class="mono" style="word-break:break-all; font-size:0.82rem; font-weight:600; color:${evt.is_signature_valid ? 'var(--success-dark)' : 'var(--danger-dark)'};">${escapeHtml(evt.signature_header || 'Missing')}</td>
                        </tr>
                        <tr>
                            <td style="font-weight:600;">Computed Signature:</td>
                            <td class="mono" style="word-break:break-all; font-size:0.82rem; color:var(--text-color);">${escapeHtml(evt.computed_signature || 'N/A')}</td>
                        </tr>
                        ${evt.verification_error ? `<tr><td style="font-weight:600;">Verification Failure:</td><td style="color:var(--danger-dark); font-weight:600;">${escapeHtml(evt.verification_error)}</td></tr>` : ''}
                    </table>
                </div>
            </div>
        `;
    }
}

function switchInspectorTab(tab) {
    currentTab = tab;
    document.querySelectorAll('.inspector-tabs .tab-btn').forEach(btn => btn.classList.remove('active'));
    const btn = Array.from(document.querySelectorAll('.inspector-tabs .tab-btn')).find(b => b.innerText.toLowerCase().includes(tab.slice(0, 4)));
    if (btn) btn.classList.add('active');
    renderInspector();
}

function switchCodeLang(lang) {
    document.querySelectorAll('.lang-tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.code-snippet-box').forEach(box => box.classList.add('hidden'));

    const btn = Array.from(document.querySelectorAll('.lang-tab-btn')).find(b => b.innerText.toLowerCase().includes(lang.slice(0, 2)));
    if (btn) btn.classList.add('active');

    const target = document.getElementById(`code-${lang}`);
    if (target) target.classList.remove('hidden');
}

function simulateEvent(tamper) {
    const sel = document.getElementById('simEventType');
    const eventType = sel ? sel.value : 'transaction.status_changed';

    fetch('/api/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            event_type: eventType,
            tamper_signature: tamper
        })
    })
    .then(r => r.json())
    .then(data => {
        showToast(tamper ? 'Simulated tampered event sent (expect rejection)' : 'Valid simulation event sent');
    })
    .catch(err => {
        alert('Simulation error: ' + err.message);
    });
}

function updateSecret() {
    const input = document.getElementById('secretInput');
    const secret = input.value.trim();
    if (!secret) {
        alert('Please enter a non-empty secret');
        return;
    }

    fetch('/api/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ secret: secret })
    })
    .then(r => r.json())
    .then(data => {
        activeSecret = data.secret;
        showToast('Webhook secret updated successfully');
    })
    .catch(err => {
        alert('Failed to update secret: ' + err.message);
    });
}

function copySecret() {
    const input = document.getElementById('secretInput');
    if (!input || !input.value) return;
    navigator.clipboard.writeText(input.value);
    showToast('Secret copied to clipboard');
}

function copyReceiverUrl() {
    const el = document.getElementById('receiverUrlDisplay');
    if (!el) return;
    navigator.clipboard.writeText(el.innerText);
    showToast('Receiver URL copied');
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text);
    showToast('Copied to clipboard');
}

function showToast(msg) {
    const toast = document.createElement('div');
    toast.className = 'portal-toast';
    toast.innerHTML = `<i class="fa-solid fa-circle-check" style="color:var(--success-color);"></i> <span>${escapeHtml(msg)}</span>`;
    document.body.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 0.2s';
        setTimeout(() => toast.remove(), 200);
    }, 2200);
}

function clearEventList() {
    events = [];
    clearInspector();
    renderEventList();
    showToast('Event history cleared');
}

function formatStatusLabel(st) {
    if (!st || st === 'verified') return 'Verified';
    if (st === 'invalid_signature') return 'Invalid Sig';
    if (st === 'expired_timestamp') return 'Expired TS';
    if (st === 'missing_headers') return 'Missing Headers';
    return st;
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function escapeJsString(str) {
    return str.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n');
}
