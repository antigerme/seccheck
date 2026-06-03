document.addEventListener('DOMContentLoaded', () => {
    // Aplica strings traduzidas pelos data-i18n (textContent por padrao).
    // Use data-i18n-html nas tags onde a string contem markup (ex.: <code>).
    // Como todas as strings vem do nosso proprio i18n.js (nao ha entrada de
    // usuario), innerHTML aqui e seguro.
    document.querySelectorAll('[data-i18n]').forEach(el => {
        el.textContent = t(el.getAttribute('data-i18n'));
    });
    document.querySelectorAll('[data-i18n-html]').forEach(el => {
        el.innerHTML = t(el.getAttribute('data-i18n-html'));
    });

    const form = document.getElementById('scanForm');
    const fileInput = document.getElementById('fileInput');
    const uploadLabel = document.querySelector('.upload-label');
    const fileInfo = document.getElementById('fileInfo');
    const fileName = document.getElementById('fileName');
    const fileSize = document.getElementById('fileSize');
    const removeFileBtn = document.getElementById('removeFile');
    const submitBtn = document.getElementById('submitBtn');
    const formError = document.getElementById('formError');

    const statusContainer = document.getElementById('statusContainer');
    const statusTitle = document.getElementById('statusTitle');
    const statusMessage = document.getElementById('statusMessage');
    const loaderSpinner = document.getElementById('loaderSpinner');
    const actionArea = document.getElementById('actionArea');
    const downloadBtn = document.getElementById('downloadBtn');
    const sbomBtn = document.getElementById('sbomBtn');
    const resetBtn = document.getElementById('resetBtn');
    const cancelBtn = document.getElementById('cancelBtn');

    const progressBarContainer = document.getElementById('progressBarContainer');
    const progressBarFill = document.getElementById('progressBarFill');
    const progressText = document.getElementById('progressText');

    const fixSuggestionsEl = document.getElementById('fixSuggestions');
    const fixSuggestionsLabel = document.getElementById('fixSuggestionsLabel');
    const fixSuggestionsList = document.getElementById('fixSuggestionsList');
    const fixSnippetAll = document.getElementById('fixSnippetAll');
    const copyAllFixesBtn = document.getElementById('copyAllFixesBtn');

    const summaryPanel = document.getElementById('summaryPanel');
    const summaryBadge = document.getElementById('summaryBadge');
    const summaryGenerating = document.getElementById('summaryGenerating');
    const summaryText = document.getElementById('summaryText');
    const summaryError = document.getElementById('summaryError');
    const summaryActions = document.getElementById('summaryActions');
    const summaryDisclaimer = document.getElementById('summaryDisclaimer');
    const copySummaryBtn = document.getElementById('copySummaryBtn');
    const downloadSummaryBtn = document.getElementById('downloadSummaryBtn');

    const compareBtn = document.getElementById('compareBtn');
    const diffPanel = document.getElementById('diffPanel');
    const diffSummary = document.getElementById('diffSummary');
    const diffNewCount = document.getElementById('diffNewCount');
    const diffFixedCount = document.getElementById('diffFixedCount');
    const diffUnchangedCount = document.getElementById('diffUnchangedCount');
    const diffNewList = document.getElementById('diffNewList');
    const diffFixedList = document.getElementById('diffFixedList');
    const diffNewSection = document.getElementById('diffNewSection');
    const diffFixedSection = document.getElementById('diffFixedSection');
    const baselineBanner = document.getElementById('baselineBanner');
    const baselineBannerLabel = document.getElementById('baselineBannerLabel');
    const clearBaselineBtn = document.getElementById('clearBaselineBtn');

    // Diff scan: o "baseline" e o resultado do scan anterior que o usuario
    // marcou como referencia ao clicar em "Comparar com nova versao". Fica em
    // memoria de sessao apenas — refresh limpa.
    let baseline = null;          // { fileName, findings: [...] }
    let currentScanFile = null;   // nome do arquivo do scan corrente

    let currentScanId = null;
    let pollTimer = null;
    let pollFailures = 0;
    let summaryPollTimer = null;
    let summaryPollAttempts = 0;
    const MAX_SUMMARY_POLLS = 30; // ~60s a 2s/poll
    const MAX_POLL_FAILURES = 6;
    const BASE_POLL_INTERVAL_MS = 2000;
    const SEVERITY_CLASSES = ['severity-none', 'severity-low', 'severity-medium', 'severity-high', 'severity-critical'];

    function applyMood(severity) {
        document.body.classList.remove(...SEVERITY_CLASSES);
        if (severity) document.body.classList.add('severity-' + severity.toLowerCase());
    }
    function clearMood() {
        document.body.classList.remove(...SEVERITY_CLASSES);
    }

    // Drag and Drop
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        uploadLabel.addEventListener(eventName, preventDefaults, false);
    });
    function preventDefaults(e) { e.preventDefault(); e.stopPropagation(); }

    ['dragenter', 'dragover'].forEach(eventName => {
        uploadLabel.addEventListener(eventName, () => uploadLabel.classList.add('dragover'), false);
    });
    ['dragleave', 'drop'].forEach(eventName => {
        uploadLabel.addEventListener(eventName, () => uploadLabel.classList.remove('dragover'), false);
    });

    uploadLabel.addEventListener('drop', (e) => handleFiles(e.dataTransfer.files));
    fileInput.addEventListener('change', function () { handleFiles(this.files); });

    function showFormError(msg) {
        formError.textContent = msg;
        formError.classList.remove('hidden');
    }
    function clearFormError() {
        formError.textContent = '';
        formError.classList.add('hidden');
    }

    function formatBytes(bytes) {
        if (bytes < 1024) return bytes + ' B';
        const units = ['KB', 'MB', 'GB'];
        let value = bytes / 1024;
        for (let i = 0; i < units.length; i++) {
            if (value < 1024 || i === units.length - 1) {
                return value.toFixed(value < 10 ? 1 : 0) + ' ' + units[i];
            }
            value /= 1024;
        }
        return bytes + ' B';
    }

    function handleFiles(files) {
        if (files.length === 0) return;
        const file = files[0];
        const validExtensions = ['.jar', '.war', '.ear'];
        const fileExtension = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();

        if (!validExtensions.includes(fileExtension)) {
            showFormError(t('upload.invalid'));
            return;
        }

        clearFormError();
        fileInput.files = files;
        fileName.textContent = file.name;
        fileSize.textContent = formatBytes(file.size);
        currentScanFile = file.name;
        uploadLabel.parentElement.classList.add('hidden');
        fileInfo.classList.remove('hidden');
        submitBtn.classList.remove('hidden');
    }

    removeFileBtn.addEventListener('click', resetForm);
    resetBtn.addEventListener('click', resetForm);
    cancelBtn.addEventListener('click', requestCancel);

    // resetForm(keepBaseline=false) - quando o usuario clica "Comparar com
    // nova versao", chamamos com keepBaseline=true (a baseline e definida e
    // o form e resetado pro proximo upload). Caso contrario, baseline tambem
    // e descartada.
    function resetForm(keepBaseline) {
        if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
        if (summaryPollTimer) { clearTimeout(summaryPollTimer); summaryPollTimer = null; }
        currentScanId = null;
        if (!keepBaseline) currentScanFile = null;
        pollFailures = 0;
        clearMood();

        if (!keepBaseline) clearBaseline();

        fileInput.value = '';
        clearFormError();
        uploadLabel.parentElement.classList.remove('hidden');
        fileInfo.classList.add('hidden');
        submitBtn.classList.add('hidden');
        form.classList.remove('hidden');
        statusContainer.classList.add('hidden');
        actionArea.classList.add('hidden');
        cancelBtn.classList.add('hidden');
        progressBarContainer.classList.add('hidden');
        fixSuggestionsEl.classList.add('hidden');
        fixSuggestionsEl.open = false;
        summaryPanel.classList.add('hidden');
        diffPanel.classList.add('hidden');
        diffPanel.open = false;
        loaderSpinner.style.display = 'inline-block';
        statusTitle.style.color = 'var(--text-primary)';
        downloadBtn.style.display = '';
        downloadBtn.style.pointerEvents = '';
        downloadBtn.classList.remove('btn-downloaded');
        downloadBtn.classList.add('btn-success');
        downloadBtn.onclick = null;
        sbomBtn.classList.add('hidden');
        sbomBtn.classList.remove('btn-downloaded');
        sbomBtn.style.pointerEvents = '';
        sbomBtn.onclick = null;
        resetBtn.style.width = '';

        updateProgressBar(0);

        const icon = statusTitle.previousElementSibling;
        if (icon && icon.tagName === 'svg') icon.remove();
    }

    function updateProgressBar(percent) {
        progressBarFill.style.width = percent + '%';
        progressText.textContent = percent + '%';
    }

    form.addEventListener('submit', (e) => {
        e.preventDefault();
        if (fileInput.files.length === 0) {
            showFormError(t('upload.invalid'));
            return;
        }
        clearFormError();
        const formData = new FormData(form);

        form.classList.add('hidden');
        statusContainer.classList.remove('hidden');
        progressBarContainer.classList.remove('hidden');
        cancelBtn.classList.remove('hidden');
        statusTitle.textContent = t('status.sending');
        statusMessage.textContent = t('status.sendingDetail');
        updateProgressBar(0);

        const xhr = new XMLHttpRequest();

        xhr.upload.addEventListener('progress', (event) => {
            if (event.lengthComputable) {
                const pct = Math.round((event.loaded / event.total) * 100);
                statusMessage.textContent = 'Enviando: ' + pct + '%';
                updateProgressBar(Math.min(3, Math.round(pct * 0.03)));
            }
        });

        xhr.addEventListener('load', () => {
            if (xhr.status >= 200 && xhr.status < 300) {
                try {
                    const result = JSON.parse(xhr.responseText);
                    startPolling(result.scanId);
                } catch (err) {
                    showError(t('status.unexpected'));
                }
            } else {
                let serverMsg = null;
                try {
                    serverMsg = JSON.parse(xhr.responseText).error;
                } catch (_) {}
                showError(serverMsg || t('status.serverRefused'));
            }
        });

        xhr.addEventListener('error', () => showError(t('status.communicationError')));
        xhr.addEventListener('timeout', () => showError(t('status.timeout')));

        // Passa o idioma resolvido pelo i18n para o resumo executivo sair no mesmo idioma da UI.
        const lang = window.currentLang || 'pt-BR';
        xhr.open('POST', 'api/scan?lang=' + encodeURIComponent(lang));
        xhr.timeout = 600000;
        xhr.send(formData);
    });

    function startPolling(scanId) {
        currentScanId = scanId;
        statusTitle.textContent = t('status.processing');
        pollFailures = 0;
        scheduleNextPoll(BASE_POLL_INTERVAL_MS);
    }

    function scheduleNextPoll(delay) {
        if (!currentScanId) return;
        pollTimer = setTimeout(pollOnce, delay);
    }

    async function pollOnce() {
        if (!currentScanId) return;
        try {
            const response = await fetch(`api/status?id=${currentScanId}`);
            if (response.ok) {
                pollFailures = 0;
                const status = await response.json();
                statusMessage.textContent = status.message;
                if (typeof status.progress === 'number') updateProgressBar(status.progress);

                if (status.state === 'COMPLETED') {
                    showSuccess(currentScanId, status);
                    return;
                } else if (status.state === 'ERROR') {
                    showError(status.message);
                    return;
                } else if (status.state === 'CANCELLED') {
                    showCancelled(status.message);
                    return;
                }
                scheduleNextPoll(BASE_POLL_INTERVAL_MS);
            } else if (response.status === 404) {
                showError(t('status.lostInServer'));
            } else {
                pollFailures++;
                handlePollFailure();
            }
        } catch (error) {
            pollFailures++;
            console.warn("Falha temporaria de rede no polling", error);
            handlePollFailure();
        }
    }

    function handlePollFailure() {
        if (pollFailures >= MAX_POLL_FAILURES) {
            showError(t('status.giveUp'));
            return;
        }
        statusMessage.textContent = t('status.reconnecting') +
            ' (' + pollFailures + '/' + MAX_POLL_FAILURES + ')';
        // Backoff exponencial: 2s, 4s, 8s, 16s, 32s, 60s (cap)
        const delay = Math.min(BASE_POLL_INTERVAL_MS * Math.pow(2, pollFailures), 60000);
        scheduleNextPoll(delay);
    }

    async function requestCancel() {
        if (!currentScanId) return;
        cancelBtn.disabled = true;
        try {
            await fetch(`api/cancel?id=${currentScanId}`, { method: 'POST' });
        } catch (err) {
            console.warn("Falha ao cancelar", err);
        }
        // O polling vai capturar o estado CANCELLED no proximo ciclo.
    }

    function showSuccess(scanId, statusData) {
        if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
        currentScanId = null;
        loaderSpinner.style.display = 'none';
        progressBarContainer.classList.add('hidden');
        cancelBtn.classList.add('hidden');
        statusTitle.textContent = t('status.completed');
        statusTitle.style.color = 'var(--success)';

        // Mood blobs: pinta o fundo conforme a severidade pior do scan.
        const severity = (statusData && statusData.severity) || 'NONE';
        const count = (statusData && typeof statusData.vulnerabilityCount === 'number') ? statusData.vulnerabilityCount : 0;
        applyMood(severity);

        if (severity === 'NONE' || count === 0) {
            statusMessage.textContent = t('status.cleanDetail');
        } else {
            const tpl = t('status.findingsDetail');
            statusMessage.textContent = tpl
                .replace('{n}', count)
                .replace('{sev}', t('severity.' + severity));
        }

        downloadBtn.href = `api/report?id=${scanId}`;
        downloadBtn.classList.remove('btn-downloaded');
        downloadBtn.classList.add('btn-success');
        downloadBtn.style.pointerEvents = '';
        downloadBtn.innerHTML = `
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
            <span>${t('submit.download')}</span>
        `;

        downloadBtn.onclick = function onFirstDownload() {
            downloadBtn.onclick = null;
            setTimeout(() => {
                downloadBtn.classList.remove('btn-success');
                downloadBtn.classList.add('btn-downloaded');
                downloadBtn.style.pointerEvents = 'none';
                downloadBtn.innerHTML = `
                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                    <span>${t('submit.downloaded')}</span>
                `;
            }, 400);
        };

        // SBOM (CycloneDX): mostra botao se foi gerado pelo motor.
        if (statusData && statusData.sbomAvailable) {
            sbomBtn.href = `api/sbom?id=${scanId}`;
            sbomBtn.classList.remove('hidden');
            sbomBtn.classList.remove('btn-downloaded');
            sbomBtn.style.pointerEvents = '';
            sbomBtn.onclick = function onSbomFirstDownload() {
                sbomBtn.onclick = null;
                setTimeout(() => {
                    sbomBtn.classList.add('btn-downloaded');
                    sbomBtn.style.pointerEvents = 'none';
                }, 400);
            };
        } else {
            sbomBtn.classList.add('hidden');
        }

        renderFixSuggestions(statusData && statusData.fixSuggestions);

        // Diff scan: se ha uma baseline guardada de scan anterior, computa
        // o delta de findings (mesma group:artifact:cve = mesma vuln).
        const findings = (statusData && statusData.findings) || [];
        if (baseline && baseline.findings) {
            renderDiff(baseline, { fileName: currentScanFile, findings });
        } else {
            diffPanel.classList.add('hidden');
        }
        // Guarda este scan como possivel proxima baseline (se o usuario clicar
        // "Comparar com nova versao"). NAO substitui a baseline existente.
        window.__lastScan = { fileName: currentScanFile, findings };

        // Resumo executivo: se a feature esta ligada (summaryState != DISABLED),
        // mostra o painel e inicia o polling de /api/summary.
        const summaryState = statusData && statusData.summaryState;
        if (summaryState && summaryState !== 'DISABLED') {
            startSummaryPanel(scanId, summaryState);
        } else {
            summaryPanel.classList.add('hidden');
        }

        actionArea.classList.remove('hidden');
        setStatusIcon('success');
    }

    // === Diff Scan helpers ===
    function setBaseline(scan) {
        if (!scan || !scan.findings) return;
        baseline = scan;
        baselineBannerLabel.textContent =
            t('baseline.label').replace('{name}', scan.fileName || '?');
        baselineBanner.classList.remove('hidden');
    }
    function clearBaseline() {
        baseline = null;
        baselineBanner.classList.add('hidden');
        diffPanel.classList.add('hidden');
        diffPanel.open = false;
    }
    function findingKey(f) { return f.groupId + ':' + f.artifactId + ':' + f.cveName; }

    function renderDiff(base, cand) {
        const baseMap = new Map();
        for (const f of base.findings) baseMap.set(findingKey(f), f);
        const candMap = new Map();
        for (const f of cand.findings) candMap.set(findingKey(f), f);

        const newOnes = [];
        const fixed = [];
        let unchanged = 0;
        for (const [k, f] of candMap) {
            if (baseMap.has(k)) unchanged++;
            else newOnes.push(f);
        }
        for (const [k, f] of baseMap) {
            if (!candMap.has(k)) fixed.push(f);
        }

        diffNewCount.textContent = newOnes.length;
        diffFixedCount.textContent = fixed.length;
        diffUnchangedCount.textContent = unchanged;
        diffSummary.textContent = t('diff.summary')
            .replace('{new}', newOnes.length)
            .replace('{fixed}', fixed.length)
            .replace('{unchanged}', unchanged);

        diffNewList.innerHTML = newOnes.map(renderFindingRow).join('');
        diffFixedList.innerHTML = fixed.map(renderFindingRow).join('');
        diffNewSection.style.display = newOnes.length === 0 ? 'none' : '';
        diffFixedSection.style.display = fixed.length === 0 ? 'none' : '';

        diffPanel.classList.remove('hidden');
        if (newOnes.length > 0 || fixed.length > 0) diffPanel.open = true;
    }

    function renderFindingRow(f) {
        return `
            <div class="diff-row">
                <span class="diff-row-coord">${escapeHtml(f.groupId)}:${escapeHtml(f.artifactId)}@${escapeHtml(f.version || '?')}</span>
                <span class="diff-row-cve">${escapeHtml(f.cveName)}</span>
                <span class="fix-badge severity-badge-${(f.severity || 'NONE').toLowerCase()}">${escapeHtml(t('severity.' + (f.severity || 'NONE')))}</span>
            </div>
        `;
    }

    if (compareBtn) {
        compareBtn.addEventListener('click', () => {
            // Marca o scan recem-concluido como baseline e reseta o form
            // para o proximo upload. Findings da baseline ficam em memoria.
            if (window.__lastScan) setBaseline(window.__lastScan);
            resetForm(true);
        });
    }
    if (clearBaselineBtn) {
        clearBaselineBtn.addEventListener('click', clearBaseline);
    }

    // === Resumo executivo (Claude API) ===
    function startSummaryPanel(scanId, initialState) {
        summaryPanel.classList.remove('hidden');
        summaryText.classList.add('hidden');
        summaryError.classList.add('hidden');
        summaryActions.classList.add('hidden');
        summaryDisclaimer.classList.add('hidden');
        summaryGenerating.classList.remove('hidden');
        summaryBadge.textContent = '';
        summaryPollAttempts = 0;

        if (initialState === 'READY') {
            // raro: ja pronto no primeiro status
            fetchSummaryOnce(scanId);
        } else if (initialState === 'FAILED') {
            renderSummaryFailed();
        } else {
            scheduleSummaryPoll(scanId);
        }
    }

    function scheduleSummaryPoll(scanId) {
        summaryPollTimer = setTimeout(() => fetchSummaryOnce(scanId), BASE_POLL_INTERVAL_MS);
    }

    async function fetchSummaryOnce(scanId) {
        summaryPollAttempts++;
        try {
            const resp = await fetch(`api/summary?id=${scanId}`);
            if (!resp.ok) {
                // 404 = scan ja foi removido (download concluido); para de tentar.
                renderSummaryFailed();
                return;
            }
            const data = await resp.json();
            if (data.state === 'READY') {
                renderSummaryReady(data.summary, data.model);
            } else if (data.state === 'FAILED' || data.state === 'DISABLED') {
                renderSummaryFailed();
            } else if (summaryPollAttempts >= MAX_SUMMARY_POLLS) {
                renderSummaryFailed();
            } else {
                scheduleSummaryPoll(scanId); // PENDING / GENERATING
            }
        } catch (e) {
            if (summaryPollAttempts >= MAX_SUMMARY_POLLS) {
                renderSummaryFailed();
            } else {
                scheduleSummaryPoll(scanId);
            }
        }
    }

    function renderSummaryReady(text, model) {
        if (summaryPollTimer) { clearTimeout(summaryPollTimer); summaryPollTimer = null; }
        summaryGenerating.classList.add('hidden');
        summaryError.classList.add('hidden');
        summaryText.textContent = text || '';
        summaryText.classList.remove('hidden');
        summaryActions.classList.remove('hidden');
        summaryDisclaimer.classList.remove('hidden');
        summaryBadge.textContent = model || '';
    }

    function renderSummaryFailed() {
        if (summaryPollTimer) { clearTimeout(summaryPollTimer); summaryPollTimer = null; }
        summaryGenerating.classList.add('hidden');
        summaryText.classList.add('hidden');
        summaryActions.classList.add('hidden');
        summaryDisclaimer.classList.add('hidden');
        summaryError.classList.remove('hidden');
        summaryBadge.textContent = '';
    }

    if (copySummaryBtn) {
        copySummaryBtn.addEventListener('click', async () => {
            const text = summaryText.textContent;
            if (!text) return;
            try {
                await navigator.clipboard.writeText(text);
                const old = copySummaryBtn.textContent;
                copySummaryBtn.textContent = t('summary.copied');
                setTimeout(() => copySummaryBtn.textContent = old, 1500);
            } catch (e) {
                console.warn('Falha ao copiar resumo', e);
            }
        });
    }
    if (downloadSummaryBtn) {
        downloadSummaryBtn.addEventListener('click', () => {
            const text = summaryText.textContent;
            if (!text) return;
            const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'seccheck-resumo.txt';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        });
    }

    function escapeHtml(s) {
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function renderFixSuggestions(suggestions) {
        fixSuggestionsList.innerHTML = '';
        fixSnippetAll.textContent = '';
        if (!suggestions || suggestions.length === 0) {
            fixSuggestionsEl.classList.add('hidden');
            return;
        }
        fixSuggestionsEl.classList.remove('hidden');
        fixSuggestionsLabel.textContent =
            t('fix.summary').replace('{n}', suggestions.length);

        // Snippet combinado (todas as deps em sequencia)
        fixSnippetAll.textContent = suggestions.map(s => s.pomSnippet).join('\n\n');

        // Lista detalhada com badge de severidade e CVEs
        for (const s of suggestions) {
            const card = document.createElement('div');
            card.className = 'fix-card';
            card.innerHTML = `
                <div class="fix-card-head">
                    <span class="fix-coord">${escapeHtml(s.groupId)}:${escapeHtml(s.artifactId)}</span>
                    <span class="fix-badge severity-badge-${s.severity.toLowerCase()}">${escapeHtml(t('severity.' + s.severity))}</span>
                </div>
                <div class="fix-meta">
                    <span class="fix-version-change">${escapeHtml(s.currentVersion)} → ${escapeHtml(s.fixedVersion)}</span>
                    <span class="fix-cves">${s.cves.map(escapeHtml).join(', ')}</span>
                </div>
            `;
            fixSuggestionsList.appendChild(card);
        }
    }

    if (copyAllFixesBtn) {
        copyAllFixesBtn.addEventListener('click', async () => {
            const text = fixSnippetAll.textContent;
            if (!text) return;
            try {
                await navigator.clipboard.writeText(text);
                const old = copyAllFixesBtn.textContent;
                copyAllFixesBtn.textContent = t('fix.copied');
                setTimeout(() => copyAllFixesBtn.textContent = old, 1500);
            } catch (e) {
                // Fallback: selectAll + execCommand (browsers antigos)
                const range = document.createRange();
                range.selectNodeContents(fixSnippetAll);
                const sel = window.getSelection();
                sel.removeAllRanges();
                sel.addRange(range);
            }
        });
    }

    function showError(msg) {
        if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
        currentScanId = null;
        loaderSpinner.style.display = 'none';
        progressBarContainer.classList.add('hidden');
        cancelBtn.classList.add('hidden');
        fixSuggestionsEl.classList.add('hidden');
        summaryPanel.classList.add('hidden');
        diffPanel.classList.add('hidden');
        statusTitle.textContent = t('status.error');
        statusTitle.style.color = 'var(--danger)';
        statusMessage.textContent = msg;

        actionArea.classList.remove('hidden');
        downloadBtn.style.display = 'none';
        sbomBtn.classList.add('hidden');
        resetBtn.style.width = '100%';
        setStatusIcon('error');
    }

    function showCancelled(msg) {
        if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
        currentScanId = null;
        loaderSpinner.style.display = 'none';
        progressBarContainer.classList.add('hidden');
        cancelBtn.classList.add('hidden');
        fixSuggestionsEl.classList.add('hidden');
        summaryPanel.classList.add('hidden');
        diffPanel.classList.add('hidden');
        statusTitle.textContent = t('status.cancelled');
        statusTitle.style.color = 'var(--text-secondary)';
        statusMessage.textContent = msg || t('status.cancelledDetail');

        actionArea.classList.remove('hidden');
        downloadBtn.style.display = 'none';
        sbomBtn.classList.add('hidden');
        resetBtn.style.width = '100%';
        setStatusIcon('cancelled');
    }

    function setStatusIcon(kind) {
        const oldIcon = statusTitle.previousElementSibling;
        if (oldIcon && oldIcon.tagName === 'svg') oldIcon.remove();
        const svgByKind = {
            success: `<svg style="margin-bottom: 1.5rem; color: var(--success);" xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>`,
            error: `<svg style="margin-bottom: 1.5rem; color: var(--danger);" xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>`,
            cancelled: `<svg style="margin-bottom: 1.5rem; color: var(--text-secondary);" xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"></line></svg>`
        };
        statusTitle.insertAdjacentHTML('beforebegin', svgByKind[kind] || '');
    }
});
