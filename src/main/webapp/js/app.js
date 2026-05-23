document.addEventListener('DOMContentLoaded', () => {
    // Aplica strings traduzidas pelos data-i18n
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        el.textContent = t(key);
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
    const resetBtn = document.getElementById('resetBtn');
    const cancelBtn = document.getElementById('cancelBtn');

    const progressBarContainer = document.getElementById('progressBarContainer');
    const progressBarFill = document.getElementById('progressBarFill');
    const progressText = document.getElementById('progressText');

    let currentScanId = null;
    let pollTimer = null;
    let pollFailures = 0;
    const MAX_POLL_FAILURES = 6;
    const BASE_POLL_INTERVAL_MS = 2000;

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
        const validExtensions = ['.jar', '.war'];
        const fileExtension = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();

        if (!validExtensions.includes(fileExtension)) {
            showFormError(t('upload.invalid'));
            return;
        }

        clearFormError();
        fileInput.files = files;
        fileName.textContent = file.name;
        fileSize.textContent = formatBytes(file.size);
        uploadLabel.parentElement.classList.add('hidden');
        fileInfo.classList.remove('hidden');
        submitBtn.classList.remove('hidden');
    }

    removeFileBtn.addEventListener('click', resetForm);
    resetBtn.addEventListener('click', resetForm);
    cancelBtn.addEventListener('click', requestCancel);

    function resetForm() {
        if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
        currentScanId = null;
        pollFailures = 0;

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
        loaderSpinner.style.display = 'inline-block';
        statusTitle.style.color = 'var(--text-primary)';
        downloadBtn.style.display = '';
        downloadBtn.style.pointerEvents = '';
        downloadBtn.classList.remove('btn-downloaded');
        downloadBtn.classList.add('btn-success');
        downloadBtn.onclick = null;
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

        xhr.open('POST', 'api/scan');
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
                    showSuccess(currentScanId);
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

    function showSuccess(scanId) {
        if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
        currentScanId = null;
        loaderSpinner.style.display = 'none';
        progressBarContainer.classList.add('hidden');
        cancelBtn.classList.add('hidden');
        statusTitle.textContent = t('status.completed');
        statusTitle.style.color = 'var(--success)';
        statusMessage.textContent = t('status.completedDetail');

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

        actionArea.classList.remove('hidden');
        setStatusIcon('success');
    }

    function showError(msg) {
        if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
        currentScanId = null;
        loaderSpinner.style.display = 'none';
        progressBarContainer.classList.add('hidden');
        cancelBtn.classList.add('hidden');
        statusTitle.textContent = t('status.error');
        statusTitle.style.color = 'var(--danger)';
        statusMessage.textContent = msg;

        actionArea.classList.remove('hidden');
        downloadBtn.style.display = 'none';
        resetBtn.style.width = '100%';
        setStatusIcon('error');
    }

    function showCancelled(msg) {
        if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
        currentScanId = null;
        loaderSpinner.style.display = 'none';
        progressBarContainer.classList.add('hidden');
        cancelBtn.classList.add('hidden');
        statusTitle.textContent = t('status.cancelled');
        statusTitle.style.color = 'var(--text-secondary)';
        statusMessage.textContent = msg || t('status.cancelledDetail');

        actionArea.classList.remove('hidden');
        downloadBtn.style.display = 'none';
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
