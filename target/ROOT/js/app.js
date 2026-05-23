document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('scanForm');
    const fileInput = document.getElementById('fileInput');
    const uploadLabel = document.querySelector('.upload-label');
    const fileInfo = document.getElementById('fileInfo');
    const fileName = document.getElementById('fileName');
    const removeFileBtn = document.getElementById('removeFile');
    const submitBtn = document.getElementById('submitBtn');
    
    const statusContainer = document.getElementById('statusContainer');
    const statusTitle = document.getElementById('statusTitle');
    const statusMessage = document.getElementById('statusMessage');
    const loaderSpinner = document.getElementById('loaderSpinner');
    const actionArea = document.getElementById('actionArea');
    const downloadBtn = document.getElementById('downloadBtn');
    const resetBtn = document.getElementById('resetBtn');

    // Progress bar elements
    const progressBarContainer = document.getElementById('progressBarContainer');
    const progressBarFill = document.getElementById('progressBarFill');
    const progressText = document.getElementById('progressText');

    // Drag and Drop Effects
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        uploadLabel.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    ['dragenter', 'dragover'].forEach(eventName => {
        uploadLabel.addEventListener(eventName, () => {
            uploadLabel.classList.add('dragover');
        }, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        uploadLabel.addEventListener(eventName, () => {
            uploadLabel.classList.remove('dragover');
        }, false);
    });

    uploadLabel.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        handleFiles(dt.files);
    });

    fileInput.addEventListener('change', function() {
        handleFiles(this.files);
    });

    function handleFiles(files) {
        if (files.length > 0) {
            const file = files[0];
            const validExtensions = ['.jar', '.war'];
            const fileExtension = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();

            if (validExtensions.includes(fileExtension)) {
                fileInput.files = files;
                fileName.textContent = file.name;
                uploadLabel.parentElement.classList.add('hidden');
                fileInfo.classList.remove('hidden');
                submitBtn.classList.remove('hidden');
            } else {
                alert('Apenas arquivos .jar e .war sao suportados.');
            }
        }
    }

    removeFileBtn.addEventListener('click', resetForm);
    resetBtn.addEventListener('click', resetForm);

    function resetForm() {
        fileInput.value = '';
        uploadLabel.parentElement.classList.remove('hidden');
        fileInfo.classList.add('hidden');
        submitBtn.classList.add('hidden');
        form.classList.remove('hidden');
        statusContainer.classList.add('hidden');
        actionArea.classList.add('hidden');
        progressBarContainer.classList.add('hidden');
        loaderSpinner.style.display = 'inline-block';
        statusTitle.style.color = 'var(--text-primary)';
        downloadBtn.style.display = '';
        resetBtn.style.width = '';
        
        // Resetar barra de progresso
        updateProgressBar(0);

        // Remove icones se existirem
        const icon = statusTitle.previousElementSibling;
        if(icon && icon.tagName === 'svg') icon.remove();
    }

    function updateProgressBar(percent) {
        progressBarFill.style.width = percent + '%';
        progressText.textContent = percent + '%';
    }

    form.addEventListener('submit', (e) => {
        e.preventDefault();

        if (fileInput.files.length === 0) {
            alert('Por favor, selecione um arquivo.');
            return;
        }

        const formData = new FormData(form);

        form.classList.add('hidden');
        statusContainer.classList.remove('hidden');
        progressBarContainer.classList.remove('hidden');
        statusTitle.textContent = 'Enviando arquivo...';
        statusMessage.textContent = 'Aguarde o upload do arquivo para o servidor.';
        updateProgressBar(0);

        // Usar XMLHttpRequest para capturar progresso de upload
        const xhr = new XMLHttpRequest();

        xhr.upload.addEventListener('progress', (event) => {
            if (event.lengthComputable) {
                const pct = Math.round((event.loaded / event.total) * 100);
                statusMessage.textContent = 'Enviando: ' + pct + '%';
                // Upload ocupa de 0% a 3% da barra total (scan e o grosso)
                updateProgressBar(Math.min(3, Math.round(pct * 0.03)));
            }
        });

        xhr.addEventListener('load', () => {
            if (xhr.status >= 200 && xhr.status < 300) {
                try {
                    const result = JSON.parse(xhr.responseText);
                    startPolling(result.scanId);
                } catch (err) {
                    showError('Resposta inesperada do servidor.');
                }
            } else {
                showError('Falha no upload do arquivo. O servidor recusou.');
            }
        });

        xhr.addEventListener('error', () => {
            showError('Erro de comunicacao com o servidor.');
        });

        xhr.addEventListener('timeout', () => {
            showError('Tempo de conexao esgotado.');
        });

        xhr.open('POST', 'api/scan');
        xhr.timeout = 600000; // 10 minutos para uploads grandes
        xhr.send(formData);
    });

    function startPolling(scanId) {
        statusTitle.textContent = 'Processando...';
        
        const pollInterval = setInterval(async () => {
            try {
                const response = await fetch(`api/status?id=${scanId}`);
                if (response.ok) {
                    const status = await response.json();
                    statusMessage.textContent = status.message;
                    
                    // Atualizar barra de progresso com valor do servidor
                    if (typeof status.progress === 'number') {
                        updateProgressBar(status.progress);
                    }
                    
                    if (status.state === 'COMPLETED') {
                        clearInterval(pollInterval);
                        showSuccess(scanId);
                    } else if (status.state === 'ERROR') {
                        clearInterval(pollInterval);
                        showError(status.message);
                    }
                } else {
                    clearInterval(pollInterval);
                    showError('Varredura perdida no servidor ou expirada.');
                }
            } catch (error) {
                // Tenta novamente na proxima iteracao
                console.warn("Falha temporaria de rede no polling", error);
            }
        }, 2000); // Poll a cada 2 segundos (era 3s, mais responsivo agora)
    }

    function showSuccess(scanId) {
        loaderSpinner.style.display = 'none';
        progressBarContainer.classList.add('hidden');
        statusTitle.textContent = 'Varredura Concluida!';
        statusTitle.style.color = 'var(--success)';
        statusMessage.textContent = 'O relatorio foi gerado com sucesso.';
        
        downloadBtn.href = `api/report?id=${scanId}`;
        actionArea.classList.remove('hidden');
        
        // Adiciona icone de sucesso
        const oldIcon = statusTitle.previousElementSibling;
        if(oldIcon && oldIcon.tagName === 'svg') oldIcon.remove();
        
        statusTitle.insertAdjacentHTML('beforebegin', `
            <svg style="margin-bottom: 1.5rem; color: var(--success);" xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
        `);
    }

    function showError(msg) {
        loaderSpinner.style.display = 'none';
        progressBarContainer.classList.add('hidden');
        statusTitle.textContent = 'Erro na Varredura';
        statusTitle.style.color = 'var(--danger)';
        statusMessage.textContent = msg;
        
        actionArea.classList.remove('hidden');
        downloadBtn.style.display = 'none'; // Esconde botao de download
        resetBtn.style.width = '100%';
        
        // Adiciona icone de erro
        const oldIcon = statusTitle.previousElementSibling;
        if(oldIcon && oldIcon.tagName === 'svg') oldIcon.remove();
        
        statusTitle.insertAdjacentHTML('beforebegin', `
            <svg style="margin-bottom: 1.5rem; color: var(--danger);" xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>
        `);
    }
});
