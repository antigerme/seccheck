// Sistema simples de i18n. O idioma e detectado por (1) ?lang=xx na URL,
// (2) navigator.language, ou (3) fallback "pt-BR". Para adicionar idiomas,
// estenda o objeto MESSAGES e use t("chave") nos componentes.
(function () {
    const MESSAGES = {
        "pt-BR": {
            "upload.title": "Arraste seu arquivo .jar, .war ou .ear aqui",
            "upload.hint": "ou clique para selecionar",
            "upload.invalid": "Apenas arquivos .jar, .war e .ear sao suportados.",
            "upload.tooBig": "Arquivo muito grande para o limite do servidor.",
            "submit.start": "Iniciar Varredura",
            "submit.cancel": "Cancelar varredura",
            "submit.reset": "Fazer nova varredura",
            "submit.download": "Baixar Relatorio HTML",
            "submit.downloaded": "Relatorio Baixado",
            "status.sending": "Enviando arquivo...",
            "status.sendingDetail": "Aguarde o upload do arquivo para o servidor.",
            "status.processing": "Processando...",
            "status.completed": "Varredura Concluida!",
            "status.completedDetail": "O relatorio foi gerado com sucesso.",
            "status.cancelled": "Varredura cancelada.",
            "status.cancelledDetail": "Voce interrompeu a analise.",
            "status.error": "Erro na Varredura",
            "status.lostInServer": "Varredura perdida no servidor ou expirada.",
            "status.reconnecting": "Tentando reconectar ao servidor...",
            "status.giveUp": "Servidor nao responde apos varias tentativas. Recarregue a pagina.",
            "status.serverRefused": "Falha no upload. O servidor recusou o arquivo.",
            "status.communicationError": "Erro de comunicacao com o servidor.",
            "status.timeout": "Tempo de conexao esgotado.",
            "status.unexpected": "Resposta inesperada do servidor."
        },
        "en-US": {
            "upload.title": "Drop your .jar, .war or .ear file here",
            "upload.hint": "or click to select",
            "upload.invalid": "Only .jar, .war and .ear files are supported.",
            "upload.tooBig": "File too large for the server limit.",
            "submit.start": "Start Scan",
            "submit.cancel": "Cancel scan",
            "submit.reset": "Start a new scan",
            "submit.download": "Download HTML Report",
            "submit.downloaded": "Report Downloaded",
            "status.sending": "Uploading file...",
            "status.sendingDetail": "Please wait while the file is uploaded.",
            "status.processing": "Processing...",
            "status.completed": "Scan Completed!",
            "status.completedDetail": "Report generated successfully.",
            "status.cancelled": "Scan cancelled.",
            "status.cancelledDetail": "You interrupted the analysis.",
            "status.error": "Scan Error",
            "status.lostInServer": "Scan lost on the server or expired.",
            "status.reconnecting": "Trying to reconnect to the server...",
            "status.giveUp": "Server not responding after several retries. Refresh the page.",
            "status.serverRefused": "Upload failed. The server refused the file.",
            "status.communicationError": "Communication error with the server.",
            "status.timeout": "Connection timed out.",
            "status.unexpected": "Unexpected response from the server."
        }
    };

    function detectLang() {
        const urlLang = new URLSearchParams(location.search).get("lang");
        const candidates = [urlLang, navigator.language, "pt-BR"];
        for (const c of candidates) {
            if (!c) continue;
            if (MESSAGES[c]) return c;
            const short = c.split("-")[0];
            const match = Object.keys(MESSAGES).find(k => k.split("-")[0] === short);
            if (match) return match;
        }
        return "pt-BR";
    }

    const LANG = detectLang();

    window.t = function (key) {
        return (MESSAGES[LANG] && MESSAGES[LANG][key]) || (MESSAGES["pt-BR"][key]) || key;
    };
})();
