package br.com.security;

import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.Future;

public class ScanStatus {
    public enum State {
        QUEUED, RUNNING, COMPLETED, ERROR, CANCELLED
    }

    /** Estado do resumo executivo gerado via Claude API (feature opcional). */
    public enum SummaryState {
        DISABLED,    // ANTHROPIC_API_KEY ausente — feature off
        PENDING,     // scan concluiu, geracao ainda nao iniciada
        GENERATING,  // chamada a Claude API em andamento
        READY,       // resumo disponivel
        FAILED       // chamada falhou (timeout, erro de API, etc.)
    }

    private State state;
    private String message;
    private int progress;
    private Path reportPath;
    private Path sbomPath;
    private Path workDir;
    private Future<?> task;
    private volatile boolean cancelRequested;
    private final long createdAt;
    private Severity.Level severity = Severity.Level.NONE;
    private int vulnerabilityCount;
    private List<FixSuggestion> fixSuggestions = List.of();
    private List<ScanFinding> findings = List.of();

    // Resumo executivo (feature opcional via Claude API)
    private SummaryState summaryState = SummaryState.DISABLED;
    private String executiveSummary;
    private long summaryGeneratedAt;
    // Idioma resolvido no upload (ex.: "pt-BR", "en-US"), usado para gerar o resumo
    private String langCode = "pt-BR";

    public ScanStatus(Path workDir) {
        this.state = State.QUEUED;
        this.message = "Aguardando na fila de processamento...";
        this.progress = 0;
        this.workDir = workDir;
        this.createdAt = System.currentTimeMillis();
    }

    public synchronized State getState() { return state; }
    public synchronized String getMessage() { return message; }
    public synchronized int getProgress() { return progress; }
    public synchronized Path getReportPath() { return reportPath; }
    public synchronized Path getSbomPath() { return sbomPath; }
    public synchronized void setSbomPath(Path sbomPath) { this.sbomPath = sbomPath; }
    public synchronized Path getWorkDir() { return workDir; }
    public long getCreatedAt() { return createdAt; }

    public synchronized void setTask(Future<?> task) { this.task = task; }
    public synchronized Future<?> getTask() { return task; }

    public synchronized Severity.Level getSeverity() { return severity; }
    public synchronized int getVulnerabilityCount() { return vulnerabilityCount; }
    public synchronized List<FixSuggestion> getFixSuggestions() { return fixSuggestions; }
    public synchronized List<ScanFinding> getFindings() { return findings; }
    public synchronized void setScanResult(Severity.Level severity, int vulnerabilityCount,
                                            List<FixSuggestion> fixSuggestions,
                                            List<ScanFinding> findings) {
        this.severity = severity;
        this.vulnerabilityCount = vulnerabilityCount;
        this.fixSuggestions = List.copyOf(fixSuggestions);
        this.findings = List.copyOf(findings);
    }

    public synchronized SummaryState getSummaryState() { return summaryState; }
    public synchronized void setSummaryState(SummaryState s) { this.summaryState = s; }
    /** True enquanto o resumo executivo ainda esta sendo gerado (ou na fila). */
    public synchronized boolean isSummaryPending() {
        return summaryState == SummaryState.PENDING || summaryState == SummaryState.GENERATING;
    }
    public synchronized String getExecutiveSummary() { return executiveSummary; }
    public synchronized long getSummaryGeneratedAt() { return summaryGeneratedAt; }
    public synchronized void setExecutiveSummary(String summary) {
        this.executiveSummary = summary;
        this.summaryState = SummaryState.READY;
        this.summaryGeneratedAt = System.currentTimeMillis();
    }
    public synchronized String getLangCode() { return langCode; }
    public synchronized void setLangCode(String langCode) {
        if (langCode != null && !langCode.isBlank()) this.langCode = langCode;
    }

    public boolean isCancelRequested() { return cancelRequested; }
    public void requestCancel() { this.cancelRequested = true; }

    public synchronized void update(State state, String message) {
        if (this.state == State.CANCELLED) return;
        this.state = state;
        this.message = message;
    }

    public synchronized void updateProgress(int progress, String message) {
        if (this.state == State.CANCELLED) return;
        this.progress = Math.min(progress, 100);
        this.message = message;
    }

    public synchronized void setCompleted(Path reportPath) {
        this.state = State.COMPLETED;
        this.message = "Relatorio gerado com sucesso!";
        this.progress = 100;
        this.reportPath = reportPath;
    }

    public synchronized void setCancelled() {
        this.state = State.CANCELLED;
        this.message = "Varredura cancelada pelo usuario.";
    }

    public synchronized boolean isFinal() {
        return state == State.COMPLETED || state == State.ERROR || state == State.CANCELLED;
    }
}
