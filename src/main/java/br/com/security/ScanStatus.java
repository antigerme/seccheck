package br.com.security;

import java.nio.file.Path;

public class ScanStatus {
    public enum State {
        QUEUED, RUNNING, COMPLETED, ERROR
    }

    private State state;
    private String message;
    private int progress;
    private Path reportPath;
    private Path workDir; // Needed for cleanup later
    private final long createdAt;

    public ScanStatus() {
        this.state = State.QUEUED;
        this.message = "Aguardando na fila de processamento...";
        this.progress = 0;
        this.createdAt = System.currentTimeMillis();
    }

    public synchronized State getState() { return state; }
    public synchronized String getMessage() { return message; }
    public synchronized int getProgress() { return progress; }
    public synchronized Path getReportPath() { return reportPath; }
    public synchronized Path getWorkDir() { return workDir; }
    public long getCreatedAt() { return createdAt; }

    public synchronized void update(State state, String message) {
        this.state = state;
        this.message = message;
    }

    public synchronized void updateProgress(int progress, String message) {
        this.progress = Math.min(progress, 100);
        this.message = message;
    }

    public synchronized void setCompleted(Path reportPath, Path workDir) {
        this.state = State.COMPLETED;
        this.message = "Relatorio gerado com sucesso!";
        this.progress = 100;
        this.reportPath = reportPath;
        this.workDir = workDir;
    }
}
