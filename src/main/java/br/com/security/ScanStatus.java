package br.com.security;

import java.nio.file.Path;
import java.util.concurrent.Future;

public class ScanStatus {
    public enum State {
        QUEUED, RUNNING, COMPLETED, ERROR, CANCELLED
    }

    private State state;
    private String message;
    private int progress;
    private Path reportPath;
    private Path workDir;
    private Future<?> task;
    private volatile boolean cancelRequested;
    private final long createdAt;
    private long startedAt;
    private long finishedAt;

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
    public synchronized Path getWorkDir() { return workDir; }
    public long getCreatedAt() { return createdAt; }
    public synchronized long getStartedAt() { return startedAt; }
    public synchronized long getFinishedAt() { return finishedAt; }

    public synchronized void setTask(Future<?> task) { this.task = task; }
    public synchronized Future<?> getTask() { return task; }

    public boolean isCancelRequested() { return cancelRequested; }
    public void requestCancel() { this.cancelRequested = true; }

    public synchronized void update(State state, String message) {
        if (this.state == State.CANCELLED) return;
        if (state == State.RUNNING && this.startedAt == 0) {
            this.startedAt = System.currentTimeMillis();
        }
        if (state == State.COMPLETED || state == State.ERROR || state == State.CANCELLED) {
            this.finishedAt = System.currentTimeMillis();
        }
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
        this.finishedAt = System.currentTimeMillis();
    }

    public synchronized void setCancelled() {
        this.state = State.CANCELLED;
        this.message = "Varredura cancelada pelo usuario.";
        this.finishedAt = System.currentTimeMillis();
    }

    public synchronized boolean isFinal() {
        return state == State.COMPLETED || state == State.ERROR || state == State.CANCELLED;
    }
}
