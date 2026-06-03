package br.com.security;

/**
 * Uma CVE individual encontrada num scan, ja decorada com a coordenada
 * Maven da dep afetada. Usado pelo cliente para computar o diff entre dois
 * scans (mesma {@code group:artifact:cve} = mesma finding).
 */
public final class ScanFinding {

    public final String groupId;
    public final String artifactId;
    public final String version;
    public final String cveName;
    public final Severity.Level severity;
    public final double cvssScore;

    public ScanFinding(String groupId, String artifactId, String version,
                       String cveName, Severity.Level severity, double cvssScore) {
        this.groupId = groupId;
        this.artifactId = artifactId;
        this.version = version;
        this.cveName = cveName;
        this.severity = severity;
        this.cvssScore = cvssScore;
    }
}
