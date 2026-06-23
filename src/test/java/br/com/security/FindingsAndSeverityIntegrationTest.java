package br.com.security;

import io.github.jeremylong.openvulnerability.client.nvd.CvssV3Data;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.Engine;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** FindingsExtractor + Severity.worstOf contra a Engine real. */
class FindingsAndSeverityIntegrationTest {

    @Test
    void findingsCarryRichDetailsForApiParity() throws Exception {
        try (Engine engine = TestFixtures.evidenceEngine()) {
            engine.addDependency(TestFixtures.mavenDep("g", "a", "1.0.0",
                TestFixtures.richVuln("CVE-2021-44228", 10.0,
                    CvssV3Data.SeverityType.CRITICAL, "2.17.0", true)));

            List<ScanFinding> findings = FindingsExtractor.extract(engine);
            assertEquals(1, findings.size());
            ScanFinding f = findings.get(0);
            assertEquals("g", f.groupId);
            assertEquals("a", f.artifactId);
            assertEquals("CVE-2021-44228", f.cveName());
            assertEquals(Severity.Level.CRITICAL, f.severity());
            assertEquals(10.0, f.cvssScore(), 0.001);
            // os campos ricos (paridade com o SBOM) vivem em f.vuln
            assertNotNull(f.vuln.cvssVector);
            assertTrue(f.vuln.cwes.contains(502));
            assertTrue(f.vuln.knownExploited);
        }
    }

    @Test
    void worstOfReturnsHighestSeverityAcrossDeps() throws Exception {
        try (Engine engine = TestFixtures.evidenceEngine()) {
            engine.addDependency(TestFixtures.mavenDep("g", "low", "1.0.0",
                TestFixtures.richVuln("CVE-1", 3.0, CvssV3Data.SeverityType.LOW, null, false)));
            engine.addDependency(TestFixtures.mavenDep("g", "crit", "1.0.0",
                TestFixtures.richVuln("CVE-2", 9.8, CvssV3Data.SeverityType.CRITICAL, null, false)));
            engine.addDependency(TestFixtures.mavenDep("g", "med", "1.0.0",
                TestFixtures.richVuln("CVE-3", 5.0, CvssV3Data.SeverityType.MEDIUM, null, false)));

            assertEquals(Severity.Level.CRITICAL, Severity.worstOf(engine));
        }
    }

    @Test
    void worstOfIsNoneWhenNoVulns() throws Exception {
        try (Engine engine = TestFixtures.evidenceEngine()) {
            engine.addDependency(TestFixtures.mavenDep("g", "clean", "1.0.0"));
            assertEquals(Severity.Level.NONE, Severity.worstOf(engine));
        }
    }
}
