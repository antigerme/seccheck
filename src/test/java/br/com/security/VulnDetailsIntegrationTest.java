package br.com.security;

import io.github.jeremylong.openvulnerability.client.nvd.CvssV3Data;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.dependency.Vulnerability;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercita a reflection de {@link VulnDetails} contra a API REAL do
 * dependency-check. Se um getter for renomeado entre versoes, estes testes
 * quebram — em vez de o campo sumir silenciosamente do SBOM e da API.
 */
class VulnDetailsIntegrationTest {

    @Test
    void extractsAllRichFields() throws Exception {
        Vulnerability v = TestFixtures.richVuln(
            "CVE-2021-44228", 10.0, CvssV3Data.SeverityType.CRITICAL, "2.17.0", true);

        VulnDetails d = VulnDetails.from(v);
        assertNotNull(d);
        assertEquals("CVE-2021-44228", d.cveName);
        assertEquals("NVD", d.source);
        assertNotNull(d.description);
        assertEquals(10.0, d.cvssScore, 0.001);
        assertEquals(Severity.Level.CRITICAL, d.severity);
        assertEquals("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", d.cvssVector);
        assertEquals("CVSSv31", d.cvssMethod());
        // CWE-502 / CWE-917 -> inteiros, como a spec CycloneDX exige
        assertTrue(d.cwes.contains(502));
        assertTrue(d.cwes.contains(917));
        assertEquals(1, d.advisories.size());
        assertEquals("https://nvd.nist.gov/vuln/detail/CVE-2021-44228", d.advisories.get(0).url());
        assertTrue(d.knownExploited);
    }

    @Test
    void nonKevVulnHasFlagFalse() throws Exception {
        Vulnerability v = TestFixtures.richVuln(
            "CVE-2021-45046", 9.0, CvssV3Data.SeverityType.CRITICAL, "2.17.0", false);
        VulnDetails d = VulnDetails.from(v);
        assertNotNull(d);
        assertFalse(d.knownExploited);
    }

    @Test
    void vulnWithoutNameReturnsNull() {
        Vulnerability v = new Vulnerability(); // sem setName
        assertNull(VulnDetails.from(v));
    }
}
