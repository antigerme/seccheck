package br.com.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * compareVersions e package-private; testamos aqui o ordenamento usado para
 * escolher o maior {@code versionEndExcluding} entre as CVEs de um artefato.
 */
class FixSuggesterVersionTest {

    @Test
    void higherVersionWins() {
        assertTrue(FixSuggester.compareVersions("2.17.0", "2.14.1") > 0);
        assertTrue(FixSuggester.compareVersions("2.11.0", "2.9.0") > 0);
        assertTrue(FixSuggester.compareVersions("5.6.1", "5.6") > 0);
        assertTrue(FixSuggester.compareVersions("10.0.0", "9.9.9") > 0);
    }

    @Test
    void equalVersionsAreZero() {
        assertTrue(FixSuggester.compareVersions("2.17.0", "2.17.0") == 0);
    }

    @Test
    void nullIsLowest() {
        // null = "ainda nao temos versao de fix" — qualquer versao real vence.
        assertTrue(FixSuggester.compareVersions("1.0.0", null) > 0);
        assertTrue(FixSuggester.compareVersions(null, "1.0.0") < 0);
        assertTrue(FixSuggester.compareVersions(null, null) == 0);
    }

    @Test
    void nonNumericPartsDoNotThrow() {
        // versoes com qualificadores nao podem quebrar a comparacao.
        assertTrue(FixSuggester.compareVersions("2.17.0-RELEASE", "2.14.1") > 0);
    }
}
