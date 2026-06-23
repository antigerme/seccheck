package br.com.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Valida os cabecalhos de seguranca emitidos pelo filtro — em especial a CSP
 * endurecida — usando proxies dinamicos (sem dependencia de mock framework).
 */
class SecurityHeadersFilterTest {

    /** Estado capturado da resposta durante o filtro. */
    private static final class Captured {
        final Map<String, String> headers = new HashMap<>();
        final AtomicInteger status = new AtomicInteger(200);
        final AtomicBoolean chainCalled = new AtomicBoolean(false);
    }

    private Captured runFilter(String method) throws Exception {
        Captured cap = new Captured();

        HttpServletRequest req = (HttpServletRequest) Proxy.newProxyInstance(
            getClass().getClassLoader(), new Class<?>[]{HttpServletRequest.class},
            (p, m, args) -> "getMethod".equals(m.getName()) ? method : defaultFor(m.getReturnType()));

        HttpServletResponse res = (HttpServletResponse) Proxy.newProxyInstance(
            getClass().getClassLoader(), new Class<?>[]{HttpServletResponse.class},
            (p, m, args) -> {
                switch (m.getName()) {
                    case "setHeader" -> cap.headers.put((String) args[0], (String) args[1]);
                    case "setStatus" -> cap.status.set((int) args[0]);
                }
                return defaultFor(m.getReturnType());
            });

        FilterChain chain = (FilterChain) Proxy.newProxyInstance(
            getClass().getClassLoader(), new Class<?>[]{FilterChain.class},
            (p, m, args) -> { cap.chainCalled.set(true); return null; });

        new SecurityHeadersFilter().doFilter(req, res, chain);
        return cap;
    }

    private static Object defaultFor(Class<?> t) {
        if (t == boolean.class) return false;
        if (t == int.class) return 0;
        if (t == long.class) return 0L;
        return null;
    }

    @Test
    void cspIsStrictNoUnsafeInlineNoExternalOrigins() throws Exception {
        String csp = runFilter("GET").headers.get("Content-Security-Policy");
        assertNotNull(csp);
        assertFalse(csp.contains("unsafe-inline"), "CSP nao deve permitir unsafe-inline");
        assertFalse(csp.contains("unsafe-eval"), "CSP nao deve permitir unsafe-eval");
        assertFalse(csp.contains("googleapis"), "CSP nao deve referenciar Google Fonts");
        assertFalse(csp.contains("gstatic"), "CSP nao deve referenciar Google Fonts");
        assertTrue(csp.contains("default-src 'self'"));
        assertTrue(csp.contains("script-src 'self'"));
        assertTrue(csp.contains("style-src 'self'"));
        assertTrue(csp.contains("frame-ancestors 'none'"));
        assertTrue(csp.contains("form-action 'self'"));
        assertTrue(csp.contains("base-uri 'self'"));
    }

    @Test
    void coreSecurityHeadersPresent() throws Exception {
        Map<String, String> h = runFilter("GET").headers;
        assertEquals("nosniff", h.get("X-Content-Type-Options"));
        assertEquals("DENY", h.get("X-Frame-Options"));
        assertEquals("strict-origin-when-cross-origin", h.get("Referrer-Policy"));
        assertNotNull(h.get("Permissions-Policy"));
    }

    @Test
    void allowedMethodsPassThrough() throws Exception {
        for (String m : new String[]{"GET", "POST", "HEAD"}) {
            Captured cap = runFilter(m);
            assertTrue(cap.chainCalled.get(), m + " deveria passar pela chain");
        }
    }

    @Test
    void disallowedMethodsAreRejected() throws Exception {
        for (String m : new String[]{"PUT", "DELETE", "TRACE", "OPTIONS"}) {
            Captured cap = runFilter(m);
            assertEquals(HttpServletResponse.SC_METHOD_NOT_ALLOWED, cap.status.get(),
                m + " deveria ser 405");
            assertFalse(cap.chainCalled.get(), m + " nao deveria chegar na chain");
            assertEquals("GET, POST, HEAD", cap.headers.get("Allow"));
        }
    }
}
