package br.com.security;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebFilter(filterName = "SecurityHeadersFilter", urlPatterns = {"/*"})
public class SecurityHeadersFilter implements Filter {

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        // [SEC] Impede que o browser adivinhe o Content-Type (MIME sniffing)
        response.setHeader("X-Content-Type-Options", "nosniff");

        // [SEC] Impede que a aplicacao seja embarcada em um iframe (Clickjacking)
        response.setHeader("X-Frame-Options", "DENY");

        // [SEC] Força HTTPS por 1 ano (ative somente se o servidor usa SSL/TLS)
        // response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");

        // [SEC] Content-Security-Policy endurecida (sem origens externas, sem unsafe-*).
        // A UI usa stack de fontes do sistema (zero Google Fonts), scripts e estilos
        // vem so de 'self', e todos os estilos inline foram migrados para classes —
        // por isso style-src nao precisa mais de 'unsafe-inline'. img-src mantem
        // 'data:' para os SVGs inline. form-action/base-uri fecham vetores classicos
        // de XSS (form sequestrado, <base> reroteando caminhos relativos).
        response.setHeader("Content-Security-Policy",
            "default-src 'self'; " +
            "script-src 'self'; " +
            "style-src 'self'; " +
            "img-src 'self' data:; " +
            "font-src 'self'; " +
            "connect-src 'self'; " +
            "form-action 'self'; " +
            "base-uri 'self'; " +
            "frame-ancestors 'none'");

        // [SEC] Controla como o Referer e enviado ao navegar
        response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

        // [SEC] Restringe APIs sensiveis do browser por padrao
        response.setHeader("Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()");

        // [SEC] Rejeita metodos HTTP nao utilizados. HEAD e tratado como GET
        // pelo Servlet API; permitir explicitamente desbloqueia probes/health checkers.
        String method = request.getMethod();
        if (!method.equalsIgnoreCase("GET")
            && !method.equalsIgnoreCase("POST")
            && !method.equalsIgnoreCase("HEAD")) {
            response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            response.setHeader("Allow", "GET, POST, HEAD");
            return;
        }

        chain.doFilter(req, res);
    }
}
