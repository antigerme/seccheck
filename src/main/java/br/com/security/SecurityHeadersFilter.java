package br.com.security;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SecurityHeadersFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {}

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

        // [SEC] Controle de politica de recursos do browser (CSP)
        // Como servimos HTML estatico e o relatorio gerado, limitamos ao minimo necessario.
        response.setHeader("Content-Security-Policy",
            "default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; " +
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
            "script-src 'self'; " +
            "img-src 'self' data:; " +
            "connect-src 'self'; " +
            "font-src https://fonts.gstatic.com; " +
            "frame-ancestors 'none'");

        // [SEC] Controla como o Referer e enviado ao navegar
        response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

        // [SEC] Rejeita metodos HTTP nao utilizados pela aplicacao
        String method = request.getMethod();
        if (!method.equalsIgnoreCase("GET") && !method.equalsIgnoreCase("POST")) {
            response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            response.setHeader("Allow", "GET, POST");
            return;
        }

        chain.doFilter(req, res);
    }

    @Override
    public void destroy() {}
}
