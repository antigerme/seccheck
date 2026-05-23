package br.com.security;

import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.UUID;

/**
 * Cancela uma varredura em andamento ou na fila.
 * Aceitamos POST (semantica de mutacao) com o id no parametro de query ou
 * form, para evitar ler corpo JSON sem necessidade.
 */
@WebServlet(name = "CancelServlet", urlPatterns = {"/api/cancel"})
public class CancelServlet extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String id = request.getParameter("id");
        if (id == null || id.isBlank()) {
            JsonResponse.writeError(response, HttpServletResponse.SC_BAD_REQUEST, "Parametro 'id' ausente.");
            return;
        }
        try {
            UUID.fromString(id);
        } catch (IllegalArgumentException e) {
            JsonResponse.writeError(response, HttpServletResponse.SC_BAD_REQUEST, "Scan ID malformado.");
            return;
        }

        boolean found = ScanManager.cancel(id);
        if (!found) {
            JsonResponse.writeError(response, HttpServletResponse.SC_NOT_FOUND, "Scan ID nao encontrado.");
            return;
        }

        LogUtils.info("Scan " + id + " cancelado por requisicao do cliente.");
        ObjectNode body = JsonResponse.node();
        body.put("scanId", id);
        body.put("cancelled", true);
        JsonResponse.write(response, HttpServletResponse.SC_OK, body);
    }
}
