package eu.faircore4eosc.pidmr.utilities;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import eu.faircore4eosc.pidmr.utilities.ResponseUtils;

public class ErrorHandler {

    public static void badRequest(HttpServletResponse resp, String message) throws IOException {
        writeJson(resp, HttpServletResponse.SC_BAD_REQUEST, message);
    }

    public static void notFound(HttpServletResponse resp, String message) throws IOException {
        writeJson(resp, HttpServletResponse.SC_NOT_FOUND, message);
    }

    public static void unauthorized(HttpServletResponse resp, String message) throws IOException {
        writeJson(resp, HttpServletResponse.SC_UNAUTHORIZED, message);
    }

    public static void serverError(HttpServletResponse resp, String message) throws IOException {
        writeJson(resp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, message);
    }

    public static void forbidden(HttpServletResponse resp, String message) throws IOException {
        writeJson(resp, HttpServletResponse.SC_FORBIDDEN, message);
    }

    private static void writeJson(HttpServletResponse resp, int status, String message) throws IOException {
        ResponseUtils.writeJsonError(resp, status, message);
    }
}
