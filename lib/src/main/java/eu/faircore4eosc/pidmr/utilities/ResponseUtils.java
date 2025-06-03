package eu.faircore4eosc.pidmr.utilities;

import com.google.gson.Gson;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.HashMap;

public class ResponseUtils {

    public static void writeJsonResponse(HttpServletResponse resp, Object body) throws IOException {
        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");
        resp.setStatus(HttpServletResponse.SC_OK);
        resp.getWriter().write(new Gson().toJson(body));
    }

    public static void writeJsonError(HttpServletResponse resp, int status, String message) throws IOException {
        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");
        resp.setStatus(status);

        Map<String, Object> error = new HashMap<>();
        error.put("error", message);
        error.put("code", status);

        resp.getWriter().write(new Gson().toJson(error));
    }
}
