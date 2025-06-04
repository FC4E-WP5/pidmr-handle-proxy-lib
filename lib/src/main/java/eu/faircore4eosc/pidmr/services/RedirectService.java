package eu.faircore4eosc.pidmr;

import net.handle.hdllib.AbstractMessage;
import net.handle.apps.servlet_proxy.HDLServletRequest;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import eu.faircore4eosc.pidmr.logging.AccessLogger;
import eu.faircore4eosc.pidmr.logging.InfluxLogger;

public class RedirectService {

    private final ConfigLoader.Config config;

    public RedirectService(ConfigLoader.Config config) {
        this.config = config;
    }

    public void redirect(HttpServletResponse resp, String redirectUrl,
                         String pid, String pidType, String display,
                         HDLServletRequest hdl) throws IOException {

        long startTime = System.currentTimeMillis();

        resp.setStatus(HttpServletResponse.SC_FOUND);
        resp.setHeader("Location", redirectUrl);

        long endTime = System.currentTimeMillis();
        String responseTime = String.valueOf(endTime - startTime);

        InfluxLogger.log(config, pidType, pid, display, redirectUrl, responseTime, HttpServletResponse.SC_FOUND);

        AccessLogger.log(config, pidType, pid, display, HttpServletResponse.SC_FOUND, redirectUrl,
                hdl.req.getRemoteAddr(), AbstractMessage.RC_SUCCESS, hdl.getResponseTime());
    }
}
