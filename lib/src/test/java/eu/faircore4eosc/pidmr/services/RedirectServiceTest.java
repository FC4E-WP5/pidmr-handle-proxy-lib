package eu.faircore4eosc.pidmr.services;

import eu.faircore4eosc.pidmr.ConfigLoader;
import eu.faircore4eosc.pidmr.logging.AccessLogger;
import eu.faircore4eosc.pidmr.logging.InfluxLogger;
import eu.faircore4eosc.pidmr.services.RedirectService;

import net.handle.apps.servlet_proxy.HDLServletRequest;
import net.handle.hdllib.AbstractMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

public class RedirectServiceTest {
    private HttpServletResponse resp;
    private HDLServletRequest hdl;

    private RedirectService redirectService;
    private ConfigLoader.Config config;

    @BeforeEach
    void setup() {
        resp = mock(HttpServletResponse.class);

        hdl = mock(HDLServletRequest.class);
        hdl.req = mock(HttpServletRequest.class);
        when(hdl.req.getRemoteAddr()).thenReturn("127.0.0.1");
        when(hdl.getResponseTime()).thenReturn(50L);

        config = mock(ConfigLoader.Config.class);
        redirectService = new RedirectService(config);
    }

    @Test
    void testRedirectSetsStatusAndLocationAndLogs() throws Exception {
        String redirectUrl = "https://api.crossref.org/works/10.3390/s18020479";
        String pid = "10.3390/s18020479";
        String pidType = "doi";
        String display = "metadata";

        try (
                MockedStatic<InfluxLogger> influxLogger = mockStatic(InfluxLogger.class);
                MockedStatic<AccessLogger> accessLogger = mockStatic(AccessLogger.class)
        ) {
            redirectService.redirect(resp, redirectUrl, pid, pidType, display, hdl);

            // HTTP redirect status and header
            verify(resp).setStatus(HttpServletResponse.SC_FOUND);
            verify(resp).setHeader("Location", redirectUrl);

            // InfluxLogger is called
            influxLogger.verify(() -> InfluxLogger.log(
                    eq(config),
                    eq(pidType),
                    eq(pid),
                    eq(display),
                    eq(redirectUrl),
                    anyString(),
                    eq(HttpServletResponse.SC_FOUND)
            ));

            // AccessLogger is called
            accessLogger.verify(() -> AccessLogger.log(
                    eq(config),
                    eq(pidType),
                    eq(pid),
                    eq(display),
                    eq(HttpServletResponse.SC_FOUND),
                    eq(redirectUrl),
                    eq("127.0.0.1"),
                    eq(AbstractMessage.RC_SUCCESS),
                    eq(50L)
            ));
        }
    }
}
