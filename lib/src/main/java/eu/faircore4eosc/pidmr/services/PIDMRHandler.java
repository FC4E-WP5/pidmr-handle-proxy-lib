package eu.faircore4eosc.pidmr.services;

import com.google.gson.*;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;
import java.util.function.Function;

import eu.faircore4eosc.pidmr.utilities.ResponseUtils;

public class PIDMRHandler {

    private final ProviderService providerService;

    public PIDMRHandler(ProviderService providerService) {
        this.providerService = providerService;
    }

    public String handleJsonRedirectList(
            String url,
            HttpServletResponse resp,
            Function<JsonObject, List<String>> extractor
    ) throws IOException {
        JsonObject json = ExternalApiClient.fetchJson(url);
        if (json == null) return null;
        List<String> links = extractor.apply(json);
        if (links == null || links.isEmpty()) return null;
        if (links.size() == 1) {
            return links.get(0);
        }
        ResponseUtils.writeJsonResponse(resp, links);
        return null;
    }
}

