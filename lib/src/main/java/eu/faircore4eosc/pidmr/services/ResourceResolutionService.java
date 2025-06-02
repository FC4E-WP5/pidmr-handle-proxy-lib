package eu.faircore4eosc.pidmr.services;

import com.google.gson.*;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import eu.faircore4eosc.pidmr.services.ExternalApiClient;
import eu.faircore4eosc.pidmr.services.PIDMRHandler;
import eu.faircore4eosc.pidmr.utilities.ResponseUtils;

public class ResourceResolutionService {

    private final PIDMRHandler handler;

    public ResourceResolutionService(PIDMRHandler handler) {
        this.handler = handler;
    }

    public String handle(String pidType, String apiUrl, HttpServletResponse resp) throws IOException {
        return switch (pidType.toLowerCase()) {
            case "crossref" -> handleJsonRedirectList(apiUrl, resp, this::extractCrossrefLinks);
            case "datacite" -> handleJsonRedirectList(apiUrl, resp, this::extractDataciteLink);
            case "10.5281/zenodo" -> handleJsonRedirectList(apiUrl, resp, this::extractZenodoFiles);
            case "urn:nbn:de" -> handleJsonRedirectList(apiUrl, resp, this::extractUrnResults);
            case "urn:nbn:ch" -> handleJsonRedirectList(apiUrl, resp, this::extractUrnResults);
            default -> null;
        };
    }

    private String handleJsonRedirectList(String url, HttpServletResponse resp,
                                          Function<JsonObject, List<String>> extractor) throws IOException {
        JsonObject json = ExternalApiClient.fetchJson(url);
        if (json == null) return null;

        List<String> links = extractor.apply(json);
        if (links == null || links.isEmpty()) return null;

        if (links.size() == 1) {
            return links.get(0); // Redirect
        }

        ResponseUtils.writeJsonResponse(resp, links);
        return null;
    }

    private List<String> extractCrossrefLinks(JsonObject json) {
        List<String> urls = new ArrayList<>();
        JsonArray links = json.getAsJsonObject("message").getAsJsonArray("link");
        for (JsonElement el : links) {
            JsonObject obj = el.getAsJsonObject();
            if (obj.has("URL")) {
                urls.add(obj.get("URL").getAsString());
            }
        }
        return urls;
    }

    private List<String> extractDataciteLink(JsonObject json) {
        List<String> urls = new ArrayList<>();
        JsonObject attr = json.getAsJsonObject("data").getAsJsonObject("attributes");
        if (attr.has("url")) {
            urls.add(attr.get("url").getAsString());
        }
        return urls;
    }

    private List<String> extractZenodoFiles(JsonObject json) {
        List<String> urls = new ArrayList<>();
        JsonArray files = json.getAsJsonArray("files");
        for (JsonElement el : files) {
            JsonObject file = el.getAsJsonObject().getAsJsonObject("links");
            if (file.has("self")) {
                urls.add(file.get("self").getAsString());
            }
        }
        return urls;
    }

    private List<String> extractUrnResults(JsonObject json) {
        List<String> urls = new ArrayList<>();
        JsonArray result = json.getAsJsonArray("urls");
        for (JsonElement el : result) {
            JsonObject entry = el.getAsJsonObject();
            if (entry.has("url")) {
                urls.add(entry.get("url").getAsString());
            }
        }
        return urls;
    }
}
