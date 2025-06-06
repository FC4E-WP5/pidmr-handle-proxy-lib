package eu.faircore4eosc.pidmr.services;

import com.google.gson.*;
import eu.faircore4eosc.pidmr.utilities.MetadataLinkExtractor;
import eu.faircore4eosc.pidmr.utilities.ResponseUtils;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

public class ResourceResolutionService {

    private final List<JsonObject> providers;
    public ResourceResolutionService(List<JsonObject> providers) {
        this.providers = providers;
    }
    public String handle(String pidType, String subProvider, String apiUrl, HttpServletResponse resp) throws IOException {
        List<String> paths = getPathsForSubProvider(pidType, subProvider);
        if (paths.isEmpty()) return null;
        JsonObject json = ExternalApiClient.fetchJson(apiUrl);
        if (json == null) return null;
        List<String> links = new ArrayList<>();
        for (String path : paths) {
            links.addAll(MetadataLinkExtractor.extract(json, path));
        }
        if (links.isEmpty()) return null;
        if (links.size() == 1) return links.get(0);
        ResponseUtils.writeJsonResponse(resp, links);
        return null;
    }

    public boolean canHandle(String pidType, String subProvider) {
        return !getPathsForSubProvider(pidType, subProvider).isEmpty();
    }

    private List<String> getPathsForSubProvider(String pidType, String subProvider) {
        JsonObject providerObj = getProviderByType(pidType);
        if (providerObj == null || !providerObj.has("resource_path_in_metadata")) return Collections.emptyList();
        return getPathsForSubProvider(providerObj, subProvider);
    }

    private List<String> getPathsForSubProvider(JsonObject providerObj, String subProvider) {
        List<String> paths = new ArrayList<>();
        JsonArray array = providerObj.getAsJsonArray("resource_path_in_metadata");
        for (JsonElement el : array) {
            JsonObject obj = el.getAsJsonObject();
            if (!obj.has("provider") || !obj.has("path")) continue;
            String providerName = obj.get("provider").getAsString();
            if (providerName.equalsIgnoreCase(subProvider)) {
                paths.add(obj.get("path").getAsString());
            }
        }
        return paths;
    }

    private JsonObject getProviderByType(String pidType) {
        for (JsonObject provider : providers) {
            String type = provider.get("type").getAsString();
            if (pidType.equalsIgnoreCase(type)) {
                return provider;
            }
        }
        return null;
    }
}
