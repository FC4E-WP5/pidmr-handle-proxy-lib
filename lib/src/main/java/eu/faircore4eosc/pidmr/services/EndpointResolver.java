package eu.faircore4eosc.pidmr.services;

import com.google.gson.*;

import java.io.FileReader;
import java.io.IOException;

public class EndpointResolver {

    private final JsonArray providers;

    public EndpointResolver(String providersFilePath) throws IOException {
        this.providers = readProvidersFile(providersFilePath);
    }

    private JsonArray readProvidersFile(String path) throws IOException {
        try (FileReader reader = new FileReader(path)) {
            JsonObject root = JsonParser.parseReader(reader).getAsJsonObject();
            return root.getAsJsonArray("content");
        }
    }

    public String resolve(String providerId, String subProviderId, String displayMode) {
        for (JsonElement element : providers) {
            JsonObject provider = element.getAsJsonObject();
            if (!provider.get("type").getAsString().equalsIgnoreCase(providerId)) continue;

            JsonArray resolutionModes = provider.getAsJsonArray("resolution_modes");
            for (JsonElement modeElement : resolutionModes) {
                JsonObject mode = modeElement.getAsJsonObject();
                if (!mode.get("mode").getAsString().equalsIgnoreCase(displayMode)) continue;

                JsonArray endpoints = mode.getAsJsonArray("endpoints");
                for (JsonElement endpointElement : endpoints) {
                    JsonObject endpoint = endpointElement.getAsJsonObject();
                    if (subProviderId == null || endpoint.get("provider").getAsString().equalsIgnoreCase(subProviderId)) {
                        return endpoint.get("link").getAsString();
                    }
                }
            }
        }
        return null;
    }

    public boolean isResolutionModeSupported(String pidType, String mode) {
        for (JsonElement element : providers) {
            JsonObject provider = element.getAsJsonObject();
            if (!provider.get("type").getAsString().equalsIgnoreCase(pidType)) continue;

            JsonArray resolutionModes = provider.getAsJsonArray("resolution_modes");
            for (JsonElement modeElement : resolutionModes) {
                JsonObject resolutionMode = modeElement.getAsJsonObject();
                if (resolutionMode.get("mode").getAsString().equalsIgnoreCase(mode)) {
                    return true;
                }
            }
        }
        return false;
    }
}
