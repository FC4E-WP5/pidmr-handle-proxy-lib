package eu.faircore4eosc.pidmr.utilities;

import com.google.gson.*;

import java.util.*;

public class MetadataLinkExtractor {

    public static List<String> extract(JsonObject json, String path) {
        if (json == null || path == null) return Collections.emptyList();
        String[] tokens = path.split("\\.");
        JsonElement current = json;
        for (int i = 0; i < tokens.length; i++) {
            String token = tokens[i];
            if (token.equals("n")) {
                if (!current.isJsonArray()) return Collections.emptyList();
                JsonArray array = current.getAsJsonArray();
                String[] remainingPath = Arrays.copyOfRange(tokens, i + 1, tokens.length);
                List<String> results = new ArrayList<>();
                for (JsonElement el : array) {
                    if (!el.isJsonObject()) continue;
                    JsonObject obj = el.getAsJsonObject();
                    JsonElement value = navigate(obj, remainingPath);
                    if (value != null && value.isJsonPrimitive()) {
                        results.add(value.getAsString());
                    }
                }
                return results;
            }
            if (!current.isJsonObject()) return Collections.emptyList();
            JsonObject obj = current.getAsJsonObject();
            if (!obj.has(token)) return Collections.emptyList();
            current = obj.get(token);
        }
        if (current.isJsonPrimitive()) {
            return List.of(current.getAsString());
        }
        return Collections.emptyList();
    }

    private static JsonElement navigate(JsonObject json, String[] path) {
        JsonElement current = json;
        for (String token : path) {
            if (!current.isJsonObject()) return null;
            JsonObject obj = current.getAsJsonObject();
            if (!obj.has(token)) return null;
            current = obj.get(token);
        }
        return current;
    }
}
