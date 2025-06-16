package eu.faircore4eosc.pidmr.services;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import java.util.*;
import java.util.regex.Pattern;

public class ProviderService {
    public final Map<String, List<Pattern>> pidPatterns = new HashMap<>();

    public void loadProviders(JsonArray providers) {
        for (JsonElement provider : providers) {
            String type = provider.getAsJsonObject().get("type").getAsString();
            JsonArray regexes = provider.getAsJsonObject().getAsJsonArray("regexes");
            List<Pattern> patterns = new ArrayList<>();
            for (JsonElement regex : regexes) {
                patterns.add(Pattern.compile(regex.getAsString()));
            }
            pidPatterns.put(type, patterns);
        }
    }

    public String detectPidType(String pid) {
        return pidPatterns.entrySet().stream()
                .filter(entry -> entry.getValue().stream().anyMatch(p -> p.matcher(pid).matches()))
                .map(Map.Entry::getKey)
                .findFirst().orElse(null);
    }
}
