package eu.faircore4eosc.pidmr.services;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;

public class ExternalApiClient {
    public static JsonObject fetchJson(String url) {
        try {
            URI uri = URI.create(url);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("GET");
            if (conn.getResponseCode() == 200) {
                BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                StringBuilder content = new StringBuilder();
                String line;
                while ((line = in.readLine()) != null) content.append(line);
                in.close();
                return JsonParser.parseString(content.toString()).getAsJsonObject();
            }
        } catch (Exception e) {
            System.err.println("Error fetching JSON: " + e.getMessage());
        }
        return null;
    }

    public static String fetchField(String url, java.util.function.Function<JsonObject, String> extractor) {
        JsonObject json = fetchJson(url);
        return json != null ? extractor.apply(json) : null;
    }
}
