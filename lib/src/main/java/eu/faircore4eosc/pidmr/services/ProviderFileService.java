package eu.faircore4eosc.pidmr.services;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class ProviderFileService {

    private ProviderFileService() {}

    public static JsonObject loadProviderFile(String filePath) throws IOException {
        Path jsonPath = Paths.get(filePath);
        byte[] bytes = Files.readAllBytes(jsonPath);
        String jsonString = new String(bytes, StandardCharsets.UTF_8);
        return JsonParser.parseString(jsonString).getAsJsonObject();
    }
}
