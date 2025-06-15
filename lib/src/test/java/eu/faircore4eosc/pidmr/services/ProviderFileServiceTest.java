package eu.faircore4eosc.pidmr.services;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class ProviderFileServiceTest {

    @Test
    public void testLoadProviderFile_validJson() throws IOException {
        String filePath = "src/test/resources/provider.json";
        Path jsonPath = Paths.get(filePath);
        String expectedJson = "{\"key\":\"value\"}";
        JsonObject expectedJsonObject = JsonParser.parseString(expectedJson).getAsJsonObject();
        JsonObject actualJsonObject = ProviderFileService.loadProviderFile(filePath);
        assertEquals(expectedJsonObject, actualJsonObject);
    }

    @Test
    public void testLoadProviderFile_invalidJson() {
        String filePath = "src/test/resources/invalid.json";
        Path jsonPath = Paths.get(filePath);
        assertThrows(IOException.class, () -> ProviderFileService.loadProviderFile(filePath));
    }

    @Test
    public void testLoadProviderFile_fileNotFound() {
        String filePath = "src/test/resources/nonExistingFile.json";
        Path jsonPath = Paths.get(filePath);
        assertThrows(IOException.class, () -> ProviderFileService.loadProviderFile(filePath));
    }
}