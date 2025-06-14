package eu.faircore4eosc.pidmr.services;

import com.google.gson.JsonObject;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ExternalApiClientTest {

    private MockWebServer mockWebServer;

    @BeforeEach
    void setUp() throws Exception {
        mockWebServer = new MockWebServer();
        mockWebServer.start();
    }

    @AfterEach
    void tearDown() throws Exception {
        mockWebServer.shutdown();
    }

    @Test
    void fetchJson_shouldReturnJsonObject_onHttp200() throws Exception {
        String jsonResponse = "{\"publisher\": \"MDPI AG\", \"page\": 479}";
        mockWebServer.enqueue(new MockResponse()
                .setBody(jsonResponse)
                .addHeader("Content-Type", "application/json"));

        String url = mockWebServer.url("/api/test").toString();
        JsonObject result = ExternalApiClient.fetchJson(url);

        assertNotNull(result);
        assertEquals("MDPI AG", result.get("publisher").getAsString());
        assertEquals(479, result.get("page").getAsInt());
    }

    @Test
    void fetchJson_shouldReturnNull_onHttp404() {
        mockWebServer.enqueue(new MockResponse().setResponseCode(404));
        String url = mockWebServer.url("/api/notfound").toString();

        JsonObject result = ExternalApiClient.fetchJson(url);

        assertNull(result);
    }

    @Test
    void fetchField_shouldApplyExtractor() {
        String jsonResponse = "{\"language\": \"en\"}";
        mockWebServer.enqueue(new MockResponse().setBody(jsonResponse));

        String url = mockWebServer.url("/api/field").toString();
        String msg = ExternalApiClient.fetchField(url, json -> json.get("language").getAsString());

        assertEquals("en", msg);
    }
}