package eu.faircore4eosc.pidmr.services;

import com.google.gson.*;
import org.junit.jupiter.api.Test;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import eu.faircore4eosc.pidmr.services.JsonFetcher;

public class ResourceResolutionServiceTest {

    @Test
    void testHandle_singleRedirect() throws IOException {
        JsonObject provider = new JsonObject();
        provider.addProperty("type", "doi");

        JsonArray pathArray = new JsonArray();
        JsonObject pathEntry = new JsonObject();
        pathEntry.addProperty("provider", "CROSSREF");
        pathEntry.addProperty("path", "message.link.n.URL");
        pathArray.add(pathEntry);
        provider.add("resource_path_in_metadata", pathArray);

        List<JsonObject> providers = List.of(provider);

        JsonObject mockJson = new JsonObject();
        JsonObject message = new JsonObject();
        JsonArray linkArray = new JsonArray();
        JsonObject link = new JsonObject();
        link.addProperty("URL", "https://www.mdpi.com/1424-8220/18/2/479/pdf");
        linkArray.add(link);
        message.add("link", linkArray);
        mockJson.add("message", message);

        JsonFetcher fetcher = url -> mockJson;
        HttpServletResponse resp = mock(HttpServletResponse.class);

        ResourceResolutionService service = new ResourceResolutionService(providers, fetcher);
        String result = service.handle("doi", "CROSSREF", "https://api.crossref.org/works/10.3390/s18020479", resp);

        assertEquals("https://www.mdpi.com/1424-8220/18/2/479/pdf", result);
    }

    @Test
    void testHandle_multipleResults_writesJson() throws IOException {
        JsonObject provider = new JsonObject();
        provider.addProperty("type", "doi");

        JsonArray pathArray = new JsonArray();
        JsonObject pathEntry = new JsonObject();
        pathEntry.addProperty("provider", "CROSSREF");
        pathEntry.addProperty("path", "message.link.n.URL");
        pathArray.add(pathEntry);
        provider.add("resource_path_in_metadata", pathArray);

        List<JsonObject> providers = List.of(provider);

        JsonObject mockJson = new JsonObject();
        JsonObject message = new JsonObject();
        JsonArray linkArray = new JsonArray();
        linkArray.add(createUrlObject("http://link.springer.com/content/pdf/10.1007/BF01034473.pdf"));
        linkArray.add(createUrlObject("http://link.springer.com/article/10.1007/BF01034473/fulltext.html"));
        linkArray.add(createUrlObject("http://link.springer.com/content/pdf/10.1007/BF01034473"));
        message.add("link", linkArray);
        mockJson.add("message", message);

        JsonFetcher fetcher = url -> mockJson;
        HttpServletResponse resp = mock(HttpServletResponse.class);
        when(resp.getWriter()).thenReturn(mock(PrintWriter.class));

        ResourceResolutionService service = new ResourceResolutionService(providers, fetcher);
        String result = service.handle("doi", "CROSSREF", "https://api.crossref.org/works/10.1007/bf01034473", resp);

        assertEquals("multiple", result);
    }

    private JsonObject createUrlObject(String url) {
        JsonObject obj = new JsonObject();
        obj.addProperty("URL", url);
        return obj;
    }
}
