package eu.faircore4eosc.pidmr.services;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.*;

public class ProviderServiceTest {

    @Test
    public void testLoadProviders() {
        JsonArray providers = new JsonArray();
        JsonObject provider1 = new JsonObject();
        provider1.addProperty("type", "doi");
        JsonArray regexes1 = new JsonArray();
        regexes1.add(new JsonPrimitive("^(https:\\/\\/doi\\.org\\/)?10\\.\\d+\\/(?!zenodo).+$"));
        regexes1.add(new JsonPrimitive("^(https:\\/\\/doi\\.org\\/)?(d|D)(o|O)(i|I):10\\.\\d+\\/(?!zenodo).+$"));
        provider1.add("regexes", regexes1);
        providers.add(provider1);
        JsonObject provider2 = new JsonObject();
        provider2.addProperty("type", "epic");
        JsonArray regexes2 = new JsonArray();
        regexes2.add(new JsonPrimitive("^21\\.T?\\d+(\\/.+)?$"));
        provider2.add("regexes", regexes2);
        providers.add(provider2);
        ProviderService service = new ProviderService();
        service.loadProviders(providers);
        assertEquals(2, service.pidPatterns.size());
        assertEquals(2, service.pidPatterns.get("doi").size());
        assertEquals(1, service.pidPatterns.get("epic").size());
    }

    @Test
    public void testDetectPidType() {
        JsonArray providers = new JsonArray();
        JsonObject provider = new JsonObject();
        provider.addProperty("type", "doi");
        JsonArray regexes = new JsonArray();
        regexes.add(new JsonPrimitive("^(https:\\/\\/doi\\.org\\/)?10\\.\\d+\\/(?!zenodo).+$"));
        provider.add("regexes", regexes);
        providers.add(provider);
        ProviderService service = new ProviderService();
        service.loadProviders(providers);
        assertEquals("doi", service.detectPidType("10.3390/s18020479"));
    }

    @Test
    public void testDetectPidTypeMultipleMatches() {
        JsonArray providers = new JsonArray();
        JsonObject provider1 = new JsonObject();
        provider1.addProperty("type", "doi");
        JsonArray regexes1 = new JsonArray();
        regexes1.add(new JsonPrimitive("^(https:\\/\\/doi\\.org\\/)?10\\.\\d+\\/(?!zenodo).+$"));
        regexes1.add(new JsonPrimitive("^(https:\\/\\/doi\\.org\\/)?(d|D)(o|O)(i|I):10\\.\\d+\\/(?!zenodo).+$"));
        provider1.add("regexes", regexes1);
        providers.add(provider1);
        JsonObject provider2 = new JsonObject();
        provider2.addProperty("type", "epic");
        JsonArray regexes2 = new JsonArray();
        regexes2.add(new JsonPrimitive("^21\\.T?\\d+(\\/.+)?$"));
        provider2.add("regexes", regexes2);
        providers.add(provider2);
        ProviderService service = new ProviderService();
        service.loadProviders(providers);
        assertEquals("doi", service.detectPidType("10.3390/s18020479"));
        assertEquals("doi", service.detectPidType("10.15168/11572_242752"));
        assertEquals("epic", service.detectPidType("21.11101/0000-0007-D649-6"));
    }
}
