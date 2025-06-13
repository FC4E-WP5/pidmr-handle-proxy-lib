package eu.faircore4eosc.pidmr.services;

import com.google.gson.*;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class EndpointResolverTest {

    @Test
    void testResolve_findsCorrectEndpoint() {
        JsonObject provider = new JsonObject();
        provider.addProperty("type", "doi");

        JsonArray resolutionModes = new JsonArray();

        JsonObject mode = new JsonObject();
        mode.addProperty("mode", "metadata");
        mode.addProperty("name", "Metadata");

        JsonArray endpoints = new JsonArray();
        JsonObject endpointEntry = new JsonObject();
        endpointEntry.addProperty("link", "https://api.crossref.org/works/%s");
        endpointEntry.addProperty("provider", "CROSSREF");
        endpoints.add(endpointEntry);

        mode.add("endpoints", endpoints);
        resolutionModes.add(mode);
        provider.add("resolution_modes", resolutionModes);

        List<JsonObject> providers = List.of(provider);
        EndpointResolver resolver = new EndpointResolver(providers);

        String resolved = resolver.resolve("doi", "CROSSREF", "metadata");

        assertEquals("https://api.crossref.org/works/%s", resolved);
    }

    @Test
    void testResolve_unknownProvider_returnsNull() {
        JsonObject provider = new JsonObject();
        provider.addProperty("type", "doi");
        provider.add("resolution_modes", new JsonArray());

        List<JsonObject> providers = List.of(provider);
        EndpointResolver resolver = new EndpointResolver(providers);

        String resolved = resolver.resolve("doi", "UNKNOWN", "metadata");
        assertNull(resolved);
    }

    @Test
    void testResolve_unknownPidType_returnsNull() {
        List<JsonObject> providers = List.of();
        EndpointResolver resolver = new EndpointResolver(providers);

        String resolved = resolver.resolve("unknown", "ANY", "metadata");
        assertNull(resolved);
    }
}
