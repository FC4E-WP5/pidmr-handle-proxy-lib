package eu.faircore4eosc.pidmr.services;

import com.google.gson.JsonObject;

@FunctionalInterface
public interface JsonFetcher {
    JsonObject fetch(String url);
}
