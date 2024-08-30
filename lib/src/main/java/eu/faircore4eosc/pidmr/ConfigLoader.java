package eu.faircore4eosc.pidmr;

import com.google.gson.Gson;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.util.Map;

public class ConfigLoader {
    private final String configFile;

    public ConfigLoader(String configFile) {
        this.configFile = configFile;
    }

    public Config loadConfig() throws IOException {
        InputStream inputStream = getClass().getClassLoader().getResourceAsStream(this.configFile);
        if (inputStream == null) {
            throw new IOException("Config file not found");
        }
        try (InputStreamReader inputStreamReader = new InputStreamReader(inputStream);
            BufferedReader reader = new BufferedReader(inputStreamReader)) {
            Gson gson = new Gson();
            return gson.fromJson(reader, Config.class);
        }
    }

    public static class Config {
        private String hdlServerConfigPath;
        private String influxdbConfigFile;
        private String providersFilePath;
        private String providersBackupFilePath;
        private Map<String, String> endpoints;
        private Map<String, String> mimTypes;
        private Map<String, String> resolvingModes;

        public String getHdlServerConfigPath() {
            return hdlServerConfigPath;
        }

        public String getInfluxdbConfigFile() {
            return influxdbConfigFile;
        }

        public String getProvidersFilePath() {
            return providersFilePath;
        }

        public String getProvidersBackupFilePath() {
            return providersBackupFilePath;
        }

        public Map<String, String> getEndpoints() {
            return endpoints;
        }

        public Map<String, String> getMimTypes() {
            return mimTypes;
        }

        public Map<String, String> getResolvingModes() {
            return resolvingModes;
        }
    }
}
