package eu.faircore4eosc.pidmr;

import java.io.*;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.MissingFormatArgumentException;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.influxdb.InfluxDB;
import org.influxdb.InfluxDBFactory;
import org.influxdb.dto.Point;
import org.influxdb.dto.Query;
import org.json.JSONArray;
import org.json.JSONObject;
import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;

import eu.faircore4eosc.pidmr.ConfigLoader;
import eu.faircore4eosc.pidmr.services.ProviderService;

import net.cnri.util.StreamTable;
import net.handle.apps.servlet_proxy.HDLProxy;
import net.handle.apps.servlet_proxy.HDLServletRequest;
import net.handle.apps.servlet_proxy.HDLServletRequest.ResponseType;
import net.handle.apps.servlet_proxy.RotatingAccessLog;
import net.handle.hdllib.*;
import net.handle.server.Main;
import net.handle.server.servletcontainer.HandleServerInterface;


public class PIDMRHDLProxy extends HDLProxy {
    public static RequestProcessor resolver = null;

    private String display = null;
    private String pid = null;
    private final String RESOLVING_MODE_LANDINGPAGE = "landingpage";
    private final String RESOLVING_MODE_METADATA = "metadata";
    private final String RESOLVING_MODE_RESOURCE = "resource";

    private final String RESOLVING_MODE_CN = "cn";
    private final String CN_BIBTEX = "bibtex";
    private final String CN_TURTLE = "turtle";
    private final String CN_RDF = "rdf";
    private final String CN_CITATION = "citation";
    private String pidType = null;
    private String recognizedPid = null;
    private boolean supportedMode = false;
    private final Integer TIME_OUT = 10000;

    protected HandleServerInterface handleServer;
    List<Integer> redirectHttpCodes = Arrays.asList(300, 301, 302, 303, 304, 305, 306, 307, 308);

    private ConfigLoader.Config config;

    private static final String DOI_PREFIX = "doi:";
    private static final String CROSSREF = "crossref";
    private static final String DATACITE = "datacite";
    private static final String JALC = "jalc";

    // Precompile the common regex pattern for efficiency
    private static final Pattern CANONICAL_FORMAT_PATTERN = Pattern.compile("https:\\/\\/[^\\/]+\\/(?:doi:)?(.+)", Pattern.CASE_INSENSITIVE);

    // Thread-local storage for per-request response
    private static final ThreadLocal<HttpServletResponse> responseHolder = new ThreadLocal<>();

    private ProviderService providerService;

    @Override
    public void init() throws ServletException {
        super.init();
        try {
            ConfigLoader configLoader = new ConfigLoader("config.json");
            config = configLoader.loadConfig();
            String providersFilePath = config.getProvidersFilePath();
            String content = new String(
                    Files.readAllBytes(Paths.get(providersFilePath)),
                    StandardCharsets.UTF_8
            );
            JsonObject json = JsonParser.parseString(content).getAsJsonObject();
            JsonArray providersArray = json.getAsJsonArray("content");
            this.providerService = new ProviderService();
            this.providerService.loadProviders(providersArray);
        } catch (IOException e) {
            super.logError(RotatingAccessLog.ERRLOG_LEVEL_NORMAL, "Failed to load configuration: " + e.getMessage());
            throw new ServletException("Failed to load configuration", e);
        }
    }

    @Override
    public void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException {
        responseHolder.set(resp);
        try {
            HDLServletRequest hdl = new HDLServletRequest(this, req, resp, resolver);
            String pidType = providerService.detectPidType(hdl.hdl);
            if (pidType == null) {
                errorHandling(resp, HttpServletResponse.SC_BAD_REQUEST, "PID type can not be determind.");
                return;
            }
            if (!checkForSupportedResolutionMode(resp, hdl.params.getParameter("display"), pidType) && !pidType.equalsIgnoreCase("doi")) {
                handleHttpError(400, resp, "Resolution mode is not supported.");
                return;
            }
            defaultPidTypeHandling(hdl, resp, pidType);
        } finally {
            responseHolder.remove();
        }
    }

    private void defaultPidTypeHandling(HDLServletRequest hdl, HttpServletResponse resp, String pidType) throws IOException, ServletException {
        String display = hdl.params.getParameter("display");
        if (display == null || display.trim().isEmpty()) {
            display = sanitizeInput(config.getResolvingModes().get("RESOLVING_MODE_LANDINGPAGE"));
        }
        String pid = sanitizeInput(hdl.hdl);
        try {
            dispatchPidHandlingMode(pid, display, hdl, pidType, resp);
        } catch (HandleException e) {
            super.logError(RotatingAccessLog.ERRLOG_LEVEL_NORMAL, "Error dispatching PID handling mode: " + e.getMessage());
            errorHandling(resp, HttpServletResponse.SC_BAD_REQUEST, "Error dispatching PID handling mode.");
        }
    }

    @Override
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException {
        responseHolder.set(resp);
        try {
            HDLServletRequest hdl = new HDLServletRequest(this, req, resp, resolver);
            if (hdl.hdl.equals("syncProviders")) {
                fetchProvidersFileForUIList(resp);
                return;
            }
            if (req.getQueryString() != null) {
                if (req.getQueryString().contains("&")) {
                    pid = req.getQueryString().split("&")[0];
                    display = req.getQueryString().split("&")[1];
                } else {
                    pid = req.getQueryString();
                }
                if (display == null) {
                    display = config.getResolvingModes().get("RESOLVING_MODE_LANDINGPAGE");
                }
                if (pid != null) {
                    String pidType = providerService.detectPidType(pid);
                    if (!checkForSupportedResolutionMode(resp, display, pidType) && !pidType.equalsIgnoreCase("doi")) {
                        handleHttpError(400, resp, "Resolution mode is not supported.");
                        return;
                    }
                    if (pidType != null) {
                        try {
                            dispatchPidHandlingMode(pid, display, hdl, pidType, resp);
                        } catch (HandleException e) {
                            handleHttpError(500, resp, "Error handling PID: " + e.getMessage());
                        }
                        return;
                    } else {
                        errorHandling(resp, HttpServletResponse.SC_BAD_REQUEST, "PID type can not be determind.");
                        return;
                    }
                }
            }
            if (handleSpecial(req, resp)) return;
            super.doGet(req, resp);
        } finally {
            responseHolder.remove();
        }
    }

    private String resolveEndpoint(String providerId, String subProviderId, String displayMode) throws IOException {
        HttpServletResponse resp = responseHolder.get();
        try {
            JsonArray providers = getProviders();
            for (int i = 0; i < providers.size(); i++) {
                JsonObject provider = providers.get(i).getAsJsonObject();
                if (providerId.equalsIgnoreCase(provider.get("type").getAsString())) {
                    if (!provider.has("resolution_modes")) {
                        handleHttpError(404, resp, String.format(
                                "Provider '%s' does not define any 'resolution_modes'.",
                                providerId
                        ));
                        return null;
                    }
                    JsonArray resolutionModes = provider.getAsJsonArray("resolution_modes");
                    for (int j = 0; j < resolutionModes.size(); j++) {
                        JsonObject mode = resolutionModes.get(j).getAsJsonObject();
                        if (displayMode.equalsIgnoreCase(mode.get("mode").getAsString())) {
                            JsonArray endpoints = mode.getAsJsonArray("endpoints");
                            for (int k = 0; k < endpoints.size(); k++) {
                                JsonObject endpoint = endpoints.get(k).getAsJsonObject();
                                if (subProviderId.equalsIgnoreCase(endpoint.get("provider").getAsString())) {
                                    return endpoint.get("link").getAsString();
                                }
                            }
                            handleHttpError(404, resp, String.format(
                                    "No endpoint found for sub-provider '%s' " +
                                            "in display mode '%s' for provider '%s'.",
                                    subProviderId, displayMode, providerId
                            ));
                            return null;
                        }
                    }
                    handleHttpError(404, resp, String.format(
                            "Display mode '%s' not found for provider '%s'.",
                            displayMode, providerId
                    ));
                    return null;
                }
            }
            handleHttpError(404, resp, String.format(
                    "Provider '%s' not found in providers.json.",
                    providerId
            ));
            return null;
        } catch (Exception e) {
            handleHttpError(500, resp, "Internal server error while resolving endpoint.");
            return null;
        }
    }

    private void fetchProvidersFileForUIList(HttpServletResponse resp) throws IOException {
        String providersFilePath = config.getProvidersFilePath();
        Path jsonPath = Paths.get(providersFilePath);
        byte[] bytes = Files.readAllBytes(jsonPath);
        String jsonString = new String(bytes, StandardCharsets.UTF_8);
        JsonObject json = JsonParser.parseString(jsonString).getAsJsonObject();
        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");
        resp.getWriter().write(json.toString());
    }

    public String sanitizeInput(String input) {
        if (input == null) {
            return null;
        }
        PolicyFactory policy = Sanitizers.FORMATTING.and(Sanitizers.LINKS);
        return policy.sanitize(input);
    }

    private boolean checkForSupportedResolutionMode(HttpServletResponse resp, String display, String pidType) {
        supportedMode = false;
        JsonArray providers = getProviders();
        providers.forEach(provider -> {
            JsonArray resolutionModes = getProviderElementGivenTheType("resolution_modes", provider);
            String tempPidType = getProviderType(provider);
            if (tempPidType.equals(pidType)) {
                resolutionModes.forEach(resolutionMode -> {
                    String tempResolutionMode = resolutionMode.getAsJsonObject().get("mode").getAsString();
                    if (tempResolutionMode.equals(display)) {
                        supportedMode = true;
                    }
                });
            }
        });
        return supportedMode;
    }

    private void dispatchPidHandlingMode(String pid, String display, HDLServletRequest hdl, String pidType, HttpServletResponse resp) throws IOException, ServletException, HandleException {
        String subProvider = pidType;
        if (config.handleProviderHavingSubproviders().containsKey(pidType)) {
            String methodName = config.handleProviderHavingSubproviders().get(pidType);
            if (methodName != null) {
                try {
                    Method method = this.getClass().getMethod(methodName, String.class);
                    subProvider = (String) method.invoke(this, pid);
                } catch (Exception e) {
                    handleHttpError(500, resp, "Error invoking sub-provider method: " + methodName + " - " + e.getMessage());
                }
            }
        }
        String endpoint = resolveEndpoint(pidType, subProvider, display);
        handleRedirect(subProvider, pid, display, hdl, resp, endpoint);
    }

    private void errorHandling(HttpServletResponse resp, int errorCode, String errorMessage) throws IOException {
        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");
        resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("errorCode", errorCode);
        errorResponse.put("error", errorMessage);
        ObjectMapper objectMapper = new ObjectMapper();
        String jsonResponse = objectMapper.writeValueAsString(errorResponse);
        resp.getWriter().write(jsonResponse);
    }

    private JsonArray getProviders() {
        File providersFile = new File(config.getProvidersFilePath());
        File providersBackupFile = new File(config.getProvidersBackupFilePath());
        String providersFilePath;
        if (providersFile.exists() || providersBackupFile.exists()) {
            if (providersFile.exists()) {
                providersFilePath = config.getProvidersFilePath();
            } else {
                providersFilePath = config.getProvidersBackupFilePath();
            }
            try {
                JsonObject providersFileContent = readProvidersFile(providersFilePath);
                if (providersFileContent != null) {
                    JsonArray providers = (JsonArray) providersFileContent.get("content");
                    return providers;
                }
            } catch (Exception e) {
                super.logError(RotatingAccessLog.ERRLOG_LEVEL_FATAL, "Providers list could not be fetched: " + e.getMessage());
            }
        }
        return null;
    }

    private JsonArray getProviderElementGivenTheType(String providerElement, JsonElement provider) {
        JsonArray providerElementArray = provider.getAsJsonObject().get(providerElement).getAsJsonArray();
        return providerElementArray;
    }

    private String getProviderType(JsonElement provider) {
        String pidType = provider.getAsJsonObject().get("type").getAsString();
        return pidType;
    }

    private JsonObject readProvidersFile(String providersFilePath) throws IOException {
        Path path = Paths.get(providersFilePath);
        if (!Files.exists(path) || !Files.isRegularFile(path)) {
            throw new FileNotFoundException("Provider file not found or not a regular file: " + providersFilePath);
        }
        try (FileReader reader = new FileReader(providersFilePath)) {
            return JsonParser.parseReader(reader).getAsJsonObject();
        }
    }

    public boolean isPidMatchingPattern(String pid, String regex) {
        return matchPidToRegexPattern(pid, regex).find();
    }

    private static Matcher matchPidToRegexPattern(String pid, String regex) {
        Pattern pattern = Pattern.compile(regex.trim(), Pattern.CASE_INSENSITIVE);
        return pattern.matcher(pid.trim());
    }

    public String handleUrnDeChResourceMode(String urnMetadataURL) throws IOException {
        HttpServletResponse resp = responseHolder.get();
        String redirectUrl = null;
        try {
            URL apiUrl = new URL(urnMetadataURL);
            HttpURLConnection connection = (HttpURLConnection) apiUrl.openConnection();
            connection.setRequestMethod("GET");
            int responseCode = connection.getResponseCode();
            if (responseCode == 200) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                String inputLine;
                StringBuilder content = new StringBuilder();
                while ((inputLine = reader.readLine()) != null) {
                    content.append(inputLine);
                }
                reader.close();
                connection.disconnect();
                String jsonContent = content.toString();
                JsonObject jsonObject = JsonParser.parseString(jsonContent).getAsJsonObject();
                JsonArray urlsArray = jsonObject.getAsJsonArray("urls");
                redirectUrl = urnnbn(urlsArray);
            } else {
                handleHttpError(responseCode, resp, "Failed to fetch URN metadata, HTTP code: " + responseCode);
            }
        } catch (Exception e) {
            super.logError(RotatingAccessLog.ERRLOG_LEVEL_NORMAL, "Error fetching urn:nbn:de/ch resource url: " + e.getMessage());
            handleHttpError(500, resp, "Error fetching urn:nbn:de/ch resource url: " + e.getMessage());
        }
        return redirectUrl;
    }

    private void redirect(String pidType, String pid, String display, String redirectUrl, HDLServletRequest hdl, HttpServletResponse resp) throws IOException {
        String addr = "";
        try {
            addr = hdl.getRemoteAddr();
        } catch (Throwable t) {
        }
        try {
            URL apiUrl = new URL(redirectUrl);
            HttpURLConnection connection = (HttpURLConnection) apiUrl.openConnection();
            connection.setConnectTimeout(TIME_OUT);
            connection.setReadTimeout(TIME_OUT);
            int responseCode = connection.getResponseCode();
            if (responseCode == 200) {
                hdl.sendHTTPRedirect(ResponseType.MOVED_PERMANENTLY, redirectUrl);
            } else if (redirectHttpCodes.contains(responseCode)) {
                String newUrl = connection.getHeaderField("Location");
                URL url = new URL(newUrl);
                connection = (HttpURLConnection) url.openConnection();
                responseCode = connection.getResponseCode();
                hdl.sendHTTPRedirect(ResponseType.MOVED_PERMANENTLY, newUrl);
            } else {
                handleHttpError(responseCode, resp, connection.getResponseMessage());
            }
            logPIDMRAccess(pidType, pid, display, responseCode, addr, AbstractMessage.RC_SUCCESS, hdl.getResponseTime());
            logIntoInfluxDB(pidType, pid, display, redirectUrl, hdl.getResponseTime() + "ms", responseCode);
        } catch (IOException e) {
            handleHttpError(500, resp, e.getMessage());
            logPIDMRAccess(pidType, pid, display, 500, addr, AbstractMessage.RC_ERROR, hdl.getResponseTime());
            logIntoInfluxDB(pidType, pid, display, redirectUrl,hdl.getResponseTime() + "ms", 500);
        }
    }

    public void logIntoInfluxDB(String pidType, String pid, String display, String redirectUrl, String responseTime, Integer status) {
        String influxdbConfigFile = config.getInfluxdbConfigFile();
        StreamTable configTable = new StreamTable();
        File serverDir = new File(HSG.DEFAULT_CONFIG_SUBDIR_NAME);
        try {
            File configFile = new File(serverDir, influxdbConfigFile);
            if (configFile.exists()) {
                try {
                    configTable.readFromFile(configFile);
                    if (configTable.containsKey("influxdb_config")) {
                        Map<String, Object> influxdbConfig = (Map<String, Object>) configTable.get("influxdb_config");
                        String bindAddress = (String) influxdbConfig.get("bind_address");
                        String bindPort = (String) influxdbConfig.get("bind_port");
                        String username = (String) influxdbConfig.get("username");
                        String password = (String) influxdbConfig.get("password");
                        String databaseName = (String) influxdbConfig.get("databaseName");
                        String measurement = (String) influxdbConfig.get("measurement");
                        String num_threads = (String) influxdbConfig.get("num_threads");
                        int numThreads = Integer.parseInt(num_threads);
                        String url = bindAddress + ":" + bindPort;
                        InfluxDB influxDB = InfluxDBFactory.connect(url, username, password);
                        influxDB.setDatabase(databaseName);
                        try {
                            influxDB.enableBatch(10, 200, TimeUnit.MILLISECONDS);
                            Point point = Point.measurement(measurement)
                                    .addField("time_stamp", getLogDateTime())
                                    .addField("pid_endpoint", redirectUrl)
                                    .addField("pid_type", pidType)
                                    .addField("pid_id", pid)
                                    .addField("pid_mode", display)
                                    .addField("pid_resolver_status", status)
                                    .addField("responseTime", responseTime)
                                    .build();
                            try {
                                ExecutorService executor = Executors.newFixedThreadPool(numThreads);
                            } catch (NumberFormatException e) {
                                System.err.println("Invalid number format for num_threads: " + num_threads);
                            }
                            ExecutorService executor = Executors.newFixedThreadPool(numThreads);
                            CompletableFuture.runAsync(() -> {
                                try {
                                    influxDB.write(point);
                                } catch (Exception e) {
                                    System.err.println("Write failed: " + e.getMessage());
                                }
                            }, executor).thenRun(() -> {
                            });
                            executor.shutdown();
                        } catch (Exception e) {
                            super.logError(RotatingAccessLog.ERRLOG_LEVEL_NORMAL, "Error transmiting the data to influxdb: " + e.getMessage());
                        } finally {
                            influxDB.close();
                        }
                    }
                } catch (Exception e) {
                    System.err.println("Error reading configuration: " + e);
                }
            }
        } catch (Exception e) {
            e.printStackTrace(System.err);
            System.err.println("Error loading configuration: " + e);
        }
    }

    private String getLogDateTime() {
        LocalDateTime localDateTime = LocalDateTime.now();
        DateTimeFormatter dateTimeFormat = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        String formattedDateTime = localDateTime.format(dateTimeFormat);
        return formattedDateTime;
    }
    
    private void handleHttpError(int responseCode, HttpServletResponse resp, String errmsg) throws IOException {
        errorHandling(resp,responseCode, errmsg);
    }

    private void logPIDMRAccess(String pidType, String pid, String display, int status, String addr, int hdlResponseCode,long responseTime) throws IOException {
        HttpServletResponse resp = responseHolder.get();
        Main main = null;
        String hdlServerConfigPath = config.getHdlServerConfigPath();
        StreamTable configTable = new StreamTable();
        File serverDir = new File(hdlServerConfigPath);
        try {
            configTable.readFromFile(new File(serverDir, HSG.CONFIG_FILE_NAME));
        } catch (Exception e) {
            handleHttpError(500, resp, "Error reading configuration: " + e);
            return;
        }
        try {
            main = new Main(serverDir, configTable);
            main.logAccess("HTTP:PIDMRHDLProxy", InetAddress.getByName(addr), AbstractMessage.OC_RESOLUTION, hdlResponseCode, pidType + ";" + pid + ";" + display + ";" + status, responseTime);
        } catch (Exception e) {
            handleHttpError(500, resp, "Error logging PIDMR access: " + e.getMessage());
        }
    }

    private void sendError(int statusCode, HttpServletResponse resp, String message) throws IOException {
        handleHttpError(statusCode, resp, message);
    }

    private String handleCnMode(String pid, String cnType) throws IOException {
        HttpServletResponse resp = responseHolder.get();
        String mimType = getMimType(cnType);
        String crossrefUrl = "https://api.crossref.org/works/" + pid + "/transform/" + mimType;
        try {
            URL apiUrl = new URL(crossrefUrl);
            HttpURLConnection connection = (HttpURLConnection) apiUrl.openConnection();
            connection.setRequestMethod("GET");
            int responseCode = connection.getResponseCode();
            if (responseCode == 200) {
                return crossrefUrl;
            } else {
                return "https://data.crosscite.org/" + mimType + pid;
            }
        } catch (Exception e) {
            handleHttpError(500, resp, "Internal server error while resolving CN mode for PID: " + pid);
            return null;
        }
    }

    public String urnnbn(JsonArray resources) throws IOException {
        int size = resources.size();
        if (size == 1) {
            JsonElement url = resources.get(0).getAsJsonObject().get("URL");
            String redirectUrl = url.toString().replace("\"", "");
            return redirectUrl;
        } else {
            JsonArray urlJsonArray = new JsonArray();
            for (JsonElement link : resources) {
                JsonObject linkObject = link.getAsJsonObject();
                String url = linkObject.get("url").getAsString();
                urlJsonArray.add(url);
            }
            sendJsonResponse(urlJsonArray.toString());
            return null;
        }
    }

    public String handleResourceRedirect(JsonArray resources) throws IOException {
        if (resources.size() == 0) return null;
        JsonObject firstObj = resources.get(0).getAsJsonObject();
        String fieldName = firstObj.has("url") ? "url" : "URL";
        if (resources.size() == 1) {
            return firstObj.get(fieldName).getAsString();
        } else {
            JsonArray urlJsonArray = new JsonArray();
            for (JsonElement element : resources) {
                JsonObject obj = element.getAsJsonObject();
                String url = obj.get(fieldName).getAsString();
                urlJsonArray.add(url);
            }
            sendJsonResponse(urlJsonArray.toString());
            return null;
        }
    }

    public static String checkForCanonicalFormat(String pid) {
        return extractCanonicalPid(pid).orElse(pid);
    }

    public static Optional<String> extractCanonicalPid(String pid) {
        Matcher matcher = CANONICAL_FORMAT_PATTERN.matcher(pid.trim());
        if (matcher.find()) {
            return Optional.of(matcher.group(1));
        }
        return Optional.empty();
    }

    private void noDoiProvider(HttpServletResponse resp) throws IOException {
        errorHandling(resp, HttpServletResponse.SC_BAD_REQUEST, "DOI provider can not be determind.");
    }

    public String getDoiProvider(String pid) {
        String doiProvider = null;
        if (pid.contains("/")) {
            String doiProviderId = pid.split("/")[0];
            HandleValue[] vals;
            try {
                vals = resolveHandle(doiProviderId);
            } catch (HandleException e) {
                return doiProvider;
            }
            String dataStr;
            for (HandleValue val : vals) {
                String typeAsStr = val.getTypeAsString();
                if (typeAsStr.equals("HS_SERV")) {
                    dataStr = val.getDataAsString();
                    if (dataStr != null && dataStr.contains("/")) {
                        doiProvider = dataStr.toLowerCase().split("/")[1];
                        break;
                    }
                }
            }
        }
        return doiProvider;
    }

    private String getMimType(String cnType) {
        String mimType = null;
        switch (cnType) {
            case CN_BIBTEX:
                mimType = config.getMimTypes().get("CN_BIBTEX_MIMTYPE");
                break;
            case CN_TURTLE:
                mimType = config.getMimTypes().get("CN_TURTLE_MIMTYPE");
                break;
            case CN_RDF:
                mimType = config.getMimTypes().get("CN_RDF_MIMTYPE");
                break;
            case CN_CITATION:
                mimType = config.getMimTypes().get("CN_CITATION_MIMTYPE");
                break;
            default:
                break;
        }
        return mimType;
    }

    public String handleDataciteResourceMode(String url) throws IOException {
        HttpServletResponse resp = responseHolder.get();
        try {
            String jsonContent = fetchContent(url);
            if (jsonContent != null) {
                JsonObject jsonObject = JsonParser.parseString(jsonContent).getAsJsonObject();
                String redirectUrl = jsonObject.getAsJsonObject("data").getAsJsonObject("attributes").get("url").toString();
                if (redirectUrl != null) {
                    redirectUrl = redirectUrl.toString().replace("\"", "");
                    return redirectUrl;
                }
            }
        } catch (Exception e) {
            handleHttpError(500, resp, "Internal server error while resolving DataCite resource URL: " + url);
        }
        return null;
    }

    public JsonArray getCrossrefResourceEndpoint(String url) {
        try {
            String jsonContent = fetchContent(url);
            if (jsonContent != null) {
                JsonObject jsonObject = JsonParser.parseString(jsonContent).getAsJsonObject();
                JsonObject messageObject = jsonObject.getAsJsonObject("message");
                if (messageObject.has("link") && messageObject.get("link").isJsonArray()) {
                    return messageObject.getAsJsonArray("link");
                } else {
                    super.logError(RotatingAccessLog.ERRLOG_LEVEL_NORMAL, "No resource link for crossref doi found.");
                }
            }
        } catch (Exception e) {
            super.logError(RotatingAccessLog.ERRLOG_LEVEL_FATAL, "Crossref resource link could not be fetched.");
        }
        return null;
    }

    public String handleCrossrefResourceMode(String url) throws IOException {
        HttpServletResponse resp = responseHolder.get();
        String redirectUrl = null;
        try {
            URL apiUrl = new URL(url);
            HttpURLConnection connection = (HttpURLConnection) apiUrl.openConnection();
            connection.setRequestMethod("GET");
            int responseCode = connection.getResponseCode();
            if (responseCode == 200) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                String inputLine;
                StringBuilder content = new StringBuilder();
                while ((inputLine = reader.readLine()) != null) {
                    content.append(inputLine);
                }
                reader.close();
                connection.disconnect();
                String jsonContent = content.toString();
                if (jsonContent != null) {
                    JsonObject jsonObject = JsonParser.parseString(jsonContent).getAsJsonObject();
                    JsonObject messageObject = jsonObject.getAsJsonObject("message");
                    if (messageObject.has("link") && messageObject.get("link").isJsonArray()) {
                        JsonArray urlsArray = messageObject.getAsJsonArray("link");
                        redirectUrl = urnnbn(urlsArray);
                    } else {
                        super.logError(RotatingAccessLog.ERRLOG_LEVEL_NORMAL, "No resource link for crossref doi found.");
                    }
                }
            } else {
                handleHttpError(responseCode, resp, "Failed to fetch data from Crossref. HTTP response code: " + responseCode);
            }
        } catch (Exception e) {
            handleHttpError(500, resp, "Internal server error while resolving Crossref resource URL: " + url);
        }
        return redirectUrl;
    }

    private String fetchContent(String url) throws IOException {
        HttpServletResponse resp = responseHolder.get();
        try {
            URL apiUrl = new URL(url);
            HttpURLConnection connection = (HttpURLConnection) apiUrl.openConnection();
            connection.setRequestMethod("GET");
            int responseCode = connection.getResponseCode();
            if (responseCode == 200) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                String inputLine;
                StringBuilder content = new StringBuilder();
                while ((inputLine = reader.readLine()) != null) {
                    content.append(inputLine);
                }
                reader.close();
                connection.disconnect();
                return content.toString();
            } else {
                handleHttpError(responseCode, resp, "Failed to fetch data. HTTP response code: " + responseCode);
            }
        } catch (Exception e) {
            handleHttpError(500, resp, "Internal server error while fetching content from URL: " + url);
        }
        return null;
    }

    private String extractDocumentId(String pid) {
        String regex = "(\\d+)$";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(pid);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    public String handleZenodoResourceMode(String metadataUrl) throws IOException {
        HttpServletResponse resp = responseHolder.get();
        String jsonContent = fetchContent(metadataUrl);
        String redirectUrl = null;
        if (jsonContent != null) {
            JsonArray metadataFiles = extractMetadataFiles(jsonContent);
            if (metadataFiles != null) {
                redirectUrl = processMetadataFiles(metadataFiles);
            } else {
                handleHttpError(500, resp, "No metadata found in metadata file.");
                super.logError(RotatingAccessLog.ERRLOG_LEVEL_NORMAL, "No metadata found in metadata file.");
            }
        }
        return redirectUrl;
    }

    private JsonArray extractMetadataFiles(String jsonContent) {
        JsonObject jsonObject = JsonParser.parseString(jsonContent).getAsJsonObject();
        if (jsonObject.has("files") && jsonObject.get("files").isJsonArray()) {
            return jsonObject.getAsJsonArray("files");
        }
        return null;
    }

    private String processMetadataFiles(JsonArray metadataFiles) throws IOException {
        int size = metadataFiles.size();
        if (size == 1) {
            String redirectUrl = metadataFiles
                    .get(0)
                    .getAsJsonObject()
                    .get("links")
                    .getAsJsonObject()
                    .get("self")
                    .getAsString();
            return redirectUrl;
        } else {
            JsonArray urlJsonArray = new JsonArray();
            for (JsonElement link : metadataFiles) {
                String url = link.getAsJsonObject()
                        .get("links")
                        .getAsJsonObject()
                        .get("self")
                        .getAsString();
                urlJsonArray.add(url);
            }
            return sendJsonResponse(urlJsonArray.toString());
        }
    }

    private String sendJsonResponse(String jsonArrayString) throws IOException {
        HttpServletResponse resp = responseHolder.get();
        if (resp != null) {
            try {
                resp.setCharacterEncoding("UTF-8");
                resp.setContentType("application/json");
                resp.getWriter().println(jsonArrayString);
                resp.getWriter().flush();
                return null;
            } catch (IOException e) {
                super.logError(RotatingAccessLog.ERRLOG_LEVEL_FATAL, "Failed to send resource link list: " + e.getMessage());
                try {
                    errorHandling(resp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "An error occurred while processing the request.");
                } catch (IOException ioException) {
                    super.logError(RotatingAccessLog.ERRLOG_LEVEL_FATAL, "Failed to send error response to client: " + e.getMessage());
                }
            }
        } else {
            errorHandling(resp, 500, "error");
            return null;
        }
        return null;
    }

    private HandleValue[] resolveHandle(String handle) throws HandleException {
        byte[] handleBytes = Util.encodeString(handle);
        ResolutionRequest resolutionRequest = new ResolutionRequest(handleBytes, null, null, null);
        AbstractResponse response = super.resolver.processRequest(resolutionRequest, null);
        if (response.responseCode != AbstractMessage.RC_SUCCESS) {
            throw new HandleException(HandleException.INTERNAL_ERROR, response.toString());
        }
        if (response instanceof ResolutionResponse) {
            ResolutionResponse resResponse = (ResolutionResponse) response;
            return resResponse.getHandleValues();
        } else {
            throw new HandleException(HandleException.INTERNAL_ERROR, AbstractMessage.getResponseCodeMessage(response.responseCode));
        }
    }

    private void handleRedirect(String pidType, String pid, String display, HDLServletRequest hdl, HttpServletResponse resp, String endpoint) throws IOException {
        String redirectUrl = null;
        switch (display) {
            case RESOLVING_MODE_LANDINGPAGE:
                if (endpoint != null) {
                    if (pidType.equals("10.5281/zenodo")) {
                        pid = extractDocumentId(pid);
                    }
                }
                redirectUrl = endpoint != null ? String.format(endpoint, pid) : null;
                break;
            case RESOLVING_MODE_METADATA:
                if (endpoint != null) {
                    if (pidType.equals("arXiv")) {
                        pid = pid.split(":")[1];
                    }
                    if (pidType.equals("10.5281/zenodo")) {
                        pid = extractDocumentId(pid);
                    }
                    redirectUrl = String.format(endpoint, pid);
                }
                break;
            case RESOLVING_MODE_RESOURCE:
                if (pidType.equals("10.5281/zenodo")) {
                    pid = extractDocumentId(pid);
                }
                try {
                    if (pidType.equals("GDZ")) {
                        redirectUrl = String.format(endpoint, pid, pid);
                    } else {
                        redirectUrl = String.format(endpoint, pid);
                    }
                } catch (MissingFormatArgumentException e) {
                    errorHandling(resp, 500, "Server error: Invalid format string in endpoint.");
                    return;
                }
                if (config.handlePIDResourceMode().containsKey(pidType)) {
                    String methodName = config.handlePIDResourceMode().get(pidType);
                    if (methodName != null) {
                        try {
                            Method method = this.getClass().getMethod(methodName, String.class);
                            redirectUrl = (String) method.invoke(this, redirectUrl);
                            if (redirectUrl == null) {
                                return;
                            }
                        } catch (Exception e) {
                            errorHandling(resp, 500, String.format("Invoking method %s failed.", methodName));
                            return;
                        }
                    }
                }
                break;
        }
        if (redirectUrl != null) {
            redirect(pidType, pid, display, redirectUrl, hdl, resp);
        } else {
            handleHttpError(404, resp, "No redirect endpoint found.");
        }
    }
}
