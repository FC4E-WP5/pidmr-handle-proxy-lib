package eu.faircore4eosc.pidmr;

import java.io.*;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.MissingFormatArgumentException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;

import eu.faircore4eosc.pidmr.ConfigLoader;
import eu.faircore4eosc.pidmr.services.ProviderService;
import eu.faircore4eosc.pidmr.utilities.PidUtils;
import eu.faircore4eosc.pidmr.services.ResourceResolutionService;
import eu.faircore4eosc.pidmr.services.PIDMRHandler;

import net.handle.apps.servlet_proxy.HDLProxy;
import net.handle.apps.servlet_proxy.HDLServletRequest;
import net.handle.apps.servlet_proxy.HDLServletRequest.ResponseType;
import net.handle.apps.servlet_proxy.RotatingAccessLog;
import net.handle.hdllib.*;
import net.handle.server.servletcontainer.HandleServerInterface;

public class PIDMRHDLProxy extends HDLProxy {
    public static RequestProcessor resolver = null;
    private String display = null;
    private String pid = null;
    private final String RESOLVING_MODE_LANDINGPAGE = "landingpage";
    private final String RESOLVING_MODE_METADATA = "metadata";
    private final String RESOLVING_MODE_RESOURCE = "resource";

    private String pidType = null;
    private boolean supportedMode = false;
    List<Integer> redirectHttpCodes = Arrays.asList(300, 301, 302, 303, 304, 305, 306, 307, 308);
    private ConfigLoader.Config config;
    private static final ThreadLocal<HttpServletResponse> responseHolder = new ThreadLocal<>();
    private ProviderService providerService;
    private PIDMRHandler pidmrHandler;
    private ResourceResolutionService resourceResolutionService;
    private RedirectService redirectService;

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
            this.pidmrHandler = new PIDMRHandler(providerService);
            this.resourceResolutionService = new ResourceResolutionService(pidmrHandler);
            this.redirectService = new RedirectService(config);
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
                    handleHttpError(500, resp, "Error determinig sub-provider.");
                    return;
                }
            }
        }
        String endpoint = resolveEndpoint(pidType, subProvider, display);
        if (endpoint == null) {
            return;
        }
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

    private void handleHttpError(int responseCode, HttpServletResponse resp, String errmsg) throws IOException {
        errorHandling(resp,responseCode, errmsg);
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

    private void handleRedirect(String pidType, String pid, String display,
                                HDLServletRequest hdl, HttpServletResponse resp, String endpoint) throws IOException {

        if (endpoint == null) {
            handleHttpError(404, resp, "No redirect endpoint found.");
            return;
        }
        pid = processPid(pidType, pid, display);
        String redirectUrl;
        try {
            redirectUrl = buildRedirectUrl(pidType, pid, endpoint);
        } catch (MissingFormatArgumentException e) {
            errorHandling(resp, 500, "Server error: Invalid format string in endpoint.");
            return;
        }
        if (RESOLVING_MODE_RESOURCE.equals(display)
                && config.handlePIDResourceMode().containsKey(pidType)) {
            redirectUrl = resourceResolutionService.handle(pidType, redirectUrl, resp);
            if (redirectUrl == null) {
                return;
            }
        }
        redirectService.redirect(resp, redirectUrl, pid, pidType, display, hdl);
    }

    private String processPid(String pidType, String pid, String display) {
        if (RESOLVING_MODE_METADATA.equals(display) && pidType.equals("arXiv")) {
            pid = pid.split(":")[1];
        }
        switch (pidType) {
            case "10.5281/zenodo":
                return PidUtils.extractDocumentId(pid);
            case "RAiD":
                return PidUtils.checkForCanonicalFormat(pid);
            default:
                return pid;
        }
    }

    private String buildRedirectUrl(String pidType, String pid, String endpoint) {
        if ("GDZ".equals(pidType)) {
            return String.format(endpoint, pid, pid);
        }
        return String.format(endpoint, pid);
    }
}
