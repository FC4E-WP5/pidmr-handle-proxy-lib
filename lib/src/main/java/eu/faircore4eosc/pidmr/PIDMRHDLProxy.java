package eu.faircore4eosc.pidmr;

import java.io.*;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.MissingFormatArgumentException;
import java.util.ArrayList;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonElement;

import eu.faircore4eosc.pidmr.ConfigLoader;
import eu.faircore4eosc.pidmr.services.EndpointResolver;
import eu.faircore4eosc.pidmr.services.PIDMRHandler;
import eu.faircore4eosc.pidmr.services.ProviderFileService;
import eu.faircore4eosc.pidmr.services.ProviderService;
import eu.faircore4eosc.pidmr.services.ResourceResolutionService;
import eu.faircore4eosc.pidmr.utilities.ErrorHandler;
import eu.faircore4eosc.pidmr.utilities.InputSanitizer;
import eu.faircore4eosc.pidmr.utilities.PidUtils;
import eu.faircore4eosc.pidmr.utilities.ResponseUtils;

import net.handle.apps.servlet_proxy.HDLProxy;
import net.handle.apps.servlet_proxy.HDLServletRequest;
import net.handle.apps.servlet_proxy.RotatingAccessLog;
import net.handle.hdllib.*;

public class PIDMRHDLProxy extends HDLProxy {
    public static RequestProcessor resolver = null;
    private String display = null;
    private String pid = null;
    private final String RESOLVING_MODE_LANDINGPAGE = "landingpage";
    private final String RESOLVING_MODE_METADATA = "metadata";
    private final String RESOLVING_MODE_RESOURCE = "resource";
    private String pidType = null;
    private ConfigLoader.Config config;
    private static final ThreadLocal<HttpServletResponse> responseHolder = new ThreadLocal<>();
    private ProviderService providerService;
    private PIDMRHandler pidmrHandler;
    private ResourceResolutionService resourceResolutionService;
    private RedirectService redirectService;
    private EndpointResolver endpointResolver;

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

            List<JsonObject> providers = new ArrayList<>();
            for (JsonElement element : providersArray) {
                providers.add(element.getAsJsonObject());
            }
            this.resourceResolutionService = new ResourceResolutionService(providers);
            this.redirectService = new RedirectService(config);

            this.endpointResolver = new EndpointResolver(providers);

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
                ErrorHandler.badRequest(resp, "PID type not found.");
                return;
            }
            if (!endpointResolver.isResolutionModeSupported(pidType, hdl.params.getParameter("display")) && !pidType.equalsIgnoreCase("doi")) {
                ErrorHandler.badRequest(resp, "Resolution mode not found.");
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
            display = InputSanitizer.sanitize(config.getResolvingModes().get("RESOLVING_MODE_LANDINGPAGE"));
        }
        String pid = InputSanitizer.sanitize(hdl.hdl);
        try {
            dispatchPidHandlingMode(pid, display, hdl, pidType, resp);
        } catch (HandleException e) {
            super.logError(RotatingAccessLog.ERRLOG_LEVEL_NORMAL, "Error dispatching PID handling mode: " + e.getMessage());
            ErrorHandler.badRequest(resp, "Error dispatching PID handling mode.");
        }
    }

    @Override
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException {
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
                    if (pidType == null) {
                        ErrorHandler.badRequest(resp, "PID type not found.");
                        return;
                    }
                    if (!endpointResolver.isResolutionModeSupported(pidType, display) && !pidType.equalsIgnoreCase("doi")) {
                        ErrorHandler.badRequest(resp, "Resolution mode not found.");
                        return;
                    }
                    if (pidType != null) {
                        try {
                            dispatchPidHandlingMode(pid, display, hdl, pidType, resp);
                        } catch (HandleException e) {
                            throw new RuntimeException(e);
                        }
                        return;
                    } else {
                        ErrorHandler.badRequest(resp, "PID type not found.");
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

    private void fetchProvidersFileForUIList(HttpServletResponse resp) throws IOException {
        JsonObject json = ProviderFileService.loadProviderFile(config.getProvidersFilePath());
        ResponseUtils.writeJsonResponse(resp, json);
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
                    ErrorHandler.serverError(resp, "Error determining sub-provider.");
                    return;
                }
            }
        }
        String resolvedEndpoint = endpointResolver.resolve(pidType, subProvider, display);
        if (resolvedEndpoint == null) {
            return;
        }
        handleRedirect(pidType, subProvider, pid, display, hdl, resp, resolvedEndpoint);
    }

    /**
     * Dynamically invoked via reflection, e.g., through configuration entry:
     * { "doi": "getDoiProvider" }
     *
     * Attempts to extract a sub-provider identifier from the handle record
     * of the DOI prefix (e.g., "10.1234").
     *
     * @param pid The full PID string (e.g., "10.1234/abcd5678")
     * @return The resolved sub-provider ID or null if not found
     */
    public String getDoiProvider(String pid) {
        if (pid == null || !pid.contains("/")) return null;

        String doiPrefix = pid.split("/")[0];

        try {
            HandleValue[] handleValues = resolveHandle(doiPrefix);
            for (HandleValue val : handleValues) {
                if ("HS_SERV".equals(val.getTypeAsString())) {
                    String dataStr = val.getDataAsString();
                    if (dataStr != null && dataStr.contains("/")) {
                        return dataStr.toLowerCase().split("/")[1];
                    }
                }
            }
        } catch (HandleException e) {
            logError(RotatingAccessLog.ERRLOG_LEVEL_NORMAL,
                    "Failed to resolve DOI sub-provider for '" + pid + "': " + e.getMessage());
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

    private void handleRedirect(String pidType, String subProvider, String pid, String display,
                                HDLServletRequest hdl, HttpServletResponse resp, String endpoint) throws IOException {
        if (endpoint == null) {
            ErrorHandler.notFound(resp, "No redirect endpoint found.");
            return;
        }
        pid = processPid(pidType, pid, display);
        String redirectUrl;
        try {
            redirectUrl = buildRedirectUrl(pidType, pid, endpoint);
        } catch (MissingFormatArgumentException e) {
            ErrorHandler.serverError(resp, "Invalid format string in endpoint.");
            return;
        }
        if (RESOLVING_MODE_RESOURCE.equalsIgnoreCase(display)
                && resourceResolutionService.canHandle(pidType, subProvider)) {
            redirectUrl = resourceResolutionService.handle(pidType, subProvider, redirectUrl, resp);
            if (redirectUrl == null) return;

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
