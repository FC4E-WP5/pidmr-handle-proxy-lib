package eu.faircore4eosc.pidmr.utilities;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PidUtils {
    private static final Pattern CANONICAL_FORMAT_PATTERN = Pattern.compile("https://[^/]+/(?:doi:)?(.+)", Pattern.CASE_INSENSITIVE);

    public static Optional<String> extractCanonicalPid(String pid) {
        Matcher matcher = CANONICAL_FORMAT_PATTERN.matcher(pid.trim());
        if (matcher.find()) {
            return Optional.of(matcher.group(1));
        }
        return Optional.empty();
    }

    public static String checkForCanonicalFormat(String pid) {
        return extractCanonicalPid(pid).orElse(pid);
    }

    public static String extractDocumentId(String pid) {
        Matcher matcher = Pattern.compile("(\\d+)$").matcher(pid);
        return matcher.find() ? matcher.group(1) : null;
    }
}
