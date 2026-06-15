package eu.faircode.netguard;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Pure-Java parser for hosts-block files and malware lists, extracted from
 * {@code ServiceSinkhole.prepareHostsBlocked()} and
 * {@code ServiceSinkhole.prepareMalwareList()} so that the parsing logic can
 * be tested without Android framework dependencies.
 */
public final class HostsFileParser {

    private HostsFileParser() {
    }

    /**
     * Parse a hosts-block file.
     *
     * <p>Expected format per line: {@code <ip> <hostname>}.
     * Lines starting with {@code #} are comments. Inline comments after
     * {@code #} are stripped. Blank lines are ignored. Lines that do not
     * have exactly two whitespace-separated tokens are skipped.</p>
     *
     * @param reader a {@link BufferedReader} over the hosts file content
     * @return a map from hostname to {@code true} (blocked)
     * @throws IOException if reading fails
     */
    public static Map<String, Boolean> parseHosts(BufferedReader reader) throws IOException {
        Map<String, Boolean> map = new HashMap<>();
        String line;
        while ((line = reader.readLine()) != null) {
            int hash = line.indexOf('#');
            if (hash >= 0) {
                line = line.substring(0, hash);
            }
            line = line.trim();
            if (line.length() > 0) {
                String[] words = line.split("\\s+");
                if (words.length == 2) {
                    map.put(words[1], true);
                }
                // else: silently skip invalid lines (same as original)
            }
        }
        return map;
    }

    /**
     * Parse a malware list file.
     *
     * <p>Same format as hosts, but accepts lines with more than two tokens
     * (only the second token is used as the domain name).</p>
     *
     * @param reader a {@link BufferedReader} over the malware file content
     * @return a map from domain to {@code true} (malware)
     * @throws IOException if reading fails
     */
    public static Map<String, Boolean> parseMalware(BufferedReader reader) throws IOException {
        Map<String, Boolean> map = new HashMap<>();
        String line;
        while ((line = reader.readLine()) != null) {
            int hash = line.indexOf('#');
            if (hash >= 0) {
                line = line.substring(0, hash);
            }
            line = line.trim();
            if (line.length() > 0) {
                String[] words = line.split("\\s+");
                if (words.length > 1) {
                    map.put(words[1], true);
                }
            }
        }
        return map;
    }
}
