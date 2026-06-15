package eu.faircode.netguard;

import org.junit.Test;

import java.io.BufferedReader;
import java.io.StringReader;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * JVM unit tests for {@link HostsFileParser}.
 *
 * <p>Covers normal entries, comments, inline comments, empty lines,
 * malformed lines, whitespace variations, empty input, and duplicate
 * entries for both the hosts-block and malware-list formats.</p>
 */
public class HostsFileParserTest {

    // ========================================================================
    // Hosts file parsing
    // ========================================================================

    @Test
    public void parseHosts_normalEntries() throws Exception {
        String content =
                "127.0.0.1 ads.example.com\n" +
                "0.0.0.0 tracker.example.net\n" +
                "127.0.0.1 malware.bad.org\n";
        Map<String, Boolean> map = HostsFileParser.parseHosts(new BufferedReader(new StringReader(content)));

        assertEquals(3, map.size());
        assertTrue(map.get("ads.example.com"));
        assertTrue(map.get("tracker.example.net"));
        assertTrue(map.get("malware.bad.org"));
    }

    @Test
    public void parseHosts_commentsStripped() throws Exception {
        String content =
                "# This is a comment\n" +
                "127.0.0.1 ads.example.com # inline comment\n" +
                "# another full-line comment\n" +
                "0.0.0.0 tracker.net\n";
        Map<String, Boolean> map = HostsFileParser.parseHosts(new BufferedReader(new StringReader(content)));

        assertEquals(2, map.size());
        assertTrue(map.containsKey("ads.example.com"));
        assertTrue(map.containsKey("tracker.net"));
    }

    @Test
    public void parseHosts_emptyLines() throws Exception {
        String content =
                "\n" +
                "127.0.0.1 host1.com\n" +
                "\n" +
                "\n" +
                "127.0.0.1 host2.com\n" +
                "\n";
        Map<String, Boolean> map = HostsFileParser.parseHosts(new BufferedReader(new StringReader(content)));

        assertEquals(2, map.size());
        assertTrue(map.containsKey("host1.com"));
        assertTrue(map.containsKey("host2.com"));
    }

    @Test
    public void parseHosts_emptyInput() throws Exception {
        Map<String, Boolean> map = HostsFileParser.parseHosts(new BufferedReader(new StringReader("")));
        assertTrue(map.isEmpty());
    }

    @Test
    public void parseHosts_onlyComments() throws Exception {
        String content = "# just a comment\n# and another\n";
        Map<String, Boolean> map = HostsFileParser.parseHosts(new BufferedReader(new StringReader(content)));
        assertTrue(map.isEmpty());
    }

    @Test
    public void parseHosts_malformedLines() throws Exception {
        String content =
                "justonehost\n" +               // only 1 word - skipped
                "127.0.0.1 valid.com\n" +       // valid
                "a b c d\n" +                   // 4 words - skipped (hosts expects exactly 2)
                "\n";
        Map<String, Boolean> map = HostsFileParser.parseHosts(new BufferedReader(new StringReader(content)));

        assertEquals(1, map.size());
        assertTrue(map.containsKey("valid.com"));
    }

    @Test
    public void parseHosts_tabsAndMultipleSpaces() throws Exception {
        String content =
                "127.0.0.1\ttabbed.com\n" +
                "0.0.0.0    spaced.com\n" +
                "127.0.0.1  \t  mixed.com\n";
        Map<String, Boolean> map = HostsFileParser.parseHosts(new BufferedReader(new StringReader(content)));

        assertEquals(3, map.size());
        assertTrue(map.containsKey("tabbed.com"));
        assertTrue(map.containsKey("spaced.com"));
        assertTrue(map.containsKey("mixed.com"));
    }

    @Test
    public void parseHosts_duplicateEntries() throws Exception {
        String content =
                "127.0.0.1 dup.example.com\n" +
                "0.0.0.0 dup.example.com\n";
        Map<String, Boolean> map = HostsFileParser.parseHosts(new BufferedReader(new StringReader(content)));

        assertEquals(1, map.size());
        assertTrue(map.get("dup.example.com"));
    }

    @Test
    public void parseHosts_lineWithOnlyHash() throws Exception {
        String content =
                "#\n" +
                "127.0.0.1 after-hash.com\n";
        Map<String, Boolean> map = HostsFileParser.parseHosts(new BufferedReader(new StringReader(content)));

        assertEquals(1, map.size());
        assertTrue(map.containsKey("after-hash.com"));
    }

    @Test
    public void parseHosts_whitespaceBeforeComment() throws Exception {
        String content = "  127.0.0.1 host.com  # comment  \n";
        Map<String, Boolean> map = HostsFileParser.parseHosts(new BufferedReader(new StringReader(content)));

        assertEquals(1, map.size());
        assertTrue(map.containsKey("host.com"));
    }

    @Test
    public void parseHosts_largeFile() throws Exception {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 10000; i++) {
            sb.append("127.0.0.1 host").append(i).append(".example.com\n");
        }
        Map<String, Boolean> map = HostsFileParser.parseHosts(new BufferedReader(new StringReader(sb.toString())));

        assertEquals(10000, map.size());
        assertTrue(map.containsKey("host0.example.com"));
        assertTrue(map.containsKey("host9999.example.com"));
    }

    // ========================================================================
    // Malware list parsing
    // ========================================================================

    @Test
    public void parseMalware_normalEntries() throws Exception {
        String content =
                "127.0.0.1 malware1.bad.com\n" +
                "0.0.0.0 malware2.evil.org some extra info\n";
        Map<String, Boolean> map = HostsFileParser.parseMalware(new BufferedReader(new StringReader(content)));

        assertEquals(2, map.size());
        assertTrue(map.get("malware1.bad.com"));
        assertTrue(map.get("malware2.evil.org"));
    }

    @Test
    public void parseMalware_acceptsMoreThanTwoTokens() throws Exception {
        // Unlike hosts (which requires exactly 2), malware accepts > 1 tokens
        String content =
                "127.0.0.1 evil.com category:trojan severity:high\n" +
                "0.0.0.0 bad.org extra info here\n";
        Map<String, Boolean> map = HostsFileParser.parseMalware(new BufferedReader(new StringReader(content)));

        assertEquals(2, map.size());
        assertTrue(map.containsKey("evil.com"));
        assertTrue(map.containsKey("bad.org"));
    }

    @Test
    public void parseMalware_singleTokenSkipped() throws Exception {
        String content =
                "onlyonetoken\n" +
                "127.0.0.1 valid.malware.com\n";
        Map<String, Boolean> map = HostsFileParser.parseMalware(new BufferedReader(new StringReader(content)));

        assertEquals(1, map.size());
        assertTrue(map.containsKey("valid.malware.com"));
    }

    @Test
    public void parseMalware_emptyInput() throws Exception {
        Map<String, Boolean> map = HostsFileParser.parseMalware(new BufferedReader(new StringReader("")));
        assertTrue(map.isEmpty());
    }

    @Test
    public void parseMalware_commentsAndBlankLines() throws Exception {
        String content =
                "# Malware list\n" +
                "\n" +
                "127.0.0.1 bad.com # very bad\n" +
                "# end\n";
        Map<String, Boolean> map = HostsFileParser.parseMalware(new BufferedReader(new StringReader(content)));

        assertEquals(1, map.size());
        assertTrue(map.containsKey("bad.com"));
    }
}
