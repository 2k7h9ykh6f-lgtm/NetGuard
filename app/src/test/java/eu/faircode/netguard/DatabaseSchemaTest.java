package eu.faircode.netguard;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

/**
 * Pure JDBC-based tests for DatabaseHelper schema and SQL operations.
 * Uses sqlite-jdbc to test SQL logic without requiring the Android framework.
 * Each test uses an in-memory database for complete isolation.
 */
public class DatabaseSchemaTest {

    private Connection conn;
    private static final int DB_VERSION = 22;

    @Before
    public void setUp() throws Exception {
        // Create in-memory SQLite database
        conn = DriverManager.getConnection("jdbc:sqlite::memory:");
        createAllTables();
    }

    @After
    public void tearDown() throws Exception {
        if (conn != null && !conn.isClosed()) {
            conn.close();
        }
    }

    private void createAllTables() throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            // Log table
            stmt.execute("CREATE TABLE log (" +
                    " ID INTEGER PRIMARY KEY AUTOINCREMENT" +
                    ", time INTEGER NOT NULL" +
                    ", version INTEGER" +
                    ", protocol INTEGER" +
                    ", flags TEXT" +
                    ", saddr TEXT" +
                    ", sport INTEGER" +
                    ", daddr TEXT" +
                    ", dport INTEGER" +
                    ", dname TEXT" +
                    ", uid INTEGER" +
                    ", data TEXT" +
                    ", allowed INTEGER" +
                    ", connection INTEGER" +
                    ", interactive INTEGER" +
                    ")");
            stmt.execute("CREATE INDEX idx_log_time ON log(time)");
            stmt.execute("CREATE INDEX idx_log_dest ON log(daddr)");
            stmt.execute("CREATE INDEX idx_log_dname ON log(dname)");
            stmt.execute("CREATE INDEX idx_log_dport ON log(dport)");
            stmt.execute("CREATE INDEX idx_log_uid ON log(uid)");

            // Access table
            stmt.execute("CREATE TABLE access (" +
                    " ID INTEGER PRIMARY KEY AUTOINCREMENT" +
                    ", uid INTEGER NOT NULL" +
                    ", version INTEGER NOT NULL" +
                    ", protocol INTEGER NOT NULL" +
                    ", daddr TEXT NOT NULL" +
                    ", dport INTEGER NOT NULL" +
                    ", time INTEGER NOT NULL" +
                    ", allowed INTEGER" +
                    ", block INTEGER NOT NULL" +
                    ", sent INTEGER" +
                    ", received INTEGER" +
                    ", connections INTEGER" +
                    ")");
            stmt.execute("CREATE UNIQUE INDEX idx_access ON access(uid, version, protocol, daddr, dport)");
            stmt.execute("CREATE INDEX idx_access_daddr ON access(daddr)");
            stmt.execute("CREATE INDEX idx_access_block ON access(block)");

            // DNS table
            stmt.execute("CREATE TABLE dns (" +
                    " ID INTEGER PRIMARY KEY AUTOINCREMENT" +
                    ", time INTEGER NOT NULL" +
                    ", qname TEXT NOT NULL" +
                    ", aname TEXT NOT NULL" +
                    ", resource TEXT NOT NULL" +
                    ", ttl INTEGER" +
                    ", uid INTEGER" +
                    ")");
            stmt.execute("CREATE UNIQUE INDEX idx_dns ON dns(qname, aname, resource)");
            stmt.execute("CREATE INDEX idx_dns_resource ON dns(resource)");

            // Forward table
            stmt.execute("CREATE TABLE forward (" +
                    " ID INTEGER PRIMARY KEY AUTOINCREMENT" +
                    ", protocol INTEGER NOT NULL" +
                    ", dport INTEGER NOT NULL" +
                    ", raddr TEXT NOT NULL" +
                    ", rport INTEGER NOT NULL" +
                    ", ruid INTEGER NOT NULL" +
                    ")");
            stmt.execute("CREATE UNIQUE INDEX idx_forward ON forward(protocol, dport)");

            // App table
            stmt.execute("CREATE TABLE app (" +
                    " ID INTEGER PRIMARY KEY AUTOINCREMENT" +
                    ", package TEXT" +
                    ", label TEXT" +
                    ", system INTEGER NOT NULL" +
                    ", internet INTEGER NOT NULL" +
                    ", enabled INTEGER NOT NULL" +
                    ")");
            stmt.execute("CREATE UNIQUE INDEX idx_package ON app(package)");
        }
    }

    // ===============================================================
    //  SCHEMA VALIDATION TESTS
    // ===============================================================

    @Test
    public void testAllTablesExist() throws SQLException {
        List<String> tables = new ArrayList<>();
        try (ResultSet rs = conn.createStatement().executeQuery(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")) {
            while (rs.next()) {
                tables.add(rs.getString(1));
            }
        }
        assertTrue("log table missing", tables.contains("log"));
        assertTrue("access table missing", tables.contains("access"));
        assertTrue("dns table missing", tables.contains("dns"));
        assertTrue("forward table missing", tables.contains("forward"));
        assertTrue("app table missing", tables.contains("app"));
    }

    @Test
    public void testAllIndexesExist() throws SQLException {
        List<String> indexes = new ArrayList<>();
        try (ResultSet rs = conn.createStatement().executeQuery(
                "SELECT name FROM sqlite_master WHERE type='index' ORDER BY name")) {
            while (rs.next()) {
                indexes.add(rs.getString(1));
            }
        }
        assertTrue(indexes.contains("idx_log_time"));
        assertTrue(indexes.contains("idx_log_dest"));
        assertTrue(indexes.contains("idx_log_dname"));
        assertTrue(indexes.contains("idx_log_dport"));
        assertTrue(indexes.contains("idx_log_uid"));
        assertTrue(indexes.contains("idx_access"));
        assertTrue(indexes.contains("idx_access_daddr"));
        assertTrue(indexes.contains("idx_access_block"));
        assertTrue(indexes.contains("idx_dns"));
        assertTrue(indexes.contains("idx_dns_resource"));
        assertTrue(indexes.contains("idx_forward"));
        assertTrue(indexes.contains("idx_package"));
    }

    @Test
    public void testLogTableColumns() throws SQLException {
        List<String> columns = getTableColumns("log");
        assertTrue(columns.contains("ID"));
        assertTrue(columns.contains("time"));
        assertTrue(columns.contains("version"));
        assertTrue(columns.contains("protocol"));
        assertTrue(columns.contains("flags"));
        assertTrue(columns.contains("saddr"));
        assertTrue(columns.contains("sport"));
        assertTrue(columns.contains("daddr"));
        assertTrue(columns.contains("dport"));
        assertTrue(columns.contains("dname"));
        assertTrue(columns.contains("uid"));
        assertTrue(columns.contains("data"));
        assertTrue(columns.contains("allowed"));
        assertTrue(columns.contains("connection"));
        assertTrue(columns.contains("interactive"));
    }

    @Test
    public void testDnsTableHasUidColumn() throws SQLException {
        List<String> columns = getTableColumns("dns");
        assertTrue("dns table should have uid column (v22)", columns.contains("uid"));
    }

    @Test
    public void testAccessTableHasUsageColumns() throws SQLException {
        List<String> columns = getTableColumns("access");
        assertTrue(columns.contains("sent"));
        assertTrue(columns.contains("received"));
        assertTrue(columns.contains("connections"));
    }

    private List<String> getTableColumns(String tableName) throws SQLException {
        List<String> columns = new ArrayList<>();
        try (ResultSet rs = conn.createStatement().executeQuery(
                "PRAGMA table_info(" + tableName + ")")) {
            while (rs.next()) {
                columns.add(rs.getString("name"));
            }
        }
        return columns;
    }

    // ===============================================================
    //  LOG OPERATIONS TESTS
    // ===============================================================

    @Test
    public void testInsertAndQueryLog() throws SQLException {
        insertLog(1000L, 4, 6, "S", "10.0.0.1", 12345, "1.2.3.4", 80, "example.com", 1000, null, 1, 1, 1);

        try (ResultSet rs = conn.createStatement().executeQuery(
                "SELECT * FROM log WHERE daddr = '1.2.3.4'")) {
            assertTrue(rs.next());
            assertEquals("1.2.3.4", rs.getString("daddr"));
            assertEquals(80, rs.getInt("dport"));
            assertEquals(1000, rs.getInt("uid"));
            assertEquals("example.com", rs.getString("dname"));
        }
    }

    @Test
    public void testLogOrderedByTimeDesc() throws SQLException {
        insertLog(1000L, 4, 6, "S", "10.0.0.1", 12345, "a.com", 80, null, 100, null, 1, 1, 0);
        insertLog(3000L, 4, 6, "S", "10.0.0.1", 12345, "c.com", 80, null, 100, null, 1, 1, 0);
        insertLog(2000L, 4, 6, "S", "10.0.0.1", 12345, "b.com", 80, null, 100, null, 1, 1, 0);

        try (ResultSet rs = conn.createStatement().executeQuery(
                "SELECT daddr FROM log ORDER BY time DESC")) {
            assertTrue(rs.next());
            assertEquals("c.com", rs.getString("daddr"));
            assertTrue(rs.next());
            assertEquals("b.com", rs.getString("daddr"));
            assertTrue(rs.next());
            assertEquals("a.com", rs.getString("daddr"));
        }
    }

    @Test
    public void testClearLogByUid() throws SQLException {
        insertLog(1000L, 4, 6, "S", "10.0.0.1", 12345, "a.com", 80, null, 100, null, 1, 1, 0);
        insertLog(2000L, 4, 6, "S", "10.0.0.1", 12345, "b.com", 80, null, 200, null, 1, 1, 0);
        insertLog(3000L, 4, 6, "S", "10.0.0.1", 12345, "c.com", 80, null, 100, null, 1, 1, 0);

        int deleted = conn.createStatement().executeUpdate("DELETE FROM log WHERE uid = 100");
        assertEquals(2, deleted);

        try (ResultSet rs = conn.createStatement().executeQuery("SELECT COUNT(*) FROM log")) {
            rs.next();
            assertEquals(1, rs.getInt(1));
        }
    }

    @Test
    public void testCleanupLogByTimeRange() throws SQLException {
        insertLog(1000L, 4, 6, "S", "10.0.0.1", 12345, "old1.com", 80, null, 100, null, 1, 1, 0);
        insertLog(2000L, 4, 6, "S", "10.0.0.1", 12345, "old2.com", 80, null, 100, null, 1, 1, 0);
        insertLog(5000L, 4, 6, "S", "10.0.0.1", 12345, "new1.com", 80, null, 100, null, 1, 1, 0);
        insertLog(8000L, 4, 6, "S", "10.0.0.1", 12345, "new2.com", 80, null, 100, null, 1, 1, 0);

        int deleted = conn.createStatement().executeUpdate("DELETE FROM log WHERE time < 3000");
        assertEquals(2, deleted);

        try (ResultSet rs = conn.createStatement().executeQuery(
                "SELECT daddr FROM log ORDER BY time DESC")) {
            assertTrue(rs.next());
            assertEquals("new2.com", rs.getString("daddr"));
            assertTrue(rs.next());
            assertEquals("new1.com", rs.getString("daddr"));
            assertFalse(rs.next());
        }
    }

    @Test
    public void testSearchLogByDaddr() throws SQLException {
        insertLog(1000L, 4, 6, "S", "10.0.0.1", 12345, "10.20.30.40", 80, null, 100, null, 1, 1, 0);
        insertLog(2000L, 4, 6, "S", "10.0.0.1", 12345, "192.168.1.1", 80, null, 100, null, 1, 1, 0);

        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT * FROM log WHERE daddr LIKE ? ORDER BY time DESC")) {
            ps.setString(1, "%10.20%");
            try (ResultSet rs = ps.executeQuery()) {
                assertTrue(rs.next());
                assertEquals("10.20.30.40", rs.getString("daddr"));
                assertFalse(rs.next());
            }
        }
    }

    @Test
    public void testSynSniReplacement() throws SQLException {
        // Insert SYN packet
        insertLog(5000L, 4, 6, "S", "10.0.0.1", 12345, "1.2.3.4", 443, null, 1000, null, 1, 1, 1);

        // Insert SNI packet (within 5s window) - delete SYN first
        long sniTime = 5500L;
        long synWindow = 5000L;
        int deleted = conn.createStatement().executeUpdate(
                "DELETE FROM log WHERE time > " + (sniTime - synWindow) +
                " AND protocol = 6 AND version = 4 AND flags = 'S'" +
                " AND daddr = '1.2.3.4' AND dport = 443 AND uid = 1000");
        assertEquals(1, deleted);

        // Insert SNI
        insertLog(sniTime, 4, 6, null, "10.0.0.1", 12345, "1.2.3.4", 443, "secure.example.com", 1000, "sni", 1, 2, 1);

        try (ResultSet rs = conn.createStatement().executeQuery("SELECT * FROM log")) {
            assertTrue(rs.next());
            assertEquals("sni", rs.getString("data"));
            assertEquals("secure.example.com", rs.getString("dname"));
            assertFalse(rs.next());
        }
    }

    private void insertLog(long time, int version, int protocol, String flags, String saddr,
                          int sport, String daddr, int dport, String dname, int uid,
                          String data, int allowed, int connection, int interactive) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO log (time, version, protocol, flags, saddr, sport, daddr, dport, dname, uid, data, allowed, connection, interactive) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")) {
            ps.setLong(1, time);
            ps.setInt(2, version);
            ps.setInt(3, protocol);
            ps.setString(4, flags);
            ps.setString(5, saddr);
            ps.setInt(6, sport);
            ps.setString(7, daddr);
            ps.setInt(8, dport);
            ps.setString(9, dname);
            ps.setInt(10, uid);
            ps.setString(11, data);
            ps.setInt(12, allowed);
            ps.setInt(13, connection);
            ps.setInt(14, interactive);
            ps.executeUpdate();
        }
    }

    // ===============================================================
    //  DNS OPERATIONS TESTS
    // ===============================================================

    @Test
    public void testInsertDns() throws SQLException {
        insertDns(System.currentTimeMillis(), "example.com", "example.com", "93.184.216.34", 259200000L, 1000);

        try (ResultSet rs = conn.createStatement().executeQuery("SELECT * FROM dns")) {
            assertTrue(rs.next());
            assertEquals("example.com", rs.getString("qname"));
            assertEquals("93.184.216.34", rs.getString("resource"));
            assertEquals(1000, rs.getInt("uid"));
        }
    }

    @Test
    public void testDnsDeduplication() throws SQLException {
        long time1 = System.currentTimeMillis();
        insertDns(time1, "example.com", "example.com", "93.184.216.34", 259200000L, 1000);

        // Same (qname, aname, resource) - should update via UNIQUE index
        long time2 = time1 + 10000;
        int updated = conn.createStatement().executeUpdate(
                "UPDATE dns SET time = " + time2 + ", ttl = 500000000 WHERE qname = 'example.com' AND aname = 'example.com' AND resource = '93.184.216.34'");
        assertEquals(1, updated);

        try (ResultSet rs = conn.createStatement().executeQuery("SELECT COUNT(*) FROM dns")) {
            rs.next();
            assertEquals("Duplicate should be merged", 1, rs.getInt(1));
        }
    }

    @Test
    public void testCleanupExpiredDns() throws SQLException {
        long now = System.currentTimeMillis();
        insertDns(now - 500000L, "old.com", "old.com", "1.1.1.1", 100000L, 1000); // expired
        insertDns(now, "new.com", "new.com", "2.2.2.2", 999999000L, 1000); // valid

        int deleted = conn.createStatement().executeUpdate(
                "DELETE FROM dns WHERE time + ttl < " + now);
        assertEquals(1, deleted);

        try (ResultSet rs = conn.createStatement().executeQuery("SELECT qname FROM dns")) {
            assertTrue(rs.next());
            assertEquals("new.com", rs.getString("qname"));
            assertFalse(rs.next());
        }
    }

    @Test
    public void testGetQName_reverseLookup() throws SQLException {
        insertDns(System.currentTimeMillis(), "example.com", "example.com", "93.184.216.34", 259200000L, 1000);

        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT qname FROM dns WHERE resource = ? ORDER BY (uid = ?) DESC, qname LIMIT 1")) {
            ps.setString(1, "93.184.216.34");
            ps.setInt(2, 1000);
            try (ResultSet rs = ps.executeQuery()) {
                assertTrue(rs.next());
                assertEquals("example.com", rs.getString("qname"));
            }
        }
    }

    @Test
    public void testGetAlternateQNames() throws SQLException {
        insertDns(System.currentTimeMillis(), "cdn1.example.com", "cdn1.example.com", "10.10.10.10", 259200000L, 1000);
        insertDns(System.currentTimeMillis(), "cdn2.example.com", "cdn2.example.com", "10.10.10.10", 259200000L, 1000);

        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT DISTINCT d2.qname FROM dns d1 JOIN dns d2 ON d2.resource = d1.resource AND d2.id <> d1.id WHERE d1.qname = ? ORDER BY d2.qname")) {
            ps.setString(1, "cdn1.example.com");
            try (ResultSet rs = ps.executeQuery()) {
                assertTrue(rs.next());
                assertEquals("cdn2.example.com", rs.getString("qname"));
                assertFalse(rs.next());
            }
        }
    }

    private void insertDns(long time, String qname, String aname, String resource, long ttl, int uid) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO dns (time, qname, aname, resource, ttl, uid) VALUES (?, ?, ?, ?, ?, ?)")) {
            ps.setLong(1, time);
            ps.setString(2, qname);
            ps.setString(3, aname);
            ps.setString(4, resource);
            ps.setLong(5, ttl);
            ps.setInt(6, uid);
            ps.executeUpdate();
        }
    }

    // ===============================================================
    //  FORWARD OPERATIONS TESTS
    // ===============================================================

    @Test
    public void testAddAndGetForward() throws SQLException {
        insertForward(6, 8080, "127.0.0.1", 80, 1000);

        try (ResultSet rs = conn.createStatement().executeQuery("SELECT * FROM forward")) {
            assertTrue(rs.next());
            assertEquals(6, rs.getInt("protocol"));
            assertEquals(8080, rs.getInt("dport"));
            assertEquals("127.0.0.1", rs.getString("raddr"));
            assertEquals(80, rs.getInt("rport"));
            assertEquals(1000, rs.getInt("ruid"));
        }
    }

    @Test
    public void testForwardOrderedByDport() throws SQLException {
        insertForward(6, 9090, "127.0.0.1", 90, 1000);
        insertForward(17, 3000, "127.0.0.1", 30, 1000);
        insertForward(6, 5000, "127.0.0.1", 50, 1000);

        try (ResultSet rs = conn.createStatement().executeQuery(
                "SELECT dport FROM forward ORDER BY dport")) {
            assertTrue(rs.next());
            assertEquals(3000, rs.getInt("dport"));
            assertTrue(rs.next());
            assertEquals(5000, rs.getInt("dport"));
            assertTrue(rs.next());
            assertEquals(9090, rs.getInt("dport"));
        }
    }

    @Test
    public void testDeleteForwardSpecific() throws SQLException {
        insertForward(6, 8080, "127.0.0.1", 80, 1000);
        insertForward(17, 5353, "127.0.0.1", 53, 1000);

        int deleted = conn.createStatement().executeUpdate(
                "DELETE FROM forward WHERE protocol = 6 AND dport = 8080");
        assertEquals(1, deleted);

        try (ResultSet rs = conn.createStatement().executeQuery("SELECT COUNT(*) FROM forward")) {
            rs.next();
            assertEquals(1, rs.getInt(1));
        }
    }

    @Test
    public void testForwardUniqueConstraint() throws SQLException {
        insertForward(6, 8080, "127.0.0.1", 80, 1000);

        // Try to insert duplicate - should fail
        try {
            insertForward(6, 8080, "192.168.1.1", 8080, 2000);
            fail("Should have thrown SQLException for unique constraint violation");
        } catch (SQLException e) {
            // Expected
            assertTrue(e.getMessage().contains("UNIQUE constraint failed"));
        }
    }

    private void insertForward(int protocol, int dport, String raddr, int rport, int ruid) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO forward (protocol, dport, raddr, rport, ruid) VALUES (?, ?, ?, ?, ?)")) {
            ps.setInt(1, protocol);
            ps.setInt(2, dport);
            ps.setString(3, raddr);
            ps.setInt(4, rport);
            ps.setInt(5, ruid);
            ps.executeUpdate();
        }
    }

    // ===============================================================
    //  ACCESS OPERATIONS TESTS
    // ===============================================================

    @Test
    public void testUpdateAccess() throws SQLException {
        insertAccess(1000, 4, 6, "1.2.3.4", 80, 1000L, 1, -1);

        try (ResultSet rs = conn.createStatement().executeQuery("SELECT * FROM access WHERE uid = 1000")) {
            assertTrue(rs.next());
            assertEquals("1.2.3.4", rs.getString("daddr"));
            assertEquals(80, rs.getInt("dport"));
            assertEquals(-1, rs.getInt("block"));
        }
    }

    @Test
    public void testUpdateUsage() throws SQLException {
        insertAccess(1000, 4, 6, "1.2.3.4", 80, 1000L, 1, -1);

        // Update usage twice
        updateUsage(1000, 4, 6, "1.2.3.4", 80, 100L, 200L, 1);
        updateUsage(1000, 4, 6, "1.2.3.4", 80, 50L, 75L, 1);

        try (ResultSet rs = conn.createStatement().executeQuery(
                "SELECT sent, received, connections FROM access WHERE uid = 1000")) {
            assertTrue(rs.next());
            assertEquals(150L, rs.getLong("sent"));
            assertEquals(275L, rs.getLong("received"));
            assertEquals(2, rs.getInt("connections"));
        }
    }

    @Test
    public void testGetHostCount() throws SQLException {
        insertAccess(1000, 4, 6, "a.com", 80, 1000L, 1, 0);
        insertAccess(1000, 4, 6, "b.com", 80, 2000L, 1, 1);
        insertAccess(1000, 4, 6, "c.com", 80, 3000L, 1, -1); // unset

        try (ResultSet rs = conn.createStatement().executeQuery(
                "SELECT COUNT(*) FROM access WHERE block >= 0 AND uid = 1000")) {
            assertTrue(rs.next());
            assertEquals("Only block >= 0 should be counted", 2, rs.getInt(1));
        }
    }

    private void insertAccess(int uid, int version, int protocol, String daddr, int dport,
                             long time, int allowed, int block) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO access (uid, version, protocol, daddr, dport, time, allowed, block) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")) {
            ps.setInt(1, uid);
            ps.setInt(2, version);
            ps.setInt(3, protocol);
            ps.setString(4, daddr);
            ps.setInt(5, dport);
            ps.setLong(6, time);
            ps.setInt(7, allowed);
            ps.setInt(8, block);
            ps.executeUpdate();
        }
    }

    private void updateUsage(int uid, int version, int protocol, String daddr, int dport,
                            long sent, long received, int connections) throws SQLException {
        // Read current values
        long currentSent = 0, currentReceived = 0;
        int currentConnections = 0;
        try (ResultSet rs = conn.createStatement().executeQuery(
                "SELECT sent, received, connections FROM access WHERE uid = " + uid +
                " AND version = " + version + " AND protocol = " + protocol +
                " AND daddr = '" + daddr + "' AND dport = " + dport)) {
            if (rs.next()) {
                currentSent = rs.getLong("sent");
                currentReceived = rs.getLong("received");
                currentConnections = rs.getInt("connections");
            }
        }

        // Update with incremented values
        try (PreparedStatement ps = conn.prepareStatement(
                "UPDATE access SET sent = ?, received = ?, connections = ? WHERE uid = ? AND version = ? AND protocol = ? AND daddr = ? AND dport = ?")) {
            ps.setLong(1, currentSent + sent);
            ps.setLong(2, currentReceived + received);
            ps.setInt(3, currentConnections + connections);
            ps.setInt(4, uid);
            ps.setInt(5, version);
            ps.setInt(6, protocol);
            ps.setString(7, daddr);
            ps.setInt(8, dport);
            ps.executeUpdate();
        }
    }

    // ===============================================================
    //  MIGRATION PATH TESTS
    // ===============================================================

    @Test
    public void testMigration_v21_to_v22_addsDnsUidColumn() throws SQLException {
        // Simulate v21 schema (dns without uid)
        conn.createStatement().execute("DROP TABLE dns");
        conn.createStatement().execute("CREATE TABLE dns (" +
                " ID INTEGER PRIMARY KEY AUTOINCREMENT" +
                ", time INTEGER NOT NULL" +
                ", qname TEXT NOT NULL" +
                ", aname TEXT NOT NULL" +
                ", resource TEXT NOT NULL" +
                ", ttl INTEGER)");

        // Insert data
        conn.createStatement().executeUpdate(
                "INSERT INTO dns (time, qname, aname, resource, ttl) VALUES (1000, 'test.com', 'test.com', '1.1.1.1', 3600)");

        // Simulate v22 migration
        conn.createStatement().execute("ALTER TABLE dns ADD COLUMN uid INTEGER");

        // Verify uid column exists
        List<String> columns = getTableColumns("dns");
        assertTrue("uid column should exist after migration", columns.contains("uid"));

        // Verify data preserved
        try (ResultSet rs = conn.createStatement().executeQuery("SELECT * FROM dns WHERE qname = 'test.com'")) {
            assertTrue(rs.next());
            assertEquals("test.com", rs.getString("qname"));
        }
    }

    @Test
    public void testMigration_v16_to_v22_multipleAlterations() throws SQLException {
        // Simulate v16 schema (access without sent/received/connections)
        conn.createStatement().execute("DROP TABLE access");
        conn.createStatement().execute("CREATE TABLE access (" +
                " ID INTEGER PRIMARY KEY AUTOINCREMENT" +
                ", uid INTEGER NOT NULL" +
                ", version INTEGER NOT NULL" +
                ", protocol INTEGER NOT NULL" +
                ", daddr TEXT NOT NULL" +
                ", dport INTEGER NOT NULL" +
                ", time INTEGER NOT NULL" +
                ", allowed INTEGER" +
                ", block INTEGER NOT NULL)");

        // Insert data
        conn.createStatement().executeUpdate(
                "INSERT INTO access (uid, version, protocol, daddr, dport, time, allowed, block) VALUES (1000, 4, 6, 'old.com', 80, 5000, 1, 0)");

        // Simulate v17-v22 migrations
        conn.createStatement().execute("ALTER TABLE access ADD COLUMN sent INTEGER");
        conn.createStatement().execute("ALTER TABLE access ADD COLUMN received INTEGER");
        conn.createStatement().execute("ALTER TABLE access ADD COLUMN connections INTEGER");

        // Verify columns exist
        List<String> columns = getTableColumns("access");
        assertTrue(columns.contains("sent"));
        assertTrue(columns.contains("received"));
        assertTrue(columns.contains("connections"));

        // Verify data preserved
        try (ResultSet rs = conn.createStatement().executeQuery("SELECT * FROM access WHERE uid = 1000")) {
            assertTrue(rs.next());
            assertEquals("old.com", rs.getString("daddr"));
        }
    }

    // ===============================================================
    //  EDGE CASE TESTS
    // ===============================================================

    @Test
    public void testNullValuesInLog() throws SQLException {
        insertLog(1000L, 4, -1, null, "10.0.0.1", -1, "1.2.3.4", -1, null, -1, null, 1, 0, 0);

        try (ResultSet rs = conn.createStatement().executeQuery("SELECT * FROM log")) {
            assertTrue(rs.next());
            assertNull(rs.getString("flags"));
            assertNull(rs.getString("dname"));
            assertNull(rs.getString("data"));
        }
    }

    @Test
    public void testEmptyDatabaseOperations() throws SQLException {
        // All operations on empty database should work without errors
        assertEquals(0, conn.createStatement().executeUpdate("DELETE FROM log"));
        assertEquals(0, conn.createStatement().executeUpdate("DELETE FROM dns"));
        assertEquals(0, conn.createStatement().executeUpdate("DELETE FROM forward"));
        assertEquals(0, conn.createStatement().executeUpdate("DELETE FROM access"));

        try (ResultSet rs = conn.createStatement().executeQuery("SELECT COUNT(*) FROM log")) {
            rs.next();
            assertEquals(0, rs.getInt(1));
        }
    }

    @Test
    public void testAccessDnsJoin() throws SQLException {
        long now = System.currentTimeMillis();

        // Create access rule
        insertAccess(1000, 4, 6, "ads.example.com", 443, now, 1, 1);

        // Create DNS entry
        insertDns(now, "ads.example.com", "ads.example.com", "10.20.30.40", 999999000L, 1000);

        // Test join query
        String query = "SELECT a.uid, a.version, a.protocol, a.daddr, d.resource, a.dport, a.block, d.time, d.ttl " +
                      "FROM access AS a LEFT JOIN dns AS d ON d.qname = a.daddr " +
                      "WHERE a.block >= 0 AND (d.time IS NULL OR d.time + d.ttl >= " + now + ")";

        try (ResultSet rs = conn.createStatement().executeQuery(query)) {
            assertTrue(rs.next());
            assertEquals("ads.example.com", rs.getString("daddr"));
            assertEquals("10.20.30.40", rs.getString("resource"));
            assertEquals(1, rs.getInt("block"));
        }
    }
}
