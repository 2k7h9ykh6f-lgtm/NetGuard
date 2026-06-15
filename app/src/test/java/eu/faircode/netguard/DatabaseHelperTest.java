package eu.faircode.netguard;

/*
    This file is part of NetGuard.

    NetGuard is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    NetGuard is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with NetGuard.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2015-2026 by Marcel Bokhorst (M66B)
*/

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import android.app.Application;
import android.content.Context;
import android.content.SharedPreferences;
import android.database.Cursor;

import androidx.preference.PreferenceManager;
import androidx.test.core.app.ApplicationProvider;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.io.File;
import java.lang.reflect.Field;

/**
 * Isolated data-layer tests for {@link DatabaseHelper} exercising the public API used by the UI
 * ({@code ActivityLog}, {@code ActivityDns}, {@code ActivityForwarding}, ...).
 * <p>
 * Each test gets a brand-new on-disk SQLite database: {@link #setUp()} clears the {@code dh}
 * singleton via reflection and deletes the database files, so {@code onCreate} runs fresh and
 * tests never depend on execution order. The real {@link Application} ({@code ApplicationEx},
 * which loads the {@code netguard} native library) is replaced by the stock {@link Application}
 * so no JNI is touched.
 */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34, application = Application.class)
public class DatabaseHelperTest {

    private static final String DB_NAME = "Netguard";

    private Context context;
    private DatabaseHelper db;

    @Before
    public void setUp() {
        context = ApplicationProvider.getApplicationContext();
        closeAndReset();                                  // start from a clean slate
        db = DatabaseHelper.getInstance(context);
    }

    @After
    public void tearDown() {
        closeAndReset();
    }

    // ----------------------------------------------------------------------------------------
    // Log: insert / query
    // ----------------------------------------------------------------------------------------

    @Test
    public void insertLog_thenGetLog_returnsRowWithExpectedColumns() {
        db.insertLog(packet(1000L, 6, "1.2.3.4", 443, 1000, true), "example.com", 1, false);

        try (Cursor c = db.getLog(true, true, true, true, true)) {
            assertEquals(1, c.getCount());
            assertTrue(c.moveToFirst());
            assertEquals(6, c.getInt(c.getColumnIndexOrThrow("protocol")));
            assertEquals("1.2.3.4", c.getString(c.getColumnIndexOrThrow("daddr")));
            assertEquals(443, c.getInt(c.getColumnIndexOrThrow("dport")));
            assertEquals("example.com", c.getString(c.getColumnIndexOrThrow("dname")));
            assertEquals(1000, c.getInt(c.getColumnIndexOrThrow("uid")));
            assertEquals(1, c.getInt(c.getColumnIndexOrThrow("allowed")));
        }
    }

    @Test
    public void getLog_filtersByProtocol() {
        db.insertLog(packet(1000L, 6, "tcp.host", 443, 1000, true), null, 1, false);   // TCP
        db.insertLog(packet(1000L, 17, "udp.host", 53, 1000, true), null, 1, false);   // UDP
        db.insertLog(packet(1000L, 1, "icmp.host", 0, 1000, true), null, 1, false);    // ICMP -> "other"

        try (Cursor c = db.getLog(false, true, false, true, true)) {
            assertEquals(1, c.getCount());
            assertTrue(c.moveToFirst());
            assertEquals(6, c.getInt(c.getColumnIndexOrThrow("protocol")));
        }
        try (Cursor c = db.getLog(true, false, false, true, true)) {
            assertEquals(1, c.getCount());
            assertTrue(c.moveToFirst());
            assertEquals(17, c.getInt(c.getColumnIndexOrThrow("protocol")));
        }
        try (Cursor c = db.getLog(false, false, true, true, true)) {
            assertEquals(1, c.getCount());
            assertTrue(c.moveToFirst());
            assertEquals(1, c.getInt(c.getColumnIndexOrThrow("protocol")));
        }
    }

    @Test
    public void getLog_filtersByAllowedAndBlocked() {
        db.insertLog(packet(1000L, 6, "allow.host", 443, 1000, true), null, 1, false);
        db.insertLog(packet(1000L, 6, "block.host", 443, 1000, false), null, 1, false);

        try (Cursor c = db.getLog(false, true, false, true, false)) { // allowed only
            assertEquals(1, c.getCount());
            assertTrue(c.moveToFirst());
            assertEquals(1, c.getInt(c.getColumnIndexOrThrow("allowed")));
        }
        try (Cursor c = db.getLog(false, true, false, false, true)) { // blocked only
            assertEquals(1, c.getCount());
            assertTrue(c.moveToFirst());
            assertEquals(0, c.getInt(c.getColumnIndexOrThrow("allowed")));
        }
    }

    @Test
    public void searchLog_matchesDaddrDnameDportAndUid() {
        db.insertLog(packet(1000L, 6, "1.2.3.4", 443, 1000, true), "example.com", 1, false);
        db.insertLog(packet(1000L, 6, "9.9.9.9", 853, 2000, true), "dns.google", 1, false);

        try (Cursor c = db.searchLog("example")) {   // matches dname LIKE
            assertEquals(1, c.getCount());
        }
        try (Cursor c = db.searchLog("9.9.9.9")) {   // matches daddr LIKE
            assertEquals(1, c.getCount());
        }
        try (Cursor c = db.searchLog("853")) {       // matches dport =
            assertEquals(1, c.getCount());
        }
        try (Cursor c = db.searchLog("2000")) {      // matches uid =
            assertEquals(1, c.getCount());
        }
    }

    // ----------------------------------------------------------------------------------------
    // Log: time-range cleanup, clear, SNI/SYN de-duplication
    // ----------------------------------------------------------------------------------------

    @Test
    public void cleanupLog_removesEntriesOlderThanGivenTime() {
        db.insertLog(packet(1000L, 6, "a.host", 443, 1000, true), null, 1, false);
        db.insertLog(packet(2000L, 6, "b.host", 443, 1000, true), null, 1, false);
        db.insertLog(packet(3000L, 6, "c.host", 443, 1000, true), null, 1, false);

        db.cleanupLog(2000L); // deletes rows with time < 2000 -> removes the time=1000 row

        try (Cursor c = db.getLog(false, true, false, true, true)) {
            assertEquals(2, c.getCount());
            while (c.moveToNext())
                assertTrue(c.getLong(c.getColumnIndexOrThrow("time")) >= 2000L);
        }
    }

    @Test
    public void clearLog_byUidThenAll() {
        db.insertLog(packet(1000L, 6, "a.host", 443, 1000, true), null, 1, false);
        db.insertLog(packet(1000L, 6, "b.host", 443, 1000, true), null, 1, false);
        db.insertLog(packet(1000L, 6, "c.host", 443, 2000, true), null, 1, false);

        db.clearLog(1000); // delete only uid 1000 (2 rows)
        try (Cursor c = db.getLog(false, true, false, true, true)) {
            assertEquals(1, c.getCount());
            assertTrue(c.moveToFirst());
            assertEquals(2000, c.getInt(c.getColumnIndexOrThrow("uid")));
        }

        db.clearLog(-1); // delete everything
        try (Cursor c = db.getLog(false, true, false, true, true)) {
            assertEquals(0, c.getCount());
        }
    }

    @Test
    public void insertLog_sniReplacesPrecedingSynForSameConnection() {
        // A SYN packet is logged first ...
        Packet syn = packet(10000L, 6, "1.1.1.1", 443, 1000, true);
        syn.flags = "S";
        syn.data = "syn";
        db.insertLog(syn, null, 1, false);

        // ... then the SNI for the same 5-tuple arrives within the 5s window and should
        // delete the preceding SYN row (see DatabaseHelper.SYN_SNI_DELAY).
        Packet sni = packet(11000L, 6, "1.1.1.1", 443, 1000, true);
        sni.flags = "PA";
        sni.data = "sni";
        db.insertLog(sni, "host.example", 1, false);

        try (Cursor c = db.getLog(false, true, false, true, true)) {
            assertEquals(1, c.getCount());
            assertTrue(c.moveToFirst());
            assertEquals("sni", c.getString(c.getColumnIndexOrThrow("data")));
        }
    }

    // ----------------------------------------------------------------------------------------
    // DNS: de-duplication, distinct rows, cleanup, clear, reverse lookup, UI columns
    // ----------------------------------------------------------------------------------------

    @Test
    public void insertDns_deduplicatesOnQnameAnameResource_andUpdatesTime() {
        assertTrue(db.insertDns(rr(1000L, "a.com", "a.com", "1.2.3.4", 100)));
        assertTrue(db.insertDns(rr(2000L, "a.com", "a.com", "1.2.3.4", 100)));

        try (Cursor c = db.getDns()) {
            assertEquals(1, c.getCount());                          // unique index -> single row
            assertTrue(c.moveToFirst());
            assertEquals(2000L, c.getLong(c.getColumnIndexOrThrow("time"))); // time updated
        }
    }

    @Test
    public void insertDns_distinctResourcesCoexist() {
        assertTrue(db.insertDns(rr(1000L, "a.com", "a.com", "1.2.3.4", 100)));
        assertTrue(db.insertDns(rr(1000L, "a.com", "a.com", "5.6.7.8", 100)));

        try (Cursor c = db.getDns()) {
            assertEquals(2, c.getCount());
        }
    }

    @Test
    public void clearDns_removesAllRecords() {
        db.insertDns(rr(1000L, "a.com", "a.com", "1.2.3.4", 100));
        db.insertDns(rr(1000L, "b.com", "b.com", "5.6.7.8", 100));

        db.clearDns();

        try (Cursor c = db.getDns()) {
            assertEquals(0, c.getCount());
        }
    }

    @Test
    public void cleanupDns_removesOnlyExpiredRecords() {
        // ttl floor of 0 so the stored TTL equals ResourceRecord.TTL (no minimum is applied).
        PreferenceManager.getDefaultSharedPreferences(context)
                .edit().putString("ttl", "0").commit();

        long now = System.currentTimeMillis();
        db.insertDns(rr(now - 100000L, "old.com", "old.com", "9.9.9.9", 0));        // time + 0 < now -> expired
        db.insertDns(rr(now, "fresh.com", "fresh.com", "8.8.8.8", 100000));         // far-future expiry -> kept

        db.cleanupDns();

        try (Cursor c = db.getDns()) {
            assertEquals(1, c.getCount());
            assertTrue(c.moveToFirst());
            assertEquals("fresh.com", c.getString(c.getColumnIndexOrThrow("qname")));
        }
    }

    @Test
    public void getQNameAndAlternateQNames_resolveSharedResource() {
        db.insertDns(rr(1000L, "a.com", "a.com", "1.2.3.4", 100));
        db.insertDns(rr(1000L, "b.com", "b.com", "1.2.3.4", 100));

        String qname = db.getQName(1000, "1.2.3.4");
        assertNotNull(qname);
        assertTrue("a.com".equals(qname) || "b.com".equals(qname));

        try (Cursor c = db.getAlternateQNames("a.com")) {
            boolean foundB = false;
            while (c.moveToNext())
                if ("b.com".equals(c.getString(0)))
                    foundB = true;
            assertTrue("a.com and b.com share a resource -> b.com is an alternate", foundB);
        }
    }

    @Test
    public void getDns_exposesColumnsConsumedByActivityDns() {
        db.insertDns(rr(1000L, "a.com", "a.com", "1.2.3.4", 100));
        // ActivityDns reads _id, time, qname, aname, resource, ttl.
        try (Cursor c = db.getDns()) {
            assertTrue(c.getColumnIndex("_id") >= 0);
            assertTrue(c.getColumnIndex("time") >= 0);
            assertTrue(c.getColumnIndex("qname") >= 0);
            assertTrue(c.getColumnIndex("aname") >= 0);
            assertTrue(c.getColumnIndex("resource") >= 0);
            assertTrue(c.getColumnIndex("ttl") >= 0);
        }
    }

    // ----------------------------------------------------------------------------------------
    // Forwarding: add / list / delete + unique constraint (ActivityForwarding contract)
    // ----------------------------------------------------------------------------------------

    @Test
    public void addForward_thenGetForwarding_exposesColumnsConsumedByActivityForwarding() {
        db.addForward(6, 80, "10.0.0.5", 8080, 0);

        // ActivityForwarding reads _id, protocol, dport, raddr, rport (and ruid).
        try (Cursor c = db.getForwarding()) {
            assertEquals(1, c.getCount());
            assertTrue(c.moveToFirst());
            assertTrue(c.getColumnIndex("_id") >= 0);
            assertEquals(6, c.getInt(c.getColumnIndexOrThrow("protocol")));
            assertEquals(80, c.getInt(c.getColumnIndexOrThrow("dport")));
            assertEquals("10.0.0.5", c.getString(c.getColumnIndexOrThrow("raddr")));
            assertEquals(8080, c.getInt(c.getColumnIndexOrThrow("rport")));
            assertEquals(0, c.getInt(c.getColumnIndexOrThrow("ruid")));
        }
    }

    @Test
    public void getForwarding_isOrderedByDport() {
        db.addForward(6, 443, "h1", 1, 0);
        db.addForward(6, 80, "h2", 2, 0);
        db.addForward(6, 8080, "h3", 3, 0);

        try (Cursor c = db.getForwarding()) {
            assertEquals(3, c.getCount());
            int col = c.getColumnIndexOrThrow("dport");
            assertTrue(c.moveToPosition(0));
            assertEquals(80, c.getInt(col));
            assertTrue(c.moveToPosition(1));
            assertEquals(443, c.getInt(col));
            assertTrue(c.moveToPosition(2));
            assertEquals(8080, c.getInt(col));
        }
    }

    @Test
    public void deleteForward_specificRuleLeavesOthers() {
        db.addForward(6, 80, "h1", 8080, 0);
        db.addForward(17, 53, "h2", 5353, 0);

        db.deleteForward(6, 80);

        try (Cursor c = db.getForwarding()) {
            assertEquals(1, c.getCount());
            assertTrue(c.moveToFirst());
            assertEquals(17, c.getInt(c.getColumnIndexOrThrow("protocol")));
            assertEquals(53, c.getInt(c.getColumnIndexOrThrow("dport")));
        }
    }

    @Test
    public void deleteForward_allRemovesEverything() {
        db.addForward(6, 80, "h1", 8080, 0);
        db.addForward(17, 53, "h2", 5353, 0);

        db.deleteForward();

        try (Cursor c = db.getForwarding()) {
            assertEquals(0, c.getCount());
        }
    }

    @Test
    public void addForward_duplicateProtocolAndPortKeepsSingleRow() {
        // Unique index idx_forward(protocol, dport): the second insert is rejected (logged, not thrown).
        db.addForward(6, 80, "10.0.0.5", 8080, 0);
        db.addForward(6, 80, "10.0.0.9", 9090, 0);

        try (Cursor c = db.getForwarding()) {
            assertEquals(1, c.getCount());
        }
    }

    // ----------------------------------------------------------------------------------------
    // Access (per-app statistics): insert/update, host count, clear
    // ----------------------------------------------------------------------------------------

    @Test
    public void updateAccess_insertsThenUpdatesSameRow() {
        boolean inserted = db.updateAccess(packet(1000L, 6, "1.2.3.4", 443, 1000, true), null, 0);
        assertTrue("first updateAccess inserts a new row", inserted);

        boolean insertedAgain = db.updateAccess(packet(2000L, 6, "1.2.3.4", 443, 1000, false), null, 0);
        assertFalse("second updateAccess updates the existing row", insertedAgain);

        try (Cursor c = db.getAccess(1000)) {
            assertEquals(1, c.getCount());
        }
    }

    @Test
    public void getHostCount_countsRulesForUid() {
        db.updateAccess(packet(1000L, 6, "1.2.3.4", 443, 1000, true), null, 0); // block = 0 -> a rule
        DatabaseHelper.clearCache();

        assertEquals(1L, db.getHostCount(1000, false));
        assertEquals(0L, db.getHostCount(9999, false)); // different uid -> none
    }

    @Test
    public void clearAccess_removesAllRows() {
        db.updateAccess(packet(1000L, 6, "1.2.3.4", 443, 1000, true), null, 0);

        db.clearAccess();

        try (Cursor c = db.getAccess(1000)) {
            assertEquals(0, c.getCount());
        }
    }

    // ----------------------------------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------------------------------

    /**
     * Reset the {@code DatabaseHelper.dh} singleton and delete the on-disk database so that the
     * next {@code getInstance} builds a pristine schema. This guarantees order-independent tests.
     */
    /**
     * Return to a pristine state: close the live SQLite connection, drop the {@code dh} singleton
     * and delete the database files so the next {@code getInstance} runs {@code onCreate} fresh.
     * <p>
     * {@link DatabaseHelper#close()} is intentionally a no-op, so the underlying {@link
     * android.database.sqlite.SQLiteDatabase} is closed directly &mdash; otherwise the open WAL
     * handle keeps the file locked and it cannot be deleted on Windows. Everything is best-effort
     * (never throws) so a single hiccup cannot cascade into unrelated tests.
     */
    private void closeAndReset() {
        if (db != null) {
            try {
                db.getWritableDatabase().close();
            } catch (Throwable ignored) {
            }
        }
        db = null;

        try {
            Field dh = DatabaseHelper.class.getDeclaredField("dh");
            dh.setAccessible(true);
            dh.set(null, null);
        } catch (Throwable ignored) {
        }

        DatabaseHelper.clearCache();

        if (context != null)
            for (String name : new String[]{DB_NAME, DB_NAME + "-journal", DB_NAME + "-wal", DB_NAME + "-shm"}) {
                File f = context.getDatabasePath(name);
                if (f.exists())
                    //noinspection ResultOfMethodCallIgnored
                    f.delete();
            }
    }

    private static Packet packet(long time, int protocol, String daddr, int dport, int uid, boolean allowed) {
        Packet p = new Packet();
        p.time = time;
        p.version = 4;
        p.protocol = protocol;
        p.flags = "";
        p.saddr = "10.1.10.1";
        p.sport = 40000;
        p.daddr = daddr;
        p.dport = dport;
        p.data = "";
        p.uid = uid;
        p.allowed = allowed;
        return p;
    }

    private static ResourceRecord rr(long time, String qname, String aname, String resource, int ttl) {
        ResourceRecord r = new ResourceRecord();
        r.Time = time;
        r.QName = qname;
        r.AName = aname;
        r.Resource = resource;
        r.TTL = ttl;
        r.uid = 1000;
        return r;
    }
}
