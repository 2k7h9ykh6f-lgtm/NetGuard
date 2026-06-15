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
import static org.junit.Assert.assertTrue;

import android.app.Application;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;

import androidx.test.core.app.ApplicationProvider;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.lang.reflect.Field;

/**
 * Schema / migration tests for {@link DatabaseHelper}.
 * <p>
 * {@code onCreate} and {@code onUpgrade} are public overrides, so each test drives them directly
 * against a private in-memory {@link SQLiteDatabase} ({@code SQLiteDatabase.create(null)}). Every
 * test owns and closes its own database, giving complete isolation that is independent of test
 * order. The stock {@link Application} replaces {@code ApplicationEx} so no native library loads.
 * <p>
 * Note: {@code DatabaseHelper.onUpgrade} swallows internal failures (it catches {@link Throwable}
 * and only commits the transaction when the version reaches {@code DB_VERSION}); on failure the
 * transaction rolls back. These tests therefore assert the resulting schema directly rather than
 * relying on an exception, which is the only reliable signal of a broken migration step.
 */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34, application = Application.class)
public class DatabaseMigrationTest {

    private static final int DB_VERSION = 22;

    private DatabaseHelper helper;

    @Before
    public void setUp() throws Exception {
        resetSingleton();
        // onCreate/onUpgrade do not read instance state (prefs is only used by insertDns),
        // so a plain instance is enough to invoke the migration logic.
        helper = DatabaseHelper.getInstance(ApplicationProvider.getApplicationContext());
    }

    @After
    public void tearDown() throws Exception {
        resetSingleton();
    }

    @Test
    public void onCreate_createsAllTablesAndIndexes() {
        SQLiteDatabase db = SQLiteDatabase.create(null);
        try {
            helper.onCreate(db);

            for (String table : new String[]{"log", "access", "dns", "forward", "app"})
                assertTrue("missing table: " + table, tableExists(db, table));

            for (String index : new String[]{"idx_log_time", "idx_access", "idx_dns", "idx_forward", "idx_package"})
                assertTrue("missing index: " + index, indexExists(db, index));

            // Current schema includes dns.uid (added at version 22).
            assertTrue(columnExists(db, "dns", "uid"));
        } finally {
            db.close();
        }
    }

    @Test
    public void onUpgrade_from13To22_addsTablesAndColumns_andPreservesExistingData() {
        SQLiteDatabase db = SQLiteDatabase.create(null);
        try {
            // Simulate a version-13 database: only log + access exist; dns/forward/app do not yet.
            db.execSQL("CREATE TABLE log (ID INTEGER PRIMARY KEY AUTOINCREMENT, time INTEGER NOT NULL, daddr TEXT)");
            db.execSQL("CREATE TABLE access (ID INTEGER PRIMARY KEY AUTOINCREMENT)");
            db.execSQL("INSERT INTO log (time, daddr) VALUES (123, '1.2.3.4')"); // pre-existing user data
            db.setVersion(13);

            helper.onUpgrade(db, 13, DB_VERSION);

            // Tables introduced along the 13 -> 22 path.
            assertTrue("dns created (v14)", tableExists(db, "dns"));
            assertTrue("forward created (v16)", tableExists(db, "forward"));
            assertTrue("app created (v21)", tableExists(db, "app"));

            // Columns added by later upgrade steps.
            assertTrue("access.sent (v17)", columnExists(db, "access", "sent"));
            assertTrue("access.received (v17)", columnExists(db, "access", "received"));
            assertTrue("access.connections (v19)", columnExists(db, "access", "connections"));
            assertTrue("dns.uid (v22)", columnExists(db, "dns", "uid"));

            // The log table is never dropped on this path, so existing rows survive the migration.
            try (Cursor c = db.rawQuery("SELECT COUNT(*) FROM log", null)) {
                assertTrue(c.moveToFirst());
                assertEquals(1, c.getInt(0));
            }
        } finally {
            db.close();
        }
    }

    @Test
    public void onUpgrade_recreatesMissingTable() {
        SQLiteDatabase db = SQLiteDatabase.create(null);
        try {
            // Simulate a version-20 database whose 'app' table is absent (e.g. a partially applied
            // schema). dns exists but without the uid column (its pre-v22 shape).
            db.execSQL("CREATE TABLE dns (" +
                    " ID INTEGER PRIMARY KEY AUTOINCREMENT" +
                    ", time INTEGER NOT NULL" +
                    ", qname TEXT NOT NULL" +
                    ", aname TEXT NOT NULL" +
                    ", resource TEXT NOT NULL" +
                    ", ttl INTEGER" +
                    ");");
            db.setVersion(20);

            assertFalse("precondition: app table absent", tableExists(db, "app"));
            assertFalse("precondition: dns.uid absent", columnExists(db, "dns", "uid"));

            helper.onUpgrade(db, 20, DB_VERSION);

            assertTrue("missing app table recreated by upgrade", tableExists(db, "app"));
            assertTrue("dns.uid added by upgrade", columnExists(db, "dns", "uid"));
        } finally {
            db.close();
        }
    }

    @Test
    public void onUpgrade_columnAddIsIdempotentWhenColumnAlreadyExists() {
        SQLiteDatabase db = SQLiteDatabase.create(null);
        try {
            // Full current schema (dns.uid already present).
            helper.onCreate(db);
            assertTrue(columnExists(db, "dns", "uid"));

            // Re-applying the 21 -> 22 step must be safe: the columnExists() guard prevents a
            // "duplicate column" failure, leaving the dns table intact and queryable.
            helper.onUpgrade(db, 21, DB_VERSION);

            assertTrue(columnExists(db, "dns", "uid"));
            try (Cursor c = db.rawQuery("SELECT uid FROM dns LIMIT 0", null)) {
                assertTrue(c.getColumnIndex("uid") >= 0);
            }
        } finally {
            db.close();
        }
    }

    // ----------------------------------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------------------------------

    private static void resetSingleton() throws Exception {
        Field dh = DatabaseHelper.class.getDeclaredField("dh");
        dh.setAccessible(true);
        dh.set(null, null);
    }

    private static boolean tableExists(SQLiteDatabase db, String name) {
        try (Cursor c = db.rawQuery(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?", new String[]{name})) {
            return c.getCount() > 0;
        }
    }

    private static boolean indexExists(SQLiteDatabase db, String name) {
        try (Cursor c = db.rawQuery(
                "SELECT name FROM sqlite_master WHERE type='index' AND name=?", new String[]{name})) {
            return c.getCount() > 0;
        }
    }

    private static boolean columnExists(SQLiteDatabase db, String table, String column) {
        // Use PRAGMA table_info rather than "SELECT * ... LIMIT 0": the latter is compiled and
        // cached per-connection by SQLiteDatabase, and Robolectric's SQLite does not invalidate
        // that cached statement after an "ALTER TABLE ... ADD COLUMN", so a column added by a
        // migration would be invisible to a repeated SELECT on the same in-memory connection.
        // PRAGMA reads the live schema and is immune to that staleness.
        try (Cursor c = db.rawQuery("PRAGMA table_info(" + table + ")", null)) {
            int nameIdx = c.getColumnIndexOrThrow("name");
            while (c.moveToNext())
                if (column.equals(c.getString(nameIdx)))
                    return true;
            return false;
        }
    }
}
