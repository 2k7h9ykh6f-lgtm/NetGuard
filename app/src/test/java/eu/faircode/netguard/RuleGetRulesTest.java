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
*/

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.robolectric.Shadows.shadowOf;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;

import androidx.preference.PreferenceManager;
import androidx.test.core.app.ApplicationProvider;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowPackageManager;
import org.robolectric.shadows.ShadowProcess;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Regression tests for {@link Rule#getRules(boolean, Context)}.
 *
 * <p>{@code getRules} combines the {@link PackageManager} package list, nine
 * {@link SharedPreferences} files, the {@code Util} system/internet/enabled probes, the
 * predefined-rules XML, a SQLite {@link DatabaseHelper}, {@code Process.myUid()} and a
 * locale-aware sort. The previous lack of coverage meant the displayed app list could
 * silently diverge from the rules actually applied. These tests pin that behaviour using
 * Robolectric with a fully synthetic {@link PackageManager} (no reliance on real installed
 * apps).</p>
 *
 * <p>Determinism notes:</p>
 * <ul>
 *   <li>{@code Rule} keeps static caches and {@code DatabaseHelper} is a process-wide
 *       singleton; both survive between tests in the same JVM, so {@link #setUp()} resets
 *       them (the singleton via reflection) to give every test a clean database.</li>
 *   <li>{@code Process.myUid()} is pinned to a small, non-special uid so that
 *       {@code userId == 0} and the synthetic kernel uids (root/mediaserver/...) resolve to
 *       their dedicated branches, and skip-self never removes a package we installed.</li>
 *   <li>The auto-installed app-under-test package is removed so it cannot pollute counts.</li>
 * </ul>
 */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = Build.VERSION_CODES.TIRAMISU) // 33: broadly supported by Robolectric; code still compiles against compileSdk 35
public class RuleGetRulesTest {

    private static final String INTERNET = "android.permission.INTERNET";

    // Synthetic packages getRules always injects (uids 0/1013/1020/1021/1051/9999 at userId 0).
    private static final Set<String> SYNTHETIC = new HashSet<>(Arrays.asList(
            "root", "android.media", "android.multicast", "android.gps", "android.dns", "nobody"));
    private static final int SYNTHETIC_COUNT = SYNTHETIC.size(); // 6

    private Context context;
    private PackageManager pm;
    private ShadowPackageManager spm;

    @Before
    public void setUp() throws Exception {
        context = ApplicationProvider.getApplicationContext();
        pm = context.getPackageManager();
        spm = shadowOf(pm);

        // ---- Reset cross-test static state (survives within a JVM / classloader) ----
        // DatabaseHelper singleton + one-time delete guard, so each test gets a fresh DB.
        setStatic(DatabaseHelper.class, "dh", null);
        setStatic(DatabaseHelper.class, "once", Boolean.FALSE);
        DatabaseHelper.clearCache(); // host-count cache (mapUidHosts)
        // Rule package/label/system/internet/enabled caches (also rebuilds dh + clears app table).
        Rule.clearCache(context);

        // ---- Deterministic identity ----
        ShadowProcess.setUid(1); // userId == 0; non-special; skip-self matches nothing we install
        spm.removePackage(context.getPackageName()); // drop the auto-installed app-under-test

        // ---- Baseline preferences: clear everything to fall back to code defaults ----
        clear(PreferenceManager.getDefaultSharedPreferences(context));
        for (String n : new String[]{"wifi", "other", "screen_wifi", "screen_other",
                "roaming", "lockdown", "apply", "notify"})
            clear(context.getSharedPreferences(n, Context.MODE_PRIVATE));
    }

    // ------------------------------------------------------------------ tests

    /**
     * Characterises the test environment: with {@code all=true} the result must be exactly the
     * packages we installed plus the six synthetic kernel uids, and never the app-under-test.
     * Acts as a guard for every count-based assertion below.
     */
    @Test
    public void environment_containsOnlySyntheticPlusInstalledPackages() {
        installApp("com.test.one", 10100, "One", false, true, true);
        installApp("com.test.two", 10200, "Two", false, true, true);

        List<Rule> all = Rule.getRules(true, context);

        Set<String> expected = new HashSet<>(SYNTHETIC);
        expected.add("com.test.one");
        expected.add("com.test.two");
        assertEquals("getRules(all=true) must return exactly our packages plus the synthetic ones",
                expected, packageNames(all));
        assertFalse("the app-under-test package must be excluded",
                packageNames(all).contains(context.getPackageName()));
    }

    /** A normal user app is visible by default and carries the preference-derived defaults. */
    @Test
    public void normalUserApp_isIncludedWithExpectedDefaults() {
        installApp("com.test.normal", 10100, "Normal App", false, true, true);

        List<Rule> rules = Rule.getRules(false, context);

        // Default filters (show_user=true, show_system=false) → only our user app, no synthetics.
        assertEquals(1, rules.size());
        Rule r = rules.get(0);
        assertEquals("com.test.normal", r.packageName);
        assertEquals("Normal App", r.name);
        assertEquals(10100, r.uid);
        assertFalse(r.system);
        assertTrue(r.internet);
        assertTrue(r.enabled);
        assertTrue(r.pkg);

        // Defaults derived from preferences (whitelist_* default true; screen_* default false).
        assertTrue(r.wifi_default);
        assertTrue(r.other_default);
        assertTrue(r.roaming_default);
        assertFalse(r.screen_wifi_default);
        assertFalse(r.screen_other_default);
        assertTrue(r.wifi_blocked);
        assertTrue(r.other_blocked);
        assertFalse("matches defaults with no hosts/lockdown → unchanged", r.changed);
    }

    /**
     * A system app is hidden under the default filters, becomes visible when {@code show_system}
     * is enabled, and is never blocked while {@code manage_system} is off.
     */
    @Test
    public void systemApp_hiddenByDefault_shownWhenShowSystemEnabled() {
        installApp("com.test.system", 10100, "System App", true, true, true);

        // Hidden by default.
        assertNull(find(Rule.getRules(false, context), "com.test.system"));
        assertEquals(0, Rule.getRules(false, context).size());

        // Shown when show_system=true; with manage_system=false it must stay unblocked.
        pref("show_system", true);
        pref("whitelist_wifi", true);
        pref("whitelist_other", true);

        List<Rule> shown = Rule.getRules(false, context);
        // Our system app + the six (also system) synthetics are now visible.
        assertEquals(1 + SYNTHETIC_COUNT, shown.size());

        Rule r = find(shown, "com.test.system");
        assertNotNull(r);
        assertTrue(r.system);
        assertFalse("system app must not be blocked while manage_system=false", r.wifi_blocked);
        assertFalse(r.other_blocked);
    }

    /** A disabled app is shown by default but filtered out when {@code show_disabled} is off. */
    @Test
    public void disabledApp_shownByDefault_hiddenWhenShowDisabledFalse() {
        installApp("com.test.disabled", 10100, "Disabled App", false, true, false);

        Rule r = find(Rule.getRules(false, context), "com.test.disabled");
        assertNotNull("disabled app visible while show_disabled=true (default)", r);
        assertFalse(r.enabled);

        pref("show_disabled", false);
        assertNull("disabled app hidden when show_disabled=false",
                find(Rule.getRules(false, context), "com.test.disabled"));
        assertEquals(0, Rule.getRules(false, context).size());
    }

    /** An app without INTERNET is shown by default but filtered when {@code show_nointernet} is off. */
    @Test
    public void noInternetApp_shownByDefault_hiddenWhenShowNoInternetFalse() {
        installApp("com.test.noint", 10100, "No Internet App", false, false, true);

        Rule r = find(Rule.getRules(false, context), "com.test.noint");
        assertNotNull("no-internet app visible while show_nointernet=true (default)", r);
        assertFalse(r.internet);

        pref("show_nointernet", false);
        assertNull("no-internet app hidden when show_nointernet=false",
                find(Rule.getRules(false, context), "com.test.noint"));
        assertEquals(0, Rule.getRules(false, context).size());
    }

    /** Default sort ("name") orders rules case-insensitively, ascending. */
    @Test
    public void rules_sortedByName_caseInsensitiveAscending() {
        pref("sort", "name");
        installApp("com.test.z", 10100, "Zebra", false, true, true);
        installApp("com.test.a", 10200, "alpha", false, true, true);
        installApp("com.test.m", 10300, "Mango", false, true, true);

        // all=true so ordering depends purely on name (not on the 'changed' flag).
        List<Rule> mine = onlyPackages(Rule.getRules(true, context),
                "com.test.z", "com.test.a", "com.test.m");
        assertEquals(Arrays.asList("alpha", "Mango", "Zebra"), names(mine));
    }

    /** Sort "uid" orders rules by ascending uid, independent of the display name. */
    @Test
    public void rules_sortedByUid_ascending() {
        pref("sort", "uid");
        // Labels are deliberately reverse to uid order, to prove uid (not name) drives the sort.
        installApp("com.test.high", 10300, "Aaa", false, true, true);
        installApp("com.test.low", 10100, "Zzz", false, true, true);
        installApp("com.test.mid", 10200, "Mmm", false, true, true);

        List<Rule> mine = onlyPackages(Rule.getRules(true, context),
                "com.test.high", "com.test.low", "com.test.mid");

        List<Integer> uids = new ArrayList<>();
        for (Rule r : mine) uids.add(r.uid);
        assertEquals(Arrays.asList(10100, 10200, 10300), uids);
        // Names follow uid order, confirming alphabetical order did not drive the sort.
        assertEquals(Arrays.asList("Zzz", "Mmm", "Aaa"), names(mine));
    }

    /** A global block default blocks a user app on both Wi-Fi and mobile. */
    @Test
    public void globalDefaultBlock_blocksUserAppOnBothNetworks() {
        pref("whitelist_wifi", true);
        pref("whitelist_other", true);
        installApp("com.test.app", 10100, "App", false, true, true);

        Rule r = find(Rule.getRules(false, context), "com.test.app");
        assertNotNull(r);
        assertTrue(r.wifi_default);
        assertTrue(r.other_default);
        assertTrue(r.wifi_blocked);
        assertTrue(r.other_blocked);
    }

    /**
     * Wi-Fi and mobile defaults are independent, and a per-package "wifi" override beats the
     * global Wi-Fi default while mobile keeps following its own default.
     */
    @Test
    public void perNetwork_allowWifi_denyOther_withPerPackageOverride() {
        pref("whitelist_wifi", false);  // allow on Wi-Fi by default
        pref("whitelist_other", true);  // block on mobile by default
        installApp("com.test.a", 10100, "A", false, true, true);
        installApp("com.test.b", 10200, "B", false, true, true);
        // Per-package override: force B blocked on Wi-Fi despite the global allow.
        override("wifi", "com.test.b", true);

        List<Rule> rules = Rule.getRules(false, context);
        Rule a = find(rules, "com.test.a");
        Rule b = find(rules, "com.test.b");
        assertNotNull(a);
        assertNotNull(b);

        // Global defaults reflected on the rule.
        assertFalse(a.wifi_default);
        assertTrue(a.other_default);

        // A follows globals → allowed on Wi-Fi, blocked on mobile.
        assertFalse(a.wifi_blocked);
        assertTrue(a.other_blocked);

        // B's Wi-Fi override wins; mobile still follows the global block.
        assertTrue(b.wifi_blocked);
        assertTrue(b.other_blocked);
    }

    /**
     * Predefined rules (res/xml/predefined.xml) override both the app type and the network
     * defaults: {@code com.android.chrome} is forced to a user app, and {@code com.google.android.gms}
     * keeps its predefined "not blocked" defaults even when the global default is block.
     */
    @Test
    public void predefinedRules_overrideTypeAndDefaults() {
        pref("whitelist_wifi", true);   // global default = block, so we can see predefined win
        pref("whitelist_other", true);

        // Installed as a system app, but predefined <type system="false"> forces it to user.
        installApp("com.android.chrome", 10100, "Chrome", true, true, true);
        // Predefined <wifi/other blocked="false"> overrides the global block default.
        installApp("com.google.android.gms", 10200, "GMS", false, true, true);

        List<Rule> rules = Rule.getRules(false, context);
        assertEquals(2, rules.size());

        Rule chrome = find(rules, "com.android.chrome");
        assertNotNull("predefined type=system:false makes Chrome a visible user app", chrome);
        assertFalse(chrome.system);

        Rule gms = find(rules, "com.google.android.gms");
        assertNotNull(gms);
        assertFalse(gms.wifi_default);
        assertFalse(gms.other_default);
        assertFalse(gms.wifi_blocked);
        assertFalse(gms.other_blocked);
    }

    // ---------------------------------------------------------------- helpers

    private static void setStatic(Class<?> cls, String field, Object value) throws Exception {
        Field f = cls.getDeclaredField(field);
        f.setAccessible(true);
        f.set(null, value);
    }

    private static void clear(SharedPreferences prefs) {
        prefs.edit().clear().commit();
    }

    private void pref(String key, boolean value) {
        PreferenceManager.getDefaultSharedPreferences(context).edit().putBoolean(key, value).commit();
    }

    private void pref(String key, String value) {
        PreferenceManager.getDefaultSharedPreferences(context).edit().putString(key, value).commit();
    }

    private void override(String prefsName, String pkg, boolean value) {
        context.getSharedPreferences(prefsName, Context.MODE_PRIVATE)
                .edit().putBoolean(pkg, value).commit();
    }

    /** Installs a fully synthetic package into the Robolectric {@link PackageManager}. */
    private void installApp(String pkg, int uid, String label,
                            boolean system, boolean internet, boolean enabled) {
        PackageInfo pi = new PackageInfo();
        pi.packageName = pkg;
        pi.versionName = "1.0";

        ApplicationInfo ai = new ApplicationInfo();
        ai.packageName = pkg;
        ai.uid = uid;
        ai.flags = system ? ApplicationInfo.FLAG_SYSTEM : 0;
        ai.enabled = enabled;
        ai.nonLocalizedLabel = label; // drives ApplicationInfo.loadLabel()
        pi.applicationInfo = ai;

        if (internet) {
            pi.requestedPermissions = new String[]{INTERNET};
            pi.requestedPermissionsFlags = new int[]{PackageInfo.REQUESTED_PERMISSION_GRANTED};
        }

        spm.installPackage(pi);
    }

    private static Rule find(List<Rule> rules, String pkg) {
        for (Rule r : rules)
            if (pkg.equals(r.packageName))
                return r;
        return null;
    }

    private static List<String> names(List<Rule> rules) {
        List<String> out = new ArrayList<>();
        for (Rule r : rules) out.add(r.name);
        return out;
    }

    private static List<Rule> onlyPackages(List<Rule> rules, String... pkgs) {
        Set<String> keep = new HashSet<>(Arrays.asList(pkgs));
        List<Rule> out = new ArrayList<>();
        for (Rule r : rules)
            if (keep.contains(r.packageName))
                out.add(r);
        return out;
    }

    private static Set<String> packageNames(List<Rule> rules) {
        Set<String> out = new HashSet<>();
        for (Rule r : rules) out.add(r.packageName);
        return out;
    }
}
