package eu.faircode.netguard;

/*
    Regression tests for Rule.getRules().

    Covers: normal/system/disabled/no-internet apps, global default
    Wi-Fi/mobile block, manage_system toggle, screen_on interaction,
    per-app Wi-Fi/mobile override, sort by name and UID, changed flag,
    predefined XML rules, related packages, and filtering with all=false.

    Uses Robolectric for Android framework fakes (PackageManager,
    SharedPreferences, SQLite) and ShadowPackageManager to install
    synthetic packages.  DatabaseHelper app-cache is pre-populated
    so that Rule's constructor never calls through to Util (which
    would require the native library).
*/

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;

import androidx.preference.PreferenceManager;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.Shadows;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowApplication;
import org.robolectric.shadows.ShadowPackageManager;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 33)
public class RuleTest {

    private Context context;
    private ShadowPackageManager shadowPm;
    private DatabaseHelper dh;

    // ---- constants for readability ----
    private static final boolean USER_APP   = false;
    private static final boolean SYSTEM_APP = true;

    // ===================================================================
    //  Setup
    // ===================================================================

    @Before
    public void setUp() throws Exception {
        context = RuntimeEnvironment.getApplication();
        shadowPm = Shadows.shadowOf(context.getPackageManager());

        // ---- Reset DatabaseHelper singleton via reflection ----
        // Robolectric creates a fresh SQLite environment per test,
        // so the old singleton's connection becomes stale.
        Field dhField = DatabaseHelper.class.getDeclaredField("dh");
        dhField.setAccessible(true);
        dhField.set(null, null);

        // ---- Clear Rule's static caches via reflection ----
        setStaticField(Rule.class, "cachePackageInfo", null);
        setStaticField(Rule.class, "cacheLabel", new HashMap<>());
        setStaticField(Rule.class, "cacheSystem", new HashMap<>());
        setStaticField(Rule.class, "cacheInternet", new HashMap<>());
        setStaticField(Rule.class, "cacheEnabled", new HashMap<>());

        // Obtain a fresh DatabaseHelper for this test
        dh = DatabaseHelper.getInstance(context);
        dh.clearApps();
        dh.clearAccess();
    }

    private static void setStaticField(Class<?> clazz, String fieldName, Object value)
            throws Exception {
        Field f = clazz.getDeclaredField(fieldName);
        f.setAccessible(true);
        f.set(null, value);
    }

    // ===================================================================
    //  Helpers
    // ===================================================================

    /**
     * Build a {@link PackageInfo}, register it with Robolectric's
     * ShadowPackageManager, and pre-populate the DatabaseHelper
     * app-cache so that Rule's constructor reads from the DB
     * instead of calling Util static methods.
     */
    private PackageInfo installPackage(String packageName, int uid,
                                       String label, boolean system,
                                       boolean internet, boolean enabled) {
        PackageInfo pi = new PackageInfo();
        pi.packageName = packageName;
        pi.versionCode = 1;
        pi.versionName = "1.0";

        pi.applicationInfo = new ApplicationInfo();
        pi.applicationInfo.packageName = packageName;
        pi.applicationInfo.uid = uid;
        pi.applicationInfo.icon = 0;
        pi.applicationInfo.nonLocalizedLabel = label;
        pi.applicationInfo.enabled = enabled;

        if (system) {
            pi.applicationInfo.flags |=
                    (ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP);
        }

        shadowPm.addPackage(pi);

        // Pre-populate DB cache → avoids Util native-method calls
        dh.addApp(packageName, label, system, internet, enabled);

        return pi;
    }

    /** Shortcut for an enabled user app with internet. */
    private PackageInfo installUserApp(String packageName, int uid,
                                       String label, boolean internet) {
        return installPackage(packageName, uid, label,
                USER_APP, internet, true);
    }

    /** Shortcut for an enabled system app with internet. */
    private PackageInfo installSystemApp(String packageName, int uid,
                                         String label, boolean internet) {
        return installPackage(packageName, uid, label,
                SYSTEM_APP, internet, true);
    }

    /** Return the named SharedPreferences (same as Context.getSharedPreferences). */
    private SharedPreferences prefs(String name) {
        return context.getSharedPreferences(name, Context.MODE_PRIVATE);
    }

    /** Return the default (PreferenceManager) SharedPreferences. */
    private SharedPreferences defaultPrefs() {
        return PreferenceManager.getDefaultSharedPreferences(context);
    }

    /** Convenience wrapper for Rule.getRules(all, context). */
    private List<Rule> getRules(boolean all) {
        return Rule.getRules(all, context);
    }

    /** Find a rule by packageName; returns null when absent. */
    private Rule findByPackage(List<Rule> rules, String packageName) {
        for (Rule r : rules) {
            if (packageName.equals(r.packageName))
                return r;
        }
        return null;
    }

    /** Find a rule by uid (first match). */
    private Rule findByUid(List<Rule> rules, int uid) {
        for (Rule r : rules) {
            if (r.uid == uid)
                return r;
        }
        return null;
    }

    /** Count how many rules have the given packageName. */
    private int countByPackage(List<Rule> rules, String packageName) {
        int n = 0;
        for (Rule r : rules) {
            if (packageName.equals(r.packageName))
                n++;
        }
        return n;
    }

    // ===================================================================
    //  1. Rule count – synthetic entries with all=true
    // ===================================================================

    @Test
    public void testGetRules_allTrue_includesSyntheticEntries() {
        // With no installed packages, getRules(all=true) should still
        // return the synthetic entries: root, mediaserver, multicast,
        // GPS daemon, DNS daemon, nobody.  Root may be skipped if
        // Process.myUid()==0 (Robolectric default), so 5 or 6.
        List<Rule> rules = getRules(true);

        assertNotNull(rules);
        assertTrue("Expected at least 5 synthetic entries, got " + rules.size(),
                rules.size() >= 5);
        assertTrue("Expected at most 6 synthetic entries, got " + rules.size(),
                rules.size() <= 6);

        // mediaserver (uid 1013) must always be present
        assertNotNull("mediaserver entry missing",
                findByUid(rules, 1013));
        // DNS daemon (uid 1051) must always be present
        assertNotNull("DNS daemon entry missing",
                findByUid(rules, 1051));
        // nobody (uid 9999) must always be present
        assertNotNull("nobody entry missing",
                findByUid(rules, 9999));
    }

    // ===================================================================
    //  2. Rule count – normal user apps appear with all=true
    // ===================================================================

    @Test
    public void testGetRules_allTrue_includesUserApps() {
        installUserApp("com.test.alpha", 10001, "Alpha", true);
        installUserApp("com.test.beta",  10002, "Beta",  true);

        List<Rule> rules = getRules(true);

        assertNotNull(findByPackage(rules, "com.test.alpha"));
        assertNotNull(findByPackage(rules, "com.test.beta"));
        // 2 user apps + synthetic entries (5-6)
        assertTrue("Expected >= 7 rules, got " + rules.size(),
                rules.size() >= 7);
    }

    // ===================================================================
    //  3. Filtering – system apps hidden by default (all=false)
    // ===================================================================

    @Test
    public void testGetRules_systemAppsHiddenByDefault() {
        installSystemApp("com.android.system", 10010, "System Svc", true);
        installUserApp("com.test.user",        10011, "My App",     true);

        // all=false with default prefs (show_system=false, show_user=true)
        List<Rule> rules = getRules(false);

        // System app should be filtered out
        assertTrue("System app should be hidden when show_system=false",
                findByPackage(rules, "com.android.system") == null);
        // User app should be visible
        assertNotNull("User app should be visible when show_user=true",
                findByPackage(rules, "com.test.user"));
    }

    // ===================================================================
    //  4. Filtering – system apps shown when show_system=true
    // ===================================================================

    @Test
    public void testGetRules_systemAppsShownWhenEnabled() {
        installSystemApp("com.android.system", 10010, "System Svc", true);

        defaultPrefs().edit().putBoolean("show_system", true).apply();

        List<Rule> rules = getRules(false);

        assertNotNull("System app should appear when show_system=true",
                findByPackage(rules, "com.android.system"));
    }

    // ===================================================================
    //  5. Filtering – disabled apps hidden when show_disabled=false
    // ===================================================================

    @Test
    public void testGetRules_disabledAppsHidden() {
        installPackage("com.test.disabled", 10020, "Disabled App",
                USER_APP, true, false);
        installPackage("com.test.enabled",  10021, "Enabled App",
                USER_APP, true, true);

        defaultPrefs().edit()
                .putBoolean("show_disabled", false)
                .apply();

        List<Rule> rules = getRules(false);

        assertTrue("Disabled app should be hidden",
                findByPackage(rules, "com.test.disabled") == null);
        assertNotNull("Enabled app should be visible",
                findByPackage(rules, "com.test.enabled"));
    }

    // ===================================================================
    //  6. Filtering – no-internet apps hidden when show_nointernet=false
    // ===================================================================

    @Test
    public void testGetRules_noInternetAppsHidden() {
        installUserApp("com.test.nonet",    10030, "No Net",   false);
        installUserApp("com.test.withnet",  10031, "With Net", true);

        defaultPrefs().edit()
                .putBoolean("show_nointernet", false)
                .apply();

        List<Rule> rules = getRules(false);

        assertTrue("No-internet app should be hidden",
                findByPackage(rules, "com.test.nonet") == null);
        assertNotNull("Internet app should be visible",
                findByPackage(rules, "com.test.withnet"));
    }

    // ===================================================================
    //  7. Default Wi-Fi blocked (whitelist_wifi=true)
    // ===================================================================

    @Test
    public void testGetRules_defaultWifiBlocked() {
        installUserApp("com.test.app", 10040, "TestApp", true);

        defaultPrefs().edit()
                .putBoolean("whitelist_wifi", true)  // block wifi by default
                .apply();

        List<Rule> rules = getRules(true);
        Rule rule = findByPackage(rules, "com.test.app");

        assertNotNull(rule);
        assertTrue("wifi_blocked should be true when whitelist_wifi=true",
                rule.wifi_blocked);
        assertTrue("wifi_default should be true",
                rule.wifi_default);
    }

    // ===================================================================
    //  8. Default Wi-Fi allowed (whitelist_wifi=false)
    // ===================================================================

    @Test
    public void testGetRules_defaultWifiAllowed() {
        installUserApp("com.test.app", 10041, "TestApp", true);

        // whitelist_wifi=false means wifi is allowed by default
        defaultPrefs().edit()
                .putBoolean("whitelist_wifi", false)
                .apply();

        List<Rule> rules = getRules(true);
        Rule rule = findByPackage(rules, "com.test.app");

        assertNotNull(rule);
        assertFalse("wifi_blocked should be false when whitelist_wifi=false",
                rule.wifi_blocked);
        assertFalse("wifi_default should be false",
                rule.wifi_default);
    }

    // ===================================================================
    //  9. Default mobile blocked (whitelist_other=true)
    // ===================================================================

    @Test
    public void testGetRules_defaultMobileBlocked() {
        installUserApp("com.test.app", 10050, "TestApp", true);

        defaultPrefs().edit()
                .putBoolean("whitelist_other", true)  // block mobile
                .apply();

        List<Rule> rules = getRules(true);
        Rule rule = findByPackage(rules, "com.test.app");

        assertNotNull(rule);
        assertTrue("other_blocked should be true when whitelist_other=true",
                rule.other_blocked);
        assertTrue("other_default should be true",
                rule.other_default);
    }

    // ===================================================================
    // 10. Default mobile allowed (whitelist_other=false)
    // ===================================================================

    @Test
    public void testGetRules_defaultMobileAllowed() {
        installUserApp("com.test.app", 10051, "TestApp", true);

        defaultPrefs().edit()
                .putBoolean("whitelist_other", false)
                .apply();

        List<Rule> rules = getRules(true);
        Rule rule = findByPackage(rules, "com.test.app");

        assertNotNull(rule);
        assertFalse("other_blocked should be false when whitelist_other=false",
                rule.other_blocked);
        assertFalse("other_default should be false",
                rule.other_default);
    }

    // ===================================================================
    // 11. System apps NOT blocked when manage_system=false
    // ===================================================================

    @Test
    public void testGetRules_systemAppNotBlockedWhenManageSystemFalse() {
        installSystemApp("com.android.sys", 10060, "SysApp", true);

        defaultPrefs().edit()
                .putBoolean("manage_system", false)
                .putBoolean("whitelist_wifi", true)   // would block user apps
                .putBoolean("whitelist_other", true)
                .apply();

        List<Rule> rules = getRules(true);
        Rule rule = findByPackage(rules, "com.android.sys");

        assertNotNull(rule);
        // Even though defaults say block, system apps are exempt
        assertFalse("System wifi should not be blocked when manage_system=false",
                rule.wifi_blocked);
        assertFalse("System mobile should not be blocked when manage_system=false",
                rule.other_blocked);
    }

    // ===================================================================
    // 12. System apps ARE blocked when manage_system=true
    // ===================================================================

    @Test
    public void testGetRules_systemAppBlockedWhenManageSystemTrue() {
        installSystemApp("com.android.sys", 10070, "SysApp", true);

        defaultPrefs().edit()
                .putBoolean("manage_system", true)
                .putBoolean("whitelist_wifi", true)
                .putBoolean("whitelist_other", true)
                .apply();

        List<Rule> rules = getRules(true);
        Rule rule = findByPackage(rules, "com.android.sys");

        assertNotNull(rule);
        assertTrue("System wifi should be blocked when manage_system=true",
                rule.wifi_blocked);
        assertTrue("System mobile should be blocked when manage_system=true",
                rule.other_blocked);
    }

    // ===================================================================
    // 13. screen_on=true enables screen_wifi / screen_other
    // ===================================================================

    @Test
    public void testGetRules_screenOnEnablesScreenBlocking() {
        installUserApp("com.test.app", 10080, "TestApp", true);

        defaultPrefs().edit()
                .putBoolean("screen_on", true)
                .putBoolean("screen_wifi", true)
                .putBoolean("screen_other", true)
                .apply();

        List<Rule> rules = getRules(true);
        Rule rule = findByPackage(rules, "com.test.app");

        assertNotNull(rule);
        assertTrue("screen_wifi should be true when screen_on=true and default is true",
                rule.screen_wifi);
        assertTrue("screen_other should be true when screen_on=true and default is true",
                rule.screen_other);
        assertTrue("screen_wifi_default should be true",
                rule.screen_wifi_default);
        assertTrue("screen_other_default should be true",
                rule.screen_other_default);
    }

    // ===================================================================
    // 14. screen_on=false disables screen_wifi / screen_other
    // ===================================================================

    @Test
    public void testGetRules_screenOffDisablesScreenBlocking() {
        installUserApp("com.test.app", 10081, "TestApp", true);

        defaultPrefs().edit()
                .putBoolean("screen_on", false)
                .putBoolean("screen_wifi", true)
                .putBoolean("screen_other", true)
                .apply();

        List<Rule> rules = getRules(true);
        Rule rule = findByPackage(rules, "com.test.app");

        assertNotNull(rule);
        assertFalse("screen_wifi should be false when screen_on=false",
                rule.screen_wifi);
        assertFalse("screen_other should be false when screen_on=false",
                rule.screen_other);
        // defaults are also ANDed with screen_on
        assertFalse("screen_wifi_default should be false when screen_on=false",
                rule.screen_wifi_default);
        assertFalse("screen_other_default should be false when screen_on=false",
                rule.screen_other_default);
    }

    // ===================================================================
    // 15. Per-app Wi-Fi override (block one app's Wi-Fi)
    // ===================================================================

    @Test
    public void testGetRules_perAppWifiBlocked() {
        installUserApp("com.test.a", 10090, "AppA", true);
        installUserApp("com.test.b", 10091, "AppB", true);

        // Global: wifi allowed
        defaultPrefs().edit()
                .putBoolean("whitelist_wifi", false)  // allow wifi by default
                .apply();

        // Per-app: block wifi for AppA only
        prefs("wifi").edit()
                .putBoolean("com.test.a", true)
                .apply();

        List<Rule> rules = getRules(true);

        Rule ruleA = findByPackage(rules, "com.test.a");
        Rule ruleB = findByPackage(rules, "com.test.b");

        assertNotNull(ruleA);
        assertNotNull(ruleB);
        assertTrue("AppA wifi should be blocked by per-app override",
                ruleA.wifi_blocked);
        assertFalse("AppB wifi should remain allowed (default)",
                ruleB.wifi_blocked);
    }

    // ===================================================================
    // 16. Per-app mobile override (block one app's mobile)
    // ===================================================================

    @Test
    public void testGetRules_perAppMobileBlocked() {
        installUserApp("com.test.a", 10100, "AppA", true);
        installUserApp("com.test.b", 10101, "AppB", true);

        // Global: mobile allowed
        defaultPrefs().edit()
                .putBoolean("whitelist_other", false)
                .apply();

        // Per-app: block mobile for AppA
        prefs("other").edit()
                .putBoolean("com.test.a", true)
                .apply();

        List<Rule> rules = getRules(true);

        Rule ruleA = findByPackage(rules, "com.test.a");
        Rule ruleB = findByPackage(rules, "com.test.b");

        assertNotNull(ruleA);
        assertNotNull(ruleB);
        assertTrue("AppA mobile should be blocked by per-app override",
                ruleA.other_blocked);
        assertFalse("AppB mobile should remain allowed (default)",
                ruleB.other_blocked);
    }

    // ===================================================================
    // 17. Per-app Wi-Fi allow override when global default is block
    // ===================================================================

    @Test
    public void testGetRules_perAppWifiAllowedWhenDefaultBlocked() {
        installUserApp("com.test.a", 10110, "AppA", true);

        // Global: wifi blocked
        defaultPrefs().edit()
                .putBoolean("whitelist_wifi", true)
                .apply();

        // Per-app: allow wifi for AppA
        prefs("wifi").edit()
                .putBoolean("com.test.a", false)
                .apply();

        List<Rule> rules = getRules(true);
        Rule ruleA = findByPackage(rules, "com.test.a");

        assertNotNull(ruleA);
        assertFalse("AppA wifi should be allowed by per-app override",
                ruleA.wifi_blocked);
        // wifi_default still reflects the global setting
        assertTrue("wifi_default should still be true",
                ruleA.wifi_default);
    }

    // ===================================================================
    // 18. Lockdown per-app flag
    // ===================================================================

    @Test
    public void testGetRules_lockdownPerApp() {
        installUserApp("com.test.lock", 10115, "LockApp", true);

        prefs("lockdown").edit()
                .putBoolean("com.test.lock", true)
                .apply();

        List<Rule> rules = getRules(true);
        Rule rule = findByPackage(rules, "com.test.lock");

        assertNotNull(rule);
        assertTrue("lockdown should be true for this app",
                rule.lockdown);
        // lockdown sets changed=true
        assertTrue("changed should be true when lockdown is on",
                rule.changed);
    }

    // ===================================================================
    // 19. Apply flag per-app (disable rule enforcement)
    // ===================================================================

    @Test
    public void testGetRules_applyFalsePerApp() {
        installUserApp("com.test.noapply", 10116, "NoApply", true);

        prefs("apply").edit()
                .putBoolean("com.test.noapply", false)
                .apply();

        List<Rule> rules = getRules(true);
        Rule rule = findByPackage(rules, "com.test.noapply");

        assertNotNull(rule);
        assertFalse("apply should be false for this app",
                rule.apply);
        // apply=false sets changed=true
        assertTrue("changed should be true when apply=false",
                rule.changed);
    }

    // ===================================================================
    // 20. Notify flag per-app
    // ===================================================================

    @Test
    public void testGetRules_notifyFalsePerApp() {
        installUserApp("com.test.silent", 10117, "Silent", true);

        prefs("notify").edit()
                .putBoolean("com.test.silent", false)
                .apply();

        List<Rule> rules = getRules(true);
        Rule rule = findByPackage(rules, "com.test.silent");

        assertNotNull(rule);
        assertFalse("notify should be false for this app",
                rule.notify);
    }

    // ===================================================================
    // 21. Sort by name (default)
    // ===================================================================

    @Test
    public void testGetRules_sortByName() {
        installUserApp("com.test.zebra", 10120, "Zebra", true);
        installUserApp("com.test.apple", 10121, "Apple", true);
        installUserApp("com.test.mango", 10122, "Mango", true);

        // Default sort is "name"
        defaultPrefs().edit().putString("sort", "name").apply();

        List<Rule> rules = getRules(true);

        // Find positions of our test apps in the sorted list
        int posApple = -1, posMango = -1, posZebra = -1;
        for (int i = 0; i < rules.size(); i++) {
            if ("com.test.apple".equals(rules.get(i).packageName))  posApple = i;
            if ("com.test.mango".equals(rules.get(i).packageName))  posMango = i;
            if ("com.test.zebra".equals(rules.get(i).packageName)) posZebra = i;
        }

        assertTrue("Apple should be present", posApple >= 0);
        assertTrue("Mango should be present", posMango >= 0);
        assertTrue("Zebra should be present", posZebra >= 0);
        assertTrue("Apple < Mango in name sort, but got Apple@" +
                posApple + " Mango@" + posMango, posApple < posMango);
        assertTrue("Mango < Zebra in name sort, but got Mango@" +
                posMango + " Zebra@" + posZebra, posMango < posZebra);
    }

    // ===================================================================
    // 22. Sort by UID
    // ===================================================================

    @Test
    public void testGetRules_sortByUid() {
        installUserApp("com.test.high", 20003, "High", true);
        installUserApp("com.test.low",  20001, "Low",  true);
        installUserApp("com.test.mid",  20002, "Mid",  true);

        defaultPrefs().edit().putString("sort", "uid").apply();

        List<Rule> rules = getRules(true);

        int posLow  = -1, posMid = -1, posHigh = -1;
        for (int i = 0; i < rules.size(); i++) {
            if ("com.test.low".equals(rules.get(i).packageName))  posLow  = i;
            if ("com.test.mid".equals(rules.get(i).packageName))  posMid  = i;
            if ("com.test.high".equals(rules.get(i).packageName)) posHigh = i;
        }

        assertTrue("Low UID app should be present", posLow >= 0);
        assertTrue("Mid UID app should be present", posMid >= 0);
        assertTrue("High UID app should be present", posHigh >= 0);
        assertTrue("Low UID < Mid UID in uid sort", posLow < posMid);
        assertTrue("Mid UID < High UID in uid sort", posMid < posHigh);
    }

    // ===================================================================
    // 23. Sort by name – changed rules appear first when all=false
    // ===================================================================

    @Test
    public void testGetRules_changedSortedFirstWhenAllFalse() {
        installUserApp("com.test.alpha", 10200, "Alpha", true);
        installUserApp("com.test.beta",  10201, "Beta",  true);

        defaultPrefs().edit()
                .putString("sort", "name")
                .putBoolean("whitelist_wifi", true)  // default: allowed
                .apply();

        // Override Alpha's wifi → changed=true
        prefs("wifi").edit()
                .putBoolean("com.test.alpha", false)
                .apply();

        // all=false → changed rules sort first
        List<Rule> rules = getRules(false);

        Rule alpha = findByPackage(rules, "com.test.alpha");
        Rule beta  = findByPackage(rules, "com.test.beta");

        assertNotNull(alpha);
        assertNotNull(beta);
        assertTrue("Alpha should be changed", alpha.changed);
        assertFalse("Beta should not be changed", beta.changed);

        int posAlpha = rules.indexOf(alpha);
        int posBeta  = rules.indexOf(beta);
        assertTrue("Changed rule (Alpha) should sort before unchanged (Beta)",
                posAlpha < posBeta);
    }

    // ===================================================================
    // 24. changed flag – matches default → not changed
    // ===================================================================

    @Test
    public void testGetRules_notChangedWhenMatchesDefault() {
        installUserApp("com.test.app", 10210, "TestApp", true);

        defaultPrefs().edit()
                .putBoolean("whitelist_wifi", false)
                .putBoolean("whitelist_other", false)
                .putBoolean("whitelist_roaming", true)
                .apply();

        List<Rule> rules = getRules(true);
        Rule rule = findByPackage(rules, "com.test.app");

        assertNotNull(rule);
        assertFalse("Rule matching defaults should not be changed",
                rule.changed);
    }

    // ===================================================================
    // 25. changed flag – differs from default → changed
    // ===================================================================

    @Test
    public void testGetRules_changedWhenDiffersFromDefault() {
        installUserApp("com.test.app", 10220, "TestApp", true);

        defaultPrefs().edit()
                .putBoolean("whitelist_wifi", false)   // default: allow
                .apply();

        // Override: block wifi for this app
        prefs("wifi").edit()
                .putBoolean("com.test.app", true)
                .apply();

        List<Rule> rules = getRules(true);
        Rule rule = findByPackage(rules, "com.test.app");

        assertNotNull(rule);
        assertTrue("Rule differing from default should be changed",
                rule.changed);
    }

    // ===================================================================
    // 26. Predefined – root wifi is always allowed
    // ===================================================================

    @Test
    public void testGetRules_predefinedRootWifiAllowed() {
        // The predefined.xml sets root wifi blocked=false
        List<Rule> rules = getRules(true);
        Rule root = findByPackage(rules, "root");

        if (root != null) {
            // Root may be skipped if Process.myUid()==0
            assertFalse("Root wifi should not be blocked (predefined)",
                    root.wifi_blocked);
            assertFalse("Root wifi_default should be false (predefined)",
                    root.wifi_default);
        }
    }

    // ===================================================================
    // 27. Predefined – root mobile is always allowed
    // ===================================================================

    @Test
    public void testGetRules_predefinedRootMobileAllowed() {
        List<Rule> rules = getRules(true);
        Rule root = findByPackage(rules, "root");

        if (root != null) {
            assertFalse("Root mobile should not be blocked (predefined)",
                    root.other_blocked);
            assertFalse("Root other_default should be false (predefined)",
                    root.other_default);
            assertFalse("Root roaming should be false (predefined)",
                    root.roaming);
        }
    }

    // ===================================================================
    // 28. Predefined – type override (Chrome marked as non-system)
    // ===================================================================

    @Test
    public void testGetRules_predefinedTypeOverride() {
        // predefined.xml marks com.android.chrome as system=false
        installSystemApp("com.android.chrome", 10300, "Chrome", true);

        List<Rule> rules = getRules(true);
        Rule chrome = findByPackage(rules, "com.android.chrome");

        assertNotNull(chrome);
        assertFalse("Chrome should be overridden to non-system by predefined",
                chrome.system);
    }

    // ===================================================================
    // 29. Related packages from predefined XML
    // ===================================================================

    @Test
    public void testGetRules_relatedPackagesFromPredefined() {
        // predefined.xml: com.android.vending is related to
        //   com.google.android.gms, com.android.providers.downloads
        installUserApp("com.android.vending", 10310, "Play Store", true);

        List<Rule> rules = getRules(true);
        Rule vending = findByPackage(rules, "com.android.vending");

        assertNotNull(vending);
        assertNotNull("related array should not be null",
                vending.related);
        assertTrue("related should contain at least 2 entries",
                vending.related.length >= 2);
    }

    // ===================================================================
    // 30. Related UIDs – shared UIDs detected
    // ===================================================================

    @Test
    public void testGetRules_sharedUidDetected() {
        int sharedUid = 10320;
        installUserApp("com.test.first",  sharedUid, "First",  true);
        installUserApp("com.test.second", sharedUid, "Second", true);

        List<Rule> rules = getRules(true);

        Rule first  = findByPackage(rules, "com.test.first");
        Rule second = findByPackage(rules, "com.test.second");

        assertNotNull(first);
        assertNotNull(second);
        assertTrue("First should have relateduids=true",
                first.relateduids);
        assertTrue("Second should have relateduids=true",
                second.relateduids);
        // Each should list the other's packageName in related[]
        boolean firstHasSecond  = false;
        boolean secondHasFirst  = false;
        for (String r : first.related)
            if ("com.test.second".equals(r)) firstHasSecond = true;
        for (String r : second.related)
            if ("com.test.first".equals(r)) secondHasFirst = true;
        assertTrue("First's related should contain Second", firstHasSecond);
        assertTrue("Second's related should contain First", secondHasFirst);
    }

    // ===================================================================
    // 31. Roaming default from SharedPreferences
    // ===================================================================

    @Test
    public void testGetRules_roamingDefault() {
        installUserApp("com.test.app", 10330, "TestApp", true);

        defaultPrefs().edit()
                .putBoolean("whitelist_roaming", false)
                .apply();

        List<Rule> rules = getRules(true);
        Rule rule = findByPackage(rules, "com.test.app");

        assertNotNull(rule);
        assertFalse("roaming should be false when whitelist_roaming=false",
                rule.roaming);
        assertFalse("roaming_default should be false",
                rule.roaming_default);
    }

    // ===================================================================
    // 32. Per-app roaming override
    // ===================================================================

    @Test
    public void testGetRules_perAppRoamingOverride() {
        installUserApp("com.test.app", 10340, "TestApp", true);

        defaultPrefs().edit()
                .putBoolean("whitelist_roaming", true)
                .apply();

        // Per-app: disable roaming
        prefs("roaming").edit()
                .putBoolean("com.test.app", false)
                .apply();

        List<Rule> rules = getRules(true);
        Rule rule = findByPackage(rules, "com.test.app");

        assertNotNull(rule);
        assertFalse("roaming should be false via per-app override",
                rule.roaming);
        assertTrue("roaming_default should still be true",
                rule.roaming_default);
    }

    // ===================================================================
    // 33. Hosts count sets changed flag
    // ===================================================================

    @Test
    public void testGetRules_hostsSetChangedFlag() {
        installUserApp("com.test.hosts", 10350, "HostApp", true);

        // We can't easily insert into the access table through the
        // public API, but we can verify that hosts=0 → not changed
        // (when everything else matches defaults).
        defaultPrefs().edit()
                .putBoolean("whitelist_wifi", true)
                .putBoolean("whitelist_other", true)
                .apply();

        List<Rule> rules = getRules(true);
        Rule rule = findByPackage(rules, "com.test.hosts");

        assertNotNull(rule);
        assertEquals("hosts should be 0 for fresh install", 0, rule.hosts);
    }

    // ===================================================================
    // 34. all=true includes everything regardless of filters
    // ===================================================================

    @Test
    public void testGetRules_allTrueIncludesEverything() {
        // Install a system app, a disabled app, a no-internet app
        installSystemApp("com.test.sys", 10400, "Sys",     true);
        installPackage("com.test.dis",  10401, "Dis",
                USER_APP, true,  false);
        installPackage("com.test.noio", 10402, "NoIO",
                USER_APP, false, true);

        // Set restrictive filters
        defaultPrefs().edit()
                .putBoolean("show_system", false)
                .putBoolean("show_disabled", false)
                .putBoolean("show_nointernet", false)
                .apply();

        // all=true should include everything
        List<Rule> allRules = getRules(true);
        assertNotNull(findByPackage(allRules, "com.test.sys"));
        assertNotNull(findByPackage(allRules, "com.test.dis"));
        assertNotNull(findByPackage(allRules, "com.test.noio"));

        // all=false should exclude them
        List<Rule> filtered = getRules(false);
        assertTrue("System app hidden with all=false",
                findByPackage(filtered, "com.test.sys") == null);
        assertTrue("Disabled app hidden with all=false",
                findByPackage(filtered, "com.test.dis") == null);
        assertTrue("No-internet app hidden with all=false",
                findByPackage(filtered, "com.test.noio") == null);
    }

    // ===================================================================
    // 35. Field correctness – verify all key fields on a single rule
    // ===================================================================

    @Test
    public void testGetRules_fieldCorrectness() {
        installUserApp("com.test.full", 10500, "FullTest", true);

        defaultPrefs().edit()
                .putBoolean("whitelist_wifi", true)
                .putBoolean("whitelist_other", false)
                .putBoolean("whitelist_roaming", true)
                .putBoolean("screen_on", true)
                .putBoolean("screen_wifi", false)
                .putBoolean("screen_other", true)
                .apply();

        List<Rule> rules = getRules(true);
        Rule rule = findByPackage(rules, "com.test.full");

        assertNotNull(rule);
        assertEquals("uid mismatch", 10500, rule.uid);
        assertEquals("packageName mismatch", "com.test.full", rule.packageName);
        assertEquals("name mismatch", "FullTest", rule.name);
        assertFalse("should not be system", rule.system);
        assertTrue("should have internet", rule.internet);
        assertTrue("should be enabled", rule.enabled);
        assertTrue("pkg should be true for real packages", rule.pkg);

        // Defaults
        assertTrue("wifi_default", rule.wifi_default);
        assertFalse("other_default", rule.other_default);
        assertFalse("screen_wifi_default", rule.screen_wifi_default);
        assertTrue("screen_other_default", rule.screen_other_default);
        assertTrue("roaming_default", rule.roaming_default);

        // Actual values
        assertTrue("wifi_blocked should follow default (whitelist_wifi=true→blocked)",
                rule.wifi_blocked);
        assertFalse("other_blocked should follow default (whitelist_other=false→not blocked)",
                rule.other_blocked);
        assertFalse("screen_wifi should be false",
                rule.screen_wifi);
        assertTrue("screen_other should be true",
                rule.screen_other);
        assertTrue("roaming should follow default",
                rule.roaming);
        assertFalse("lockdown default is false",
                rule.lockdown);
        assertTrue("apply default is true",
                rule.apply);
        assertTrue("notify default is true",
                rule.notify);
    }

    // ===================================================================
    // 36. changed flag – roaming difference sets changed
    // ===================================================================

    @Test
    public void testGetRules_roamingDifferenceSetsChanged() {
        installUserApp("com.test.app", 10510, "TestApp", true);

        defaultPrefs().edit()
                .putBoolean("whitelist_wifi", true)
                .putBoolean("whitelist_other", false)
                .putBoolean("whitelist_roaming", true)
                .apply();

        // Per-app: roaming differs from default
        prefs("roaming").edit()
                .putBoolean("com.test.app", false)
                .apply();

        List<Rule> rules = getRules(true);
        Rule rule = findByPackage(rules, "com.test.app");

        assertNotNull(rule);
        assertTrue("changed should be true when roaming differs from default",
                rule.changed);
    }

    // ===================================================================
    // 37. Synthetic entries have correct properties
    // ===================================================================

    @Test
    public void testGetRules_syntheticEntryProperties() {
        List<Rule> rules = getRules(true);

        // Check mediaserver (uid=1013)
        Rule media = findByUid(rules, 1013);
        if (media != null) {
            assertEquals("mediaserver packageName", "android.media", media.packageName);
            assertTrue("mediaserver should be system", media.system);
            assertTrue("mediaserver should have internet", media.internet);
            assertTrue("mediaserver should be enabled", media.enabled);
            assertFalse("mediaserver pkg should be false", media.pkg);
        }

        // Check DNS daemon (uid=1051)
        Rule dns = findByUid(rules, 1051);
        assertNotNull("DNS daemon should always be present", dns);
        assertEquals("dns packageName", "android.dns", dns.packageName);
        assertTrue("dns should be system", dns.system);
        assertTrue("dns should have internet", dns.internet);
        assertFalse("dns pkg should be false", dns.pkg);

        // Check nobody (uid=9999)
        Rule nobody = findByUid(rules, 9999);
        assertNotNull("nobody should always be present", nobody);
        assertEquals("nobody packageName", "nobody", nobody.packageName);
        assertTrue("nobody should be system", nobody.system);
        assertFalse("nobody pkg should be false", nobody.pkg);
    }

    // ===================================================================
    // 38. Wi-Fi and mobile independently configured
    // ===================================================================

    @Test
    public void testGetRules_wifiAndMobileIndependent() {
        installUserApp("com.test.app", 10520, "TestApp", true);

        // Global: wifi allowed (will override per-app), mobile allowed
        defaultPrefs().edit()
                .putBoolean("whitelist_wifi", false)
                .putBoolean("whitelist_other", false)
                .apply();

        // Per-app: block wifi but allow mobile
        prefs("wifi").edit().putBoolean("com.test.app", true).apply();
        // mobile: leave as default (allowed)

        List<Rule> rules = getRules(true);
        Rule rule = findByPackage(rules, "com.test.app");

        assertNotNull(rule);
        assertTrue("wifi should be blocked", rule.wifi_blocked);
        assertFalse("mobile should be allowed", rule.other_blocked);
    }

    // ===================================================================
    // 39. Multiple apps with same name sorted by packageName
    // ===================================================================

    @Test
    public void testGetRules_sameNameSortedByPackageName() {
        // Two apps with the same display name
        installUserApp("com.zzz.app", 10530, "SameName", true);
        installUserApp("com.aaa.app", 10531, "SameName", true);

        defaultPrefs().edit().putString("sort", "name").apply();

        List<Rule> rules = getRules(true);

        int posZzz = -1, posAaa = -1;
        for (int i = 0; i < rules.size(); i++) {
            if ("com.zzz.app".equals(rules.get(i).packageName)) posZzz = i;
            if ("com.aaa.app".equals(rules.get(i).packageName)) posAaa = i;
        }

        assertTrue("com.aaa.app should be present", posAaa >= 0);
        assertTrue("com.zzz.app should be present", posZzz >= 0);
        // When names are identical, tiebreak is packageName (lexicographic)
        assertTrue("com.aaa.app should sort before com.zzz.app",
                posAaa < posZzz);
    }

    // ===================================================================
    // 40. Per-app screen_wifi override
    // ===================================================================

    @Test
    public void testGetRules_perAppScreenWifiOverride() {
        installUserApp("com.test.app", 10540, "TestApp", true);

        defaultPrefs().edit()
                .putBoolean("screen_on", true)
                .putBoolean("screen_wifi", false)   // default: off
                .apply();

        // Per-app: enable screen_wifi
        prefs("screen_wifi").edit()
                .putBoolean("com.test.app", true)
                .apply();

        List<Rule> rules = getRules(true);
        Rule rule = findByPackage(rules, "com.test.app");

        assertNotNull(rule);
        assertTrue("screen_wifi should be true via per-app override",
                rule.screen_wifi);
        assertFalse("screen_wifi_default should be false",
                rule.screen_wifi_default);
    }

    // ===================================================================
    // 41. Predefined – wifi blocked override for a known package
    // ===================================================================

    @Test
    public void testGetRules_predefinedWifiBlockedForKnownPackage() {
        // predefined.xml sets wifi blocked=false for several Google pkgs.
        // Let's verify that for com.google.android.gms the wifi_default
        // is overridden to false (not blocked) even if global default is true.
        installUserApp("com.google.android.gms", 10550, "GMS", true);

        defaultPrefs().edit()
                .putBoolean("whitelist_wifi", true)
                .apply();

        List<Rule> rules = getRules(true);
        Rule gms = findByPackage(rules, "com.google.android.gms");

        assertNotNull(gms);
        // predefined sets blocked=false → wifi_default=false
        assertFalse("GMS wifi_default should be false (predefined override)",
                gms.wifi_default);
    }

    // ===================================================================
    // 42. Verify rule count matches expectations
    // ===================================================================

    @Test
    public void testGetRules_exactRuleCount() {
        installUserApp("com.test.one", 10601, "One", true);
        installUserApp("com.test.two", 10602, "Two", true);
        installUserApp("com.test.three", 10603, "Three", true);

        List<Rule> rules = getRules(true);

        // 3 user apps + 5 or 6 synthetic entries (root may be skipped)
        int syntheticCount = rules.size() - 3;
        assertTrue("Synthetic entries should be 5 or 6, got " + syntheticCount,
                syntheticCount == 5 || syntheticCount == 6);

        // Verify all 3 user apps are present
        assertEquals("Should find exactly 1 rule for com.test.one",
                1, countByPackage(rules, "com.test.one"));
        assertEquals("Should find exactly 1 rule for com.test.two",
                1, countByPackage(rules, "com.test.two"));
        assertEquals("Should find exactly 1 rule for com.test.three",
                1, countByPackage(rules, "com.test.three"));
    }

    // ===================================================================
    // 43. UID sort – synthetic entries come before user apps
    // ===================================================================

    @Test
    public void testGetRules_uidSort_syntheticBeforeUser() {
        installUserApp("com.test.app", 20000, "UserApp", true);

        defaultPrefs().edit().putString("sort", "uid").apply();

        List<Rule> rules = getRules(true);

        // Find the user app position
        int userPos = -1;
        for (int i = 0; i < rules.size(); i++) {
            if ("com.test.app".equals(rules.get(i).packageName)) {
                userPos = i;
                break;
            }
        }
        assertTrue("User app should be present", userPos >= 0);

        // All synthetic entries have UID < 20000, so they should come before
        // Verify that at least the first few rules have UID < 20000
        if (userPos > 0) {
            assertTrue("First rule UID should be < 20000",
                    rules.get(0).uid < 20000);
        }
    }

    // ===================================================================
    // 44. Default apply and notify are true
    // ===================================================================

    @Test
    public void testGetRules_defaultApplyAndNotifyTrue() {
        installUserApp("com.test.app", 10700, "TestApp", true);

        List<Rule> rules = getRules(true);
        Rule rule = findByPackage(rules, "com.test.app");

        assertNotNull(rule);
        assertTrue("apply should default to true", rule.apply);
        assertTrue("notify should default to true", rule.notify);
    }

    // ===================================================================
    // 45. No-internet app included with all=true
    // ===================================================================

    @Test
    public void testGetRules_noInternetIncludedWithAll() {
        installUserApp("com.test.noio", 10800, "NoIO", false);

        List<Rule> rules = getRules(true);
        Rule rule = findByPackage(rules, "com.test.noio");

        assertNotNull("No-internet app should be included with all=true", rule);
        assertFalse("internet should be false", rule.internet);
    }

    // ===================================================================
    // 46. Version field populated from PackageInfo
    // ===================================================================

    @Test
    public void testGetRules_versionFieldPopulated() {
        installUserApp("com.test.app", 10900, "TestApp", true);

        List<Rule> rules = getRules(true);
        Rule rule = findByPackage(rules, "com.test.app");

        assertNotNull(rule);
        assertEquals("version should be '1.0' from our test helper",
                "1.0", rule.version);
    }
}
