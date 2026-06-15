package eu.faircode.netguard;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/**
 * Unit tests for {@link Allowed} — pure Java POJO, no Android dependencies.
 */
public class AllowedTest {

    @Test
    public void defaultConstructor_nullAddressZeroPort() {
        Allowed a = new Allowed();
        assertNull(a.raddr);
        assertEquals(0, a.rport);
    }

    @Test
    public void parameterizedConstructor_setsFields() {
        Allowed a = new Allowed("192.168.1.100", 8080);
        assertEquals("192.168.1.100", a.raddr);
        assertEquals(8080, a.rport);
    }

    @Test
    public void fieldMutation_works() {
        Allowed a = new Allowed();
        a.raddr = "10.0.0.1";
        a.rport = 443;
        assertEquals("10.0.0.1", a.raddr);
        assertEquals(443, a.rport);
    }
}
