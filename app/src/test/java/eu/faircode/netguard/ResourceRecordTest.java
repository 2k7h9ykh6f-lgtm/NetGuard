package eu.faircode.netguard;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for {@link ResourceRecord} — pure Java POJO, no Android dependencies.
 */
public class ResourceRecordTest {

    @Test
    public void defaultConstructor_fieldsInitialized() {
        ResourceRecord rr = new ResourceRecord();
        assertEquals(0, rr.Time);
        assertEquals(null, rr.QName);
        assertEquals(null, rr.AName);
        assertEquals(null, rr.Resource);
        assertEquals(0, rr.TTL);
        assertEquals(0, rr.uid);
    }

    @Test
    public void fieldAssignment_roundTrips() {
        ResourceRecord rr = new ResourceRecord();
        long now = System.currentTimeMillis();
        rr.Time = now;
        rr.QName = "example.com";
        rr.AName = "example.com";
        rr.Resource = "93.184.216.34";
        rr.TTL = 3600;
        rr.uid = 10086;

        assertEquals(now, rr.Time);
        assertEquals("example.com", rr.QName);
        assertEquals("example.com", rr.AName);
        assertEquals("93.184.216.34", rr.Resource);
        assertEquals(3600, rr.TTL);
        assertEquals(10086, rr.uid);
    }

    @Test
    public void toString_containsKeyFields() {
        ResourceRecord rr = new ResourceRecord();
        rr.Time = 1700000000000L;
        rr.QName = "test.example.com";
        rr.AName = "test.example.com";
        rr.Resource = "1.2.3.4";
        rr.TTL = 300;
        rr.uid = 1000;

        String str = rr.toString();
        assertNotNull(str);
        assertTrue(str.contains("test.example.com"));
        assertTrue(str.contains("1.2.3.4"));
        assertTrue(str.contains("300"));
        assertTrue(str.contains("1000"));
    }
}
