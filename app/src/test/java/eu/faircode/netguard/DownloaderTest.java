package eu.faircode.netguard;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class DownloaderTest {

    private static final Downloader.Cancel NEVER = () -> false;

    // --- checkHttpResponse -------------------------------------------------

    @Test
    public void httpOkDoesNotThrow() throws IOException {
        Downloader.checkHttpResponse(200, "OK");
    }

    @Test
    public void httpNotFoundThrowsWithMessage() {
        try {
            Downloader.checkHttpResponse(404, "Not Found");
            fail("expected IOException");
        } catch (IOException ex) {
            assertEquals("404 Not Found", ex.getMessage());
        }
    }

    @Test
    public void httpServerErrorThrowsWithMessage() {
        try {
            Downloader.checkHttpResponse(500, "Internal Server Error");
            fail("expected IOException");
        } catch (IOException ex) {
            assertEquals("500 Internal Server Error", ex.getMessage());
        }
    }

    // --- copyStream --------------------------------------------------------

    @Test
    public void copiesAllBytesAndReportsProgress() throws IOException {
        byte[] data = new byte[1000];
        for (int i = 0; i < data.length; i++)
            data[i] = (byte) i;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        List<Integer> progress = new ArrayList<>();

        long size = Downloader.copyStream(
                new ByteArrayInputStream(data), out, data.length, NEVER, p -> progress.add(p));

        assertEquals(data.length, size);
        assertArrayEquals(data, out.toByteArray());
        assertFalse("progress should be reported", progress.isEmpty());
        assertEquals(Integer.valueOf(100), progress.get(progress.size() - 1));
    }

    @Test
    public void emptyInputCopiesNothingAndReportsNoProgress() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        List<Integer> progress = new ArrayList<>();

        long size = Downloader.copyStream(
                new ByteArrayInputStream(new byte[0]), out, 0, NEVER, p -> progress.add(p));

        assertEquals(0, size);
        assertEquals(0, out.size());
        assertTrue(progress.isEmpty());
    }

    @Test
    public void cancelledBeforeFirstReadCopiesNothing() throws IOException {
        byte[] data = new byte[8192];
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        List<Integer> progress = new ArrayList<>();

        long size = Downloader.copyStream(
                new ByteArrayInputStream(data), out, data.length, () -> true, p -> progress.add(p));

        assertEquals(0, size);
        assertEquals(0, out.size());
        assertTrue(progress.isEmpty());
    }

    @Test
    public void cancelledAfterFirstChunkStopsEarly() throws IOException {
        // 3 * 4096 forces more than one read from the 4096-byte buffer.
        byte[] data = new byte[4096 * 3];
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        final int[] calls = {0};
        // Returns false on the first check, true afterwards.
        Downloader.Cancel cancelAfterFirst = () -> calls[0]++ > 0;

        long size = Downloader.copyStream(
                new ByteArrayInputStream(data), out, data.length, cancelAfterFirst, p -> { });

        assertEquals(4096, size);
        assertEquals(4096, out.size());
    }

    @Test
    public void unknownContentLengthCopiesButSkipsProgress() throws IOException {
        byte[] data = new byte[2048];
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        List<Integer> progress = new ArrayList<>();

        long size = Downloader.copyStream(
                new ByteArrayInputStream(data), out, -1, NEVER, p -> progress.add(p));

        assertEquals(data.length, size);
        assertArrayEquals(data, out.toByteArray());
        assertTrue("no progress when content length unknown", progress.isEmpty());
    }
}
