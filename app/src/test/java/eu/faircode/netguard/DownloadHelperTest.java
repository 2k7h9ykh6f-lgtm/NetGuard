package eu.faircode.netguard;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import static org.junit.Assert.*;

/**
 * JVM unit tests for {@link DownloadHelper}.
 *
 * <p>Uses in-memory streams to exercise the download logic without real
 * HTTP connections, covering success, failure, cancellation, empty
 * responses, and progress reporting.</p>
 */
public class DownloadHelperTest {

    @Rule
    public TemporaryFolder tmpDir = new TemporaryFolder();

    // ========================================================================
    // Successful downloads
    // ========================================================================

    @Test
    public void downloadStream_success() throws Exception {
        byte[] data = "Hello, NetGuard!".getBytes();
        InputStream in = new ByteArrayInputStream(data);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        DownloadHelper.DownloadResult result = DownloadHelper.downloadStream(in, out, data.length, null);

        assertFalse(result.cancelled);
        assertEquals(data.length, result.bytesDownloaded);
        assertArrayEquals(data, out.toByteArray());
    }

    @Test
    public void downloadStream_largePayload() throws Exception {
        // 1 MB payload to exercise the 4 KB buffer loop
        byte[] data = new byte[1024 * 1024];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i & 0xFF);
        }
        InputStream in = new ByteArrayInputStream(data);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        DownloadHelper.DownloadResult result = DownloadHelper.downloadStream(in, out, data.length, null);

        assertFalse(result.cancelled);
        assertEquals(data.length, result.bytesDownloaded);
        assertArrayEquals(data, out.toByteArray());
    }

    @Test
    public void downloadStream_writesToFile() throws Exception {
        byte[] data = "file content here".getBytes();
        File dest = tmpDir.newFile("downloaded.txt");
        InputStream in = new ByteArrayInputStream(data);
        OutputStream out = new java.io.FileOutputStream(dest);

        DownloadHelper.DownloadResult result = DownloadHelper.downloadStream(in, out, data.length, null);
        out.close();

        assertFalse(result.cancelled);
        assertEquals(data.length, result.bytesDownloaded);

        // Verify file contents
        byte[] fileContent = new byte[data.length];
        FileInputStream fis = new FileInputStream(dest);
        fis.read(fileContent);
        fis.close();
        assertArrayEquals(data, fileContent);
    }

    // ========================================================================
    // Empty response
    // ========================================================================

    @Test
    public void downloadStream_emptyInput() throws Exception {
        InputStream in = new ByteArrayInputStream(new byte[0]);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        DownloadHelper.DownloadResult result = DownloadHelper.downloadStream(in, out, 0, null);

        assertFalse(result.cancelled);
        assertEquals(0, result.bytesDownloaded);
        assertEquals(0, out.size());
    }

    @Test
    public void downloadStream_emptyWithNegativeContentLength() throws Exception {
        InputStream in = new ByteArrayInputStream(new byte[0]);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        DownloadHelper.DownloadResult result = DownloadHelper.downloadStream(in, out, -1, null);

        assertFalse(result.cancelled);
        assertEquals(0, result.bytesDownloaded);
    }

    // ========================================================================
    // Cancellation
    // ========================================================================

    @Test
    public void downloadStream_cancelledBeforeFirstRead() throws Exception {
        byte[] data = "some data".getBytes();
        InputStream in = new ByteArrayInputStream(data);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        DownloadHelper.ProgressCallback callback = new DownloadHelper.ProgressCallback() {
            @Override
            public boolean isCancelled() {
                return true; // always cancelled
            }

            @Override
            public void onProgress(int percent) {
            }
        };

        DownloadHelper.DownloadResult result = DownloadHelper.downloadStream(in, out, data.length, callback);

        assertTrue(result.cancelled);
        // First read succeeds but cancellation is checked before writing
        // Actually, the read happens first, then cancellation check.
        // Let's verify: the loop does read -> check cancel -> write
        // So one chunk may have been read but cancel checked before write
    }

    @Test
    public void downloadStream_cancelledMidDownload() throws Exception {
        // 16 KB of data (4 reads with 4KB buffer)
        byte[] data = new byte[16384];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) 'A';
        }
        InputStream in = new ByteArrayInputStream(data);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        final int[] readCount = {0};
        DownloadHelper.ProgressCallback callback = new DownloadHelper.ProgressCallback() {
            @Override
            public boolean isCancelled() {
                readCount[0]++;
                // Cancel after second progress callback (after ~8KB)
                return readCount[0] >= 2;
            }

            @Override
            public void onProgress(int percent) {
            }
        };

        DownloadHelper.DownloadResult result = DownloadHelper.downloadStream(in, out, data.length, callback);

        assertTrue(result.cancelled);
        assertTrue(result.bytesDownloaded < data.length);
        assertTrue(result.bytesDownloaded > 0);
    }

    @Test
    public void downloadStream_notCancelledWithCallback() throws Exception {
        byte[] data = "test data for callback".getBytes();
        InputStream in = new ByteArrayInputStream(data);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        final int[] progressCalls = {0};
        final int[] lastProgress = {0};
        DownloadHelper.ProgressCallback callback = new DownloadHelper.ProgressCallback() {
            @Override
            public boolean isCancelled() {
                return false;
            }

            @Override
            public void onProgress(int percent) {
                progressCalls[0]++;
                lastProgress[0] = percent;
            }
        };

        DownloadHelper.DownloadResult result = DownloadHelper.downloadStream(in, out, data.length, callback);

        assertFalse(result.cancelled);
        assertEquals(data.length, result.bytesDownloaded);
        assertTrue(progressCalls[0] > 0);
        assertEquals(100, lastProgress[0]); // final progress should be 100%
    }

    // ========================================================================
    // Progress reporting
    // ========================================================================

    @Test
    public void downloadStream_progressWithKnownLength() throws Exception {
        // 8 KB of data = 2 buffer reads
        byte[] data = new byte[8192];
        InputStream in = new ByteArrayInputStream(data);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        final int[] progressValues = new int[10];
        final int[] progressIdx = {0};
        DownloadHelper.ProgressCallback callback = new DownloadHelper.ProgressCallback() {
            @Override
            public boolean isCancelled() {
                return false;
            }

            @Override
            public void onProgress(int percent) {
                if (progressIdx[0] < progressValues.length) {
                    progressValues[progressIdx[0]++] = percent;
                }
            }
        };

        DownloadHelper.downloadStream(in, out, data.length, callback);

        // Should have received 2 progress callbacks (one per buffer read)
        assertEquals(2, progressIdx[0]);
        assertEquals(50, progressValues[0]); // first 4KB = 50%
        assertEquals(100, progressValues[1]); // second 4KB = 100%
    }

    @Test
    public void downloadStream_noProgressWithUnknownLength() throws Exception {
        byte[] data = "some data".getBytes();
        InputStream in = new ByteArrayInputStream(data);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        final int[] progressCalls = {0};
        DownloadHelper.ProgressCallback callback = new DownloadHelper.ProgressCallback() {
            @Override
            public boolean isCancelled() {
                return false;
            }

            @Override
            public void onProgress(int percent) {
                progressCalls[0]++;
            }
        };

        // contentLength = -1 (unknown)
        DownloadHelper.downloadStream(in, out, -1, callback);

        assertEquals(0, progressCalls[0]);
    }

    @Test
    public void downloadStream_noProgressWithZeroContentLength() throws Exception {
        byte[] data = "some data".getBytes();
        InputStream in = new ByteArrayInputStream(data);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        final int[] progressCalls = {0};
        DownloadHelper.ProgressCallback callback = new DownloadHelper.ProgressCallback() {
            @Override
            public boolean isCancelled() {
                return false;
            }

            @Override
            public void onProgress(int percent) {
                progressCalls[0]++;
            }
        };

        // contentLength = 0 (unknown)
        DownloadHelper.downloadStream(in, out, 0, callback);

        assertEquals(0, progressCalls[0]);
    }

    // ========================================================================
    // I/O errors
    // ========================================================================

    @Test(expected = IOException.class)
    public void downloadStream_throwsOnReadError() throws Exception {
        InputStream failingIn = new InputStream() {
            @Override
            public int read() throws IOException {
                throw new IOException("Simulated read failure");
            }

            @Override
            public int read(byte[] b, int off, int len) throws IOException {
                throw new IOException("Simulated read failure");
            }
        };
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        DownloadHelper.downloadStream(failingIn, out, 100, null);
    }

    @Test(expected = IOException.class)
    public void downloadStream_throwsOnWriteError() throws Exception {
        byte[] data = "some data".getBytes();
        InputStream in = new ByteArrayInputStream(data);
        OutputStream failingOut = new OutputStream() {
            @Override
            public void write(int b) throws IOException {
                throw new IOException("Simulated write failure");
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                throw new IOException("Simulated write failure");
            }
        };

        DownloadHelper.downloadStream(in, failingOut, data.length, null);
    }

    // ========================================================================
    // Null callback
    // ========================================================================

    @Test
    public void downloadStream_nullCallbackWorks() throws Exception {
        byte[] data = "test".getBytes();
        InputStream in = new ByteArrayInputStream(data);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        DownloadHelper.DownloadResult result = DownloadHelper.downloadStream(in, out, data.length, null);

        assertFalse(result.cancelled);
        assertEquals(data.length, result.bytesDownloaded);
    }

    // ========================================================================
    // Exact buffer boundary
    // ========================================================================

    @Test
    public void downloadStream_exactBufferSize() throws Exception {
        // Exactly 4096 bytes = one full buffer read
        byte[] data = new byte[DownloadHelper.BUFFER_SIZE];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i & 0xFF);
        }
        InputStream in = new ByteArrayInputStream(data);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        final int[] progressCalls = {0};
        DownloadHelper.ProgressCallback callback = new DownloadHelper.ProgressCallback() {
            @Override
            public boolean isCancelled() {
                return false;
            }

            @Override
            public void onProgress(int percent) {
                progressCalls[0]++;
            }
        };

        DownloadHelper.DownloadResult result = DownloadHelper.downloadStream(in, out, data.length, callback);

        assertFalse(result.cancelled);
        assertEquals(data.length, result.bytesDownloaded);
        assertEquals(1, progressCalls[0]); // exactly one progress callback at 100%
    }

    @Test
    public void downloadStream_oneByteOverBuffer() throws Exception {
        // 4097 bytes = one full buffer + one byte
        byte[] data = new byte[DownloadHelper.BUFFER_SIZE + 1];
        InputStream in = new ByteArrayInputStream(data);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        DownloadHelper.DownloadResult result = DownloadHelper.downloadStream(in, out, data.length, null);

        assertFalse(result.cancelled);
        assertEquals(data.length, result.bytesDownloaded);
    }
}
