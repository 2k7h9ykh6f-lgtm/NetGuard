package eu.faircode.netguard;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URLConnection;

/**
 * Pure-Java helper that encapsulates the core download-stream logic from
 * {@link DownloadTask#doInBackground}, extracted so that it can be tested
 * with fake streams and without Android framework dependencies.
 */
public final class DownloadHelper {

    /** Default buffer size matching the original DownloadTask (4 KB). */
    public static final int BUFFER_SIZE = 4096;

    private DownloadHelper() {
    }

    /**
     * Callback for reporting download progress and cancellation.
     */
    public interface ProgressCallback {
        /** @return {@code true} if the download should be cancelled */
        boolean isCancelled();

        /**
         * Called periodically with the download progress percentage (0-100).
         * Only called when the content length is known.
         */
        void onProgress(int percent);
    }

    /**
     * Result of a download operation.
     */
    public static class DownloadResult {
        /** Total bytes downloaded. */
        public final long bytesDownloaded;
        /** Whether the download was cancelled. */
        public final boolean cancelled;

        public DownloadResult(long bytesDownloaded, boolean cancelled) {
            this.bytesDownloaded = bytesDownloaded;
            this.cancelled = cancelled;
        }
    }

    /**
     * Validate an HTTP connection, throwing an {@link IOException} if the
     * response code is not 200 OK.
     *
     * @param connection the HTTP connection to validate
     * @throws IOException if the response code is not 200
     */
    public static void validateHttpResponse(HttpURLConnection connection) throws IOException {
        if (connection != null) {
            int code = connection.getResponseCode();
            if (code != HttpURLConnection.HTTP_OK) {
                throw new IOException(code + " " + connection.getResponseMessage());
            }
        }
    }

    /**
     * Copy bytes from an {@link InputStream} to an {@link OutputStream},
     * reporting progress and checking for cancellation.
     *
     * @param in            the source stream
     * @param out           the destination stream
     * @param contentLength the expected content length ({@code -1} or
     *                      {@code 0} if unknown)
     * @param callback      optional progress/cancellation callback (may be
     *                      {@code null})
     * @return a {@link DownloadResult} with the outcome
     * @throws IOException if an I/O error occurs during reading or writing
     */
    public static DownloadResult downloadStream(InputStream in, OutputStream out,
                                                 int contentLength,
                                                 ProgressCallback callback) throws IOException {
        long size = 0;
        byte[] buffer = new byte[BUFFER_SIZE];
        int bytes;

        while ((bytes = in.read(buffer)) != -1) {
            // Check cancellation before writing
            if (callback != null && callback.isCancelled()) {
                return new DownloadResult(size, true);
            }

            out.write(buffer, 0, bytes);
            size += bytes;

            if (contentLength > 0 && callback != null) {
                int percent = (int) (size * 100 / contentLength);
                callback.onProgress(percent);
            }
        }

        return new DownloadResult(size, false);
    }

    /**
     * Perform a full download from a {@link URLConnection}, including HTTP
     * validation, stream copy, and resource cleanup.
     *
     * @param connection the URL connection (already connected)
     * @param out        the destination stream
     * @param callback   optional progress/cancellation callback
     * @return a {@link DownloadResult}
     * @throws IOException if validation or I/O fails
     */
    public static DownloadResult downloadFromConnection(URLConnection connection,
                                                         OutputStream out,
                                                         ProgressCallback callback) throws IOException {
        if (connection instanceof HttpURLConnection) {
            validateHttpResponse((HttpURLConnection) connection);
        }

        int contentLength = connection.getContentLength();
        InputStream in = null;
        try {
            in = connection.getInputStream();
            return downloadStream(in, out, contentLength, callback);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ignored) {
                }
            }
            if (connection instanceof HttpURLConnection) {
                ((HttpURLConnection) connection).disconnect();
            }
        }
    }
}
