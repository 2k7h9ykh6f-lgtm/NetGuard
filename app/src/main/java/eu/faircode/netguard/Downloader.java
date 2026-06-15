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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;

// Pure (Android-free) download helpers extracted from DownloadTask so the
// stream-copy and HTTP-status logic can be unit tested on a plain JVM.
public class Downloader {

    public interface Cancel {
        boolean isCancelled();
    }

    public interface Progress {
        void onProgress(int percent);
    }

    // Throws when the server did not answer with HTTP 200, mirroring the
    // original DownloadTask behaviour (message = "<code> <reason>").
    public static void checkHttpResponse(int code, String message) throws IOException {
        if (code != HttpURLConnection.HTTP_OK)
            throw new IOException(code + " " + message);
    }

    // Copies in -> out until EOF or cancellation. Cancellation is checked
    // before each read; progress is reported only when contentLength is known
    // (> 0). Streams are NOT closed here (the caller owns them). Returns the
    // number of bytes copied.
    public static long copyStream(InputStream in, OutputStream out, int contentLength,
                                  Cancel cancel, Progress progress) throws IOException {
        long size = 0;
        byte[] buffer = new byte[4096];
        int bytes;
        while (!cancel.isCancelled() && (bytes = in.read(buffer)) != -1) {
            out.write(buffer, 0, bytes);

            size += bytes;
            if (contentLength > 0)
                progress.onProgress((int) (size * 100 / contentLength));
        }
        return size;
    }
}
