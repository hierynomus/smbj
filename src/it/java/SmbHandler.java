import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;

/**
 * Adapted from Jcifs SmbHandler
 */
public class SmbHandler extends URLStreamHandler {

    @Override
    protected URLConnection openConnection(URL u) throws IOException {
        throw new IOException("Not Supported ");
    }

    @Override
    protected void parseURL(URL u, String spec, int start, int limit) {
        String host = u.getHost();
        String path, ref;
        int port;

        if (spec.equals("smb://")) {
            spec = "smb:////";
            limit += 2;
        } else if (spec.startsWith("smb://") == false &&
                host != null && host.length() == 0) {
            spec = "//" + spec;
            limit += 2;
        }
        super.parseURL(u, spec, start, limit);
        path = u.getPath();
        ref = u.getRef();
        if (ref != null) {
            path += '#' + ref;
        }
        port = u.getPort();
        if (port == -1) {
            port = getDefaultPort();
        }
        setURL(u, "smb", u.getHost(), port,
                u.getAuthority(), u.getUserInfo(),
                path, u.getQuery(), null);
    }
}
