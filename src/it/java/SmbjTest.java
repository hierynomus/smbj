import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msdtyp.SID;
import com.hierynomus.msdtyp.SecurityDescriptor;
import com.hierynomus.msdtyp.SecurityInformation;
import com.hierynomus.msdtyp.ace.ACE;
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.msfscc.fileinformation.FileInfo;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.common.SMBApiException;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.Directory;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.smb2.SMB2CompletionFilter;
import com.hierynomus.smbj.smb2.SMB2CreateDisposition;
import com.hierynomus.smbj.smb2.SMB2ShareAccess;
import com.hierynomus.smbj.smb2.messages.SMB2ChangeNotifyRequest;
import com.hierynomus.smbj.smb2.messages.SMB2ChangeNotifyResponse;
import com.hierynomus.smbj.transport.TransportException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Future;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Integration test Pre-Req
 * <p>
 * Set the environment variable TEST_SMBJ_API_URL to an SMB URL,
 * smb://<host>/<sharepath>?[smbuser=user]&[smbpassword=pass]&[smbdomain=domain]
 * <p>
 * For eg.) smb://192.168.99.100/public?smbuser=u1&smbpassword=pass1&smbdomain=CORP
 */
public class SmbjTest {

    private static final Logger logger = LoggerFactory.getLogger(SmbjTest.class);

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    static ConnectInfo ci;
    String TEST_PATH = get("junit");

    @BeforeClass
    public static void setup() throws IOException {
        String url = System.getenv("TEST_SMBJ_API_URL");
        if (url == null) {
            url = "smb://<someip>/share?smbuser=<smbuser>&smbdomain=CORP&smbpassword=<smbpass>";
        }
        ci = getConnectInfo(url);
        System.out.printf("%s-%s-%s-%s-%s\n", ci.host, ci.domain, ci.user, ci.password, ci.sharePath);
    }

    @Test
    public void testBasic() throws IOException, SMBApiException, URISyntaxException {
        logger.info("Connect {},{},{},{}", ci.host, ci.user, ci.domain, ci.sharePath);
        SMBClient client = new SMBClient();
        Connection connection = client.connect(ci.host);
        AuthenticationContext ac = new AuthenticationContext(
                ci.user,
                ci.password == null ? new char[0] : ci.password.toCharArray(),
                ci.domain);
        Session session = connection.authenticate(ac);

        try (DiskShare share = (DiskShare)session.connectShare(ci.sharePath)) {
            try {
                share.rmdir(TEST_PATH, true);
            } catch (SMBApiException sae) {
                if (sae.getStatus() != NtStatus.STATUS_OBJECT_NAME_NOT_FOUND) {
                    throw sae;
                }
            }

            List<FileInfo> list = share.list(null);
            System.out.println(list);

            // Create it again
            share.mkdir(fix(TEST_PATH));
            share.mkdir(fix(TEST_PATH + "/1"));
            share.mkdir(fix(TEST_PATH + "/1/2"));
            share.mkdir(fix(TEST_PATH + "/1/2/3"));
            share.mkdir(fix(TEST_PATH + "/1/2/3/4"));
            share.mkdir(fix(TEST_PATH + "/2"));
            share.mkdir(fix(TEST_PATH + "/3"));
            share.mkdir(fix(TEST_PATH + "/4"));
            share.mkdir(fix(TEST_PATH + "/4/2"));
            share.mkdir(fix(TEST_PATH + "/4/2/3"));
            share.mkdir(fix(TEST_PATH + "/4/2/3/4"));

            assertTrue(share.folderExists(fix(TEST_PATH)));
            assertTrue(share.folderExists(fix(TEST_PATH + "/4/2/3/4")));
            try {
                share.fileExists(fix(TEST_PATH));
                fail(TEST_PATH + " is not a file");
            } catch (SMBApiException sae) {
                if (sae.getStatus() != NtStatus.STATUS_FILE_IS_A_DIRECTORY) {
                    throw sae;
                }
            }

            FileInfo fileInformation = share.getFileInformation(fix(TEST_PATH + "/4/2"));
            assertTrue(EnumWithValue.EnumUtils.isSet(
                    fileInformation.getFileAttributes(), FileAttributes.FILE_ATTRIBUTE_DIRECTORY));

            assertFilesInPathEquals(share, new String[]{"1", "2", "3", "4"}, fix(TEST_PATH));

            // Delete folder (Non recursive)
            share.rmdir(fix(TEST_PATH + "/2"), false);
            assertFilesInPathEquals(share, new String[]{"1", "3", "4"}, fix(TEST_PATH));

            // Delete folder (recursive)
            share.rmdir(fix(TEST_PATH + "/4"), true);
            assertFilesInPathEquals(share, new String[]{"1", "3"}, fix(TEST_PATH));


            // Upload 2 files
            String file1 = UUID.randomUUID().toString() + ".txt";
            String file2 = UUID.randomUUID().toString() + ".txt";
            String file3 = UUID.randomUUID().toString() + ".pdf";
            write(share, fix(TEST_PATH + "/1/" + file1), "testfiles/medium.txt");
            write(share, fix(TEST_PATH + "/1/2/3/" + file2), "testfiles/small.txt");
            write(share, fix(TEST_PATH + "/1/2/3/" + file3), "testfiles/large.pdf");

            assertFilesInPathEquals(share, new String[]{file2, file3, "4"}, fix(TEST_PATH +
                    "/1/2/3"));

            fileInformation = share.getFileInformation(fix(TEST_PATH + "/1/2/3/" +
                    file3));
            assertTrue(!EnumWithValue.EnumUtils.isSet(
                    fileInformation.getFileAttributes(), FileAttributes.FILE_ATTRIBUTE_DIRECTORY));

            try {
                share.folderExists(fix(TEST_PATH + "/1/2/3/" + file2));
                fail(TEST_PATH + " is not a folder");
            } catch (SMBApiException sae) {
                if (sae.getStatus() != NtStatus.STATUS_NOT_A_DIRECTORY) {
                    throw sae;
                }
            }

            //Delete
            share.rm(fix(TEST_PATH + "/1/2/3/" + file2));
            assertFilesInPathEquals(share, new String[]{"4", file3}, fix(TEST_PATH + "/1/2/3"));

            // Download and compare with originals
            File tmpFile1 = File.createTempFile("smbj", "junit");
            try (OutputStream os = new FileOutputStream(tmpFile1)) {
                share.read(fix(TEST_PATH + "/1/" + file1), os, null);
            }
            assertFileContent("testfiles/medium.txt", tmpFile1.getAbsolutePath());

            SecurityDescriptor sd = share.getSecurityInfo(fix(TEST_PATH + "/1/" +
                            file1),
                    EnumSet.of
                            (SecurityInformation
                                            .OWNER_SECURITY_INFORMATION,
                                    SecurityInformation.GROUP_SECURITY_INFORMATION,
                                    SecurityInformation.DACL_SECURITY_INFORMATION));
            assertTrue(sd.getControl().contains(SecurityDescriptor.Control.PS));
            assertTrue(sd.getControl().contains(SecurityDescriptor.Control.OD));
            assertNotNull(sd.getOwnerSid());
            assertNotNull(sd.getGroupSid());
            assertNotNull(sd.getDacl());
            assertNotNull(sd.getDacl().getAceCount() == sd.getDacl().getAces().length);

            System.out.println(sd);

            // Clean up
            share.rmdir(fix(TEST_PATH), true);
            assertFalse(share.folderExists(fix(TEST_PATH)));

            // Listing of the root directory.
            list = share.list(null);
            assertTrue(list.size() > 0);

        } finally {
            session.close();
        }
    }

    @Test
    public void testRpc() throws IOException, SMBApiException, URISyntaxException {
        logger.info("Connect {},{},{},{}", ci.host, ci.user, ci.domain, ci.sharePath);
        SMBClient client = new SMBClient();
        Connection connection = client.connect(ci.host);
        AuthenticationContext ac = new AuthenticationContext(
                ci.user,
                ci.password == null ? new char[0] : ci.password.toCharArray(),
                ci.domain);
        //TreeConnect smbTreeConnect = null;
        Session session = connection.authenticate(ac);

        try (DiskShare share = (DiskShare)session.connectShare(ci.sharePath)) {

            try {
                share.rmdir(TEST_PATH, true);
            } catch (SMBApiException sae) {
                if (sae.getStatus() != NtStatus.STATUS_OBJECT_NAME_NOT_FOUND) {
                    throw sae;
                }
            }

            share.mkdir(fix(TEST_PATH));
            share.mkdir(fix(TEST_PATH + "/DEV"));
            share.mkdir(fix(TEST_PATH + "/DEV/2"));

            String path = get(TEST_PATH, "DEV", "2");
            //String path = PathUtils.get("2");
            SecurityDescriptor sd = share.getSecurityInfo(path,
                    EnumSet.of(SecurityInformation.OWNER_SECURITY_INFORMATION,
                            SecurityInformation.GROUP_SECURITY_INFORMATION,
                            SecurityInformation.DACL_SECURITY_INFORMATION));
            System.out.println(sd.getOwnerSid());

            ACE[] aces = sd.getDacl().getAces();
            List<SID> sids = new ArrayList<>();
            sids.add(sd.getOwnerSid());
            sids.add(sd.getGroupSid());
            for(ACE ace: aces) {
                System.out.println(ace.getSid() + "-" + ace.getAceHeader());
                sids.add(ace.getSid());
            }
        } finally {
            session.close();
        }
    }


    //@Test
    public void manualTestNotify() throws IOException {

        logger.info("Connect {},{},{},{}", ci.host, ci.user, ci.domain, ci.sharePath);
        SMBClient client = new SMBClient();
        Connection connection = client.connect(ci.host);
        AuthenticationContext ac = new AuthenticationContext(
                ci.user,
                ci.password == null ? new char[0] : ci.password.toCharArray(),
                ci.domain);
        Session session = connection.authenticate(ac);

        try (DiskShare share = (DiskShare)session.connectShare(ci.sharePath)) {

            Directory fileHandle =
                    share.openDirectory(null,
                            EnumSet.of(AccessMask.FILE_LIST_DIRECTORY, AccessMask.FILE_READ_ATTRIBUTES),
                            EnumSet.of(SMB2ShareAccess.FILE_SHARE_DELETE, SMB2ShareAccess.FILE_SHARE_WRITE,
                                    SMB2ShareAccess.FILE_SHARE_READ),
                            SMB2CreateDisposition.FILE_OPEN);

            while (true) {
                List<SMB2ChangeNotifyResponse.FileNotifyInfo> notify = notify(share, fileHandle);
                System.out.println(notify);
            }
        }
    }

    List<SMB2ChangeNotifyResponse.FileNotifyInfo> notify(
            DiskShare share, Directory directory)
            throws TransportException, SMBApiException {

        int bufferLength = 64 * 1024;

        Session session = share.getTreeConnect().getSession();
        Connection connection = session.getConnection();

        SMB2ChangeNotifyRequest cnr = new SMB2ChangeNotifyRequest(
                connection.getNegotiatedDialect(),
                session.getSessionId(), share.getTreeConnect().getTreeId(),
                directory.getFileId(),
                EnumSet.of(
                        SMB2CompletionFilter.FILE_NOTIFY_CHANGE_FILE_NAME,
                        SMB2CompletionFilter.FILE_NOTIFY_CHANGE_DIR_NAME,
                        SMB2CompletionFilter.FILE_NOTIFY_CHANGE_ATTRIBUTES,
                        SMB2CompletionFilter.FILE_NOTIFY_CHANGE_CREATION,
//                                SMB2CompletionFilter.FILE_NOTIFY_CHANGE_SIZE,
                        SMB2CompletionFilter.FILE_NOTIFY_CHANGE_SECURITY,
                        SMB2CompletionFilter.FILE_NOTIFY_CHANGE_STREAM_SIZE,
                        SMB2CompletionFilter.FILE_NOTIFY_CHANGE_STREAM_WRITE),
                bufferLength, true);
        Future<SMB2ChangeNotifyResponse> changeNotifyResponseFuture = connection.send(cnr);

        SMB2ChangeNotifyResponse cnresponse = Futures.get(changeNotifyResponseFuture, TransportException.Wrapper);

        if (cnresponse.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
            throw new SMBApiException(cnresponse.getHeader().getStatus(), "Notify failed for " + directory);
        }

        return cnresponse.getFileNotifyInfoList();
    }


    // Caution load whole files into memory
    private void assertFileContent(String localResource, String downloadedFile)
            throws URISyntaxException, IOException {
        byte[] expectedBytes = Files.readAllBytes(Paths.get(this.getClass().getResource(localResource).toURI()));
        byte[] bytes = Files.readAllBytes(Paths.get(downloadedFile));
        assertArrayEquals(expectedBytes, bytes);
    }

    void write(DiskShare share, String remotePath, String localResource)
            throws IOException, SMBApiException {
        logger.debug("Writing {}, {} to {}", localResource, this.getClass().getResource(localResource), remotePath);
        try (InputStream is = this.getClass().getResourceAsStream(localResource)) {
            share.write(remotePath, true, is, null);
        }
    }

    private void assertFilesInPathEquals(DiskShare share, String[] expected, String path)
            throws SMBApiException, TransportException {
        List<FileInfo> list = share.list(path);
        String names[] = getNames(list);
        Arrays.sort(expected);
        Arrays.sort(names);
        assertArrayEquals(expected, names);
    }


    private String[] getNames(List<FileInfo> list) {
        String[] names = new String[list.size()];
        int idx = 0;
        for (FileInfo fi : list) {
            names[idx++] = fi.getFileName();
        }
        return names;
    }

    public static class ConnectInfo {
        public String host = null;
        public String domain = null;
        public String user = null;
        public String password = null;
        public String sharePath = null;
    }

    public static ConnectInfo getConnectInfo(String url) throws MalformedURLException, UnsupportedEncodingException {
        URL smbUrl = new URL(null, url, new SmbHandler());

        ConnectInfo ci = new ConnectInfo();
        ci.host = smbUrl.getHost();
        ci.sharePath = fix(smbUrl.getPath());

        Map<String, String> queryParams = splitQuery(smbUrl.getQuery());

        ci.domain = getArg("smbdomain", queryParams);
        ci.user = getArg("smbuser", queryParams);
        ci.password = getArg("smbpassword", queryParams);

        if (smbUrl.getUserInfo() != null) {
            String[] userInfoSplits = smbUrl.getUserInfo().split(":", 1);
            if (userInfoSplits.length >= 1) {
                if (ci.user == null) ci.user = userInfoSplits[0];
                if (userInfoSplits.length >= 2) {
                    if (ci.password == null) ci.password = userInfoSplits[1];
                }
            }
        }
        if (ci.domain == null) ci.domain = "?";

        return ci;
    }

    public static String fix(String s) {
        return s.replace('/', '\\');
    }

    public static String get(String first, String... more) {
        StringBuilder sb = new StringBuilder(first);
        for (int i = 0; i < more.length; i++) {
            sb.append('\\');
            sb.append(more[i]);
        }
        return sb.toString();
    }

    public static Map<String, String> splitQuery(String query) throws UnsupportedEncodingException {
        if (query == null) return new HashMap<>();
        Map<String, String> query_pairs = new HashMap<String, String>();
        String[] pairs = query.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            query_pairs.put(URLDecoder.decode(pair.substring(0, idx), "UTF-8").toUpperCase(),
                    URLDecoder.decode(pair.substring(idx + 1), "UTF-8"));
        }
        return query_pairs;
    }

    private static String getArg(String name, Map<String, String> queryParams) {
        String val = queryParams.get(name.toUpperCase());
        if (val == null) {
            // Check in env
            val = System.getenv(name.toUpperCase());
            if (val == null) val = System.getenv(name);
        }
        return val;
    }
}
