/*
 * Copyright (C)2016 - SMBJ Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.hierynomus.smbj.smoke;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2CreateOptions;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.connection.LeaseEntry;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.File;

/**
 * Live directory-cache tests against the Samba 4.23.8 dir-lease server on .12 — the payoff:
 * (a) a repeated list() of an unchanged leased dir is served from cache (zero re-query);
 * (b) an external mutation breaks the lease, invalidating the cache so the next list() re-queries
 *     and reflects the change (the correctness invariant — never serve stale across a break).
 */
@org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable(named = "SMBJ_IT_HOST", matches = ".+")
public class DirectoryLeaseCacheIntegrationTest {
    private static String env(String k, String def) {
        String v = System.getenv(k);
        return (v == null || v.isEmpty()) ? def : v;
    }

    private static final String HOST = env("SMBJ_IT_HOST", "localhost");
    private static final int PORT = Integer.parseInt(env("SMBJ_IT_PORT", "1445"));
    private static final String USER = env("SMBJ_IT_USER", "smbj");
    private static final String PASS = env("SMBJ_IT_PASS", "changeit");
    private static final String SHARE = env("SMBJ_IT_SHARE", "testshare");

    private static AuthenticationContext ac() {
        return new AuthenticationContext(USER, PASS.toCharArray(), null);
    }

    private static final EnumSet<SMB2ShareAccess> SHARE_ALL =
        EnumSet.of(SMB2ShareAccess.FILE_SHARE_READ, SMB2ShareAccess.FILE_SHARE_WRITE, SMB2ShareAccess.FILE_SHARE_DELETE);

    @Test
    public void secondListOfUnchangedDirIsServedFromCache() throws Exception {
        SmbConfig config = SmbConfig.builder().withTimeout(10, TimeUnit.SECONDS).build();
        try (SMBClient client = new SMBClient(config);
             Connection conn = client.connect(HOST, PORT)) {
            assumeTrue(conn.getConnectionContext().supportsDirectoryLeasing(), "no directory leasing");
            try (Session session = conn.authenticate(ac());
                 DiskShare share = (DiskShare) session.connectShare(SHARE)) {

                List<FileIdBothDirectoryInformation> first = share.list("subdir"); // miss -> lease + populate
                LeaseEntry entry = conn.getLeaseManager().getByPath("subdir");
                assertThat(entry).as("a lease was acquired for the listed dir").isNotNull();
                assertThat(entry.getCache().getPopulates()).isEqualTo(1L);

                List<FileIdBothDirectoryInformation> second = share.list("subdir"); // HIT

                assertThat(entry.getCache().getServeHits()).as("second list served from cache").isEqualTo(1L);
                assertThat(entry.getCache().getPopulates()).as("no re-population => no re-query").isEqualTo(1L);
                assertThat(names(second)).isEqualTo(names(first));
            }
        }
    }

    @Test
    public void listAfterTheAppClosesItsOwnDirectoryHandleDoesNotReuseAClosedHandle() throws Exception {
        // Reproduces the Cyberduck pattern: the app opens a directory, CLOSES it, then lists.
        // The cache must use its own dedicated handle, not the app's closed one (else STATUS_FILE_CLOSED).
        SmbConfig config = SmbConfig.builder().withTimeout(10, TimeUnit.SECONDS).build();
        try (SMBClient client = new SMBClient(config);
             Connection conn = client.connect(HOST, PORT)) {
            assumeTrue(conn.getConnectionContext().supportsDirectoryLeasing(), "no directory leasing");
            try (Session session = conn.authenticate(ac());
                 DiskShare share = (DiskShare) session.connectShare(SHARE)) {

                com.hierynomus.smbj.share.Directory d = share.openDirectory("subdir",
                    EnumSet.of(AccessMask.GENERIC_READ), null, SHARE_ALL,
                    SMB2CreateDisposition.FILE_OPEN, EnumSet.noneOf(SMB2CreateOptions.class));
                d.close(); // app closes its handle (as Cyberduck does)

                List<FileIdBothDirectoryInformation> l1 = share.list("subdir"); // must not throw
                List<FileIdBothDirectoryInformation> l2 = share.list("subdir"); // cache hit
                assertThat(names(l2)).isEqualTo(names(l1));
            }
        }
    }

    @Test
    public void breakInvalidatesCacheSoNextListReflectsTheChange() throws Exception {
        SmbConfig config = SmbConfig.builder().withTimeout(10, TimeUnit.SECONDS).build();
        String probe = "added-by-b.txt";
        try (SMBClient client = new SMBClient(config);
             Connection connA = client.connect(HOST, PORT)) {
            assumeTrue(connA.getConnectionContext().supportsDirectoryLeasing(), "no directory leasing");
            try (Session sessA = connA.authenticate(ac());
                 DiskShare shareA = (DiskShare) sessA.connectShare(SHARE)) {

                List<FileIdBothDirectoryInformation> before = shareA.list(""); // populate root cache
                LeaseEntry root = connA.getLeaseManager().getByPath("");
                assertThat(root).isNotNull();
                shareA.list(""); // prove it's serving from cache now
                assertThat(root.getCache().getServeHits()).isGreaterThanOrEqualTo(1L);
                int breaks0 = connA.getLeaseManager().getBreaksHandled();

                // Connection B adds a file to the leased root -> server breaks A's lease.
                try (SMBClient clientB = new SMBClient(config);
                     Connection connB = clientB.connect(HOST, PORT);
                     Session sessB = connB.authenticate(ac());
                     DiskShare shareB = (DiskShare) sessB.connectShare(SHARE)) {
                    File f = shareB.openFile(probe, EnumSet.of(AccessMask.GENERIC_WRITE, AccessMask.DELETE), null,
                        SHARE_ALL, SMB2CreateDisposition.FILE_OVERWRITE_IF, EnumSet.noneOf(SMB2CreateOptions.class));
                    f.write("x".getBytes(), 0);
                    f.close();

                    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(8);
                    while (connA.getLeaseManager().getBreaksHandled() == breaks0 && System.nanoTime() < deadline) {
                        Thread.sleep(50);
                    }
                    assertThat(root.isBroken()).as("A's root lease broke").isTrue();

                    // The next list() must NOT serve the stale cache: it re-queries and sees the new file.
                    List<FileIdBothDirectoryInformation> afterBreak = shareA.list("");
                    assertThat(names(afterBreak)).as("post-break listing reflects the external change").contains(probe);
                    assertThat(afterBreak.size()).isEqualTo(before.size() + 1);

                    shareB.rm(probe);
                }
            }
        }
    }

    private static java.util.List<String> names(List<FileIdBothDirectoryInformation> l) {
        java.util.List<String> out = new java.util.ArrayList<>();
        for (FileIdBothDirectoryInformation f : l) {
            out.add(f.getFileName());
        }
        return out;
    }
}
