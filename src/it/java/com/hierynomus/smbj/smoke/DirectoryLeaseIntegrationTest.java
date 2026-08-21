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
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2CreateOptions;
import com.hierynomus.mssmb2.SMB2LeaseState;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.connection.LeaseEntry;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.Directory;
import com.hierynomus.smbj.share.DiskShare;

/**
 * Live directory-lease tests against the Samba 4.23.8 dir-lease server on .12.
 * Run: SMBJ_IT_HOST=localhost ./gradlew integrationTest --tests "*DirectoryLeaseIntegrationTest"
 */
@org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable(named = "SMBJ_IT_HOST", matches = ".+")
public class DirectoryLeaseIntegrationTest {
    private static String env(String k, String def) {
        String v = System.getenv(k);
        return (v == null || v.isEmpty()) ? def : v;
    }

    private static final String HOST = env("SMBJ_IT_HOST", "localhost");
    private static final int PORT = Integer.parseInt(env("SMBJ_IT_PORT", "1445"));
    private static final String USER = env("SMBJ_IT_USER", "smbj");
    private static final String PASS = env("SMBJ_IT_PASS", "changeit");
    private static final String SHARE = env("SMBJ_IT_SHARE", "testshare");

    private interface Body {
        void run(Connection conn, DiskShare share) throws Exception;
    }

    private void withShare(Body body) throws Exception {
        SmbConfig config = SmbConfig.builder().withTimeout(10, TimeUnit.SECONDS).build();
        try (SMBClient client = new SMBClient(config);
             Connection conn = client.connect(HOST, PORT)) {
            assumeTrue(conn.getConnectionContext().supportsDirectoryLeasing(),
                "server does not advertise directory leasing");
            AuthenticationContext ac = new AuthenticationContext(USER, PASS.toCharArray(), null);
            try (Session session = conn.authenticate(ac);
                 DiskShare share = (DiskShare) session.connectShare(SHARE)) {
                body.run(conn, share);
            }
        }
    }

    private static Directory openDir(DiskShare share, String path) {
        return share.openDirectory(path,
            EnumSet.of(AccessMask.GENERIC_READ),
            null,
            EnumSet.of(SMB2ShareAccess.FILE_SHARE_READ, SMB2ShareAccess.FILE_SHARE_WRITE),
            SMB2CreateDisposition.FILE_OPEN,
            EnumSet.noneOf(SMB2CreateOptions.class));
    }

    @Test
    public void rootOpenIsGrantedAnRhDirectoryLease() throws Exception {
        withShare((conn, share) -> {
            try (Directory root = openDir(share, "")) {
                LeaseEntry e = root.getLeaseEntry();
                assertThat(e).as("a lease entry must be attached").isNotNull();
                assertThat(e.isGranted()).as("the lease must be granted").isTrue();
                long state = e.getGrantedState();
                assertThat(SMB2LeaseState.isRead(state)).as("granted READ_CACHING").isTrue();
                assertThat(SMB2LeaseState.isHandle(state)).as("granted HANDLE_CACHING (RH)").isTrue();
                assertThat(SMB2LeaseState.isWrite(state)).as("directory lease never gets WRITE").isFalse();
                // register-before-send held: the registry resolves the key to this entry
                assertThat(conn.getLeaseManager().lookup(e.getLeaseKey())).isSameAs(e);
            }
        });
    }

    @Test
    public void subdirOpenThreadsTheRootLeaseKeyAsParent() throws Exception {
        withShare((conn, share) -> {
            try (Directory root = openDir(share, "")) {
                LeaseEntry re = root.getLeaseEntry();
                assertThat(re).isNotNull();
                try (Directory sub = openDir(share, "subdir")) {
                    LeaseEntry se = sub.getLeaseEntry();
                    assertThat(se).isNotNull();
                    assertThat(se.isGranted()).isTrue();
                    assertThat(se.getParentLeaseKey())
                        .as("subdir's ParentLeaseKey == root dir's own lease key")
                        .isEqualTo(re.getLeaseKey());
                }
            }
        });
    }
}
