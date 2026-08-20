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
import com.hierynomus.smbj.share.File;

/**
 * Live lease-break test against the Samba 4.23.8 dir-lease server on .12. Holds an RH
 * directory lease on connection A, mutates the directory from connection B, and asserts A
 * receives + handles the break (connection survives, lease state drops, cache bumped).
 */
@org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable(named = "SMBJ_IT_HOST", matches = ".+")
public class DirectoryLeaseBreakIntegrationTest {
    private static String env(String k, String def) {
        String v = System.getenv(k);
        return (v == null || v.isEmpty()) ? def : v;
    }

    private static final String HOST = env("SMBJ_IT_HOST", "localhost");
    private static final int PORT = Integer.parseInt(env("SMBJ_IT_PORT", "1445"));
    private static final String USER = env("SMBJ_IT_USER", "smbj");
    private static final String PASS = env("SMBJ_IT_PASS", "changeit");
    private static final String SHARE = env("SMBJ_IT_SHARE", "testshare");

    private static final AuthenticationContext AC() {
        return new AuthenticationContext(USER, PASS.toCharArray(), null);
    }

    private static Directory openLeasedRoot(DiskShare share) {
        return share.openDirectory("",
            EnumSet.of(AccessMask.GENERIC_READ),
            null,
            EnumSet.of(SMB2ShareAccess.FILE_SHARE_READ, SMB2ShareAccess.FILE_SHARE_WRITE, SMB2ShareAccess.FILE_SHARE_DELETE),
            SMB2CreateDisposition.FILE_OPEN,
            EnumSet.noneOf(SMB2CreateOptions.class));
    }

    @Test
    public void anExternalMutationBreaksTheHeldDirectoryLease() throws Exception {
        SmbConfig config = SmbConfig.builder().withTimeout(10, TimeUnit.SECONDS).build();
        String probe = "break-probe.txt";

        try (SMBClient client = new SMBClient(config);
             Connection connA = client.connect(HOST, PORT)) {
            assumeTrue(connA.getConnectionContext().supportsDirectoryLeasing(), "no directory leasing");

            try (Session sessA = connA.authenticate(AC());
                 DiskShare shareA = (DiskShare) sessA.connectShare(SHARE);
                 Directory rootA = openLeasedRoot(shareA)) {

                LeaseEntry e = rootA.getLeaseEntry();
                assertThat(e).isNotNull();
                assertThat(SMB2LeaseState.isHandle(e.getGrantedState())).as("must hold H to be breakable").isTrue();
                int gen0 = e.getCacheGeneration();
                int breaks0 = connA.getLeaseManager().getBreaksHandled();

                // Connection B mutates the leased directory -> server breaks A's RH lease.
                try (SMBClient clientB = new SMBClient(config);
                     Connection connB = clientB.connect(HOST, PORT);
                     Session sessB = connB.authenticate(AC());
                     DiskShare shareB = (DiskShare) sessB.connectShare(SHARE)) {
                    File f = shareB.openFile(probe,
                        EnumSet.of(AccessMask.GENERIC_WRITE, AccessMask.DELETE),
                        null,
                        EnumSet.of(SMB2ShareAccess.FILE_SHARE_READ, SMB2ShareAccess.FILE_SHARE_WRITE, SMB2ShareAccess.FILE_SHARE_DELETE),
                        SMB2CreateDisposition.FILE_OVERWRITE_IF,
                        EnumSet.noneOf(SMB2CreateOptions.class));
                    f.write("x".getBytes(), 0);
                    f.close();

                    // Wait (no sleep-and-hope: poll a latching counter) for A to handle the break.
                    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(8);
                    while (connA.getLeaseManager().getBreaksHandled() == breaks0
                        && e.getCacheGeneration() == gen0
                        && System.nanoTime() < deadline) {
                        Thread.sleep(50);
                    }

                    assertThat(e.isBroken()).as("A's lease entry marked broken").isTrue();
                    assertThat(e.getCacheGeneration()).as("cache generation bumped (invalidation hook)").isGreaterThan(gen0);
                    assertThat(connA.getLeaseManager().getBreaksHandled()).isGreaterThan(breaks0);
                    // After a content break the H bit is dropped (RH -> R or NONE).
                    assertThat(SMB2LeaseState.isHandle(e.getGrantedState())).as("H dropped after break").isFalse();

                    shareB.rm(probe);
                }

                // Connection A survived the break and is still usable.
                assertThat(shareA.list("")).isNotNull();
            }
        }
    }
}
