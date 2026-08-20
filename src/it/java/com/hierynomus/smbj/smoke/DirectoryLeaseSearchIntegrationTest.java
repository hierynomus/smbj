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

import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;

import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;

/**
 * Reproduces a recursive search ("find all file_8.dat") over testshare/benchtree, with directory
 * leasing ON vs OFF, to check whether the lease cache drops results during a recursive walk.
 * Writes a report to /tmp/smbj-search.txt. Run:
 *   SMBJ_IT_HOST=localhost ./gradlew integrationTest --tests "*DirectoryLeaseSearchIntegrationTest"
 */
@org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable(named = "SMBJ_IT_HOST", matches = ".+")
public class DirectoryLeaseSearchIntegrationTest {
    private static String env(String k, String def) {
        String v = System.getenv(k);
        return (v == null || v.isEmpty()) ? def : v;
    }

    private static final String HOST = env("SMBJ_IT_HOST", "localhost");
    private static final int PORT = Integer.parseInt(env("SMBJ_IT_PORT", "1445"));
    private static final String USER = env("SMBJ_IT_USER", "smbj");
    private static final String PASS = env("SMBJ_IT_PASS", "changeit");
    private static final String SHARE = env("SMBJ_IT_SHARE", "testshare");
    private static final String TREE = env("SMBJ_BENCH_ROOT", "benchtree");
    private static final String NEEDLE = env("SMBJ_SEARCH_NEEDLE", "file_8.dat");

    @Test
    public void recursiveSearchFindsTheSameWithLeaseOnAndOff() throws Exception {
        long[] on = walkCount(true);
        long[] off = walkCount(false);
        String msg = String.format(
            "recursive search '%s' under %s%n  lease ON : dirs=%d files=%d matches=%d%n  lease OFF: dirs=%d files=%d matches=%d%n  => %s%n",
            NEEDLE, TREE, on[0], on[1], on[2], off[0], off[1], off[2],
            (on[2] == off[2] && on[1] == off[1]) ? "MATCH (lease cache does not drop results)"
                : "MISMATCH — lease cache is dropping results!");
        try {
            java.nio.file.Files.write(java.nio.file.Paths.get("/tmp/smbj-search.txt"), msg.getBytes());
        } catch (Exception ignore) {
        }
        System.out.println(msg);
        org.junit.jupiter.api.Assertions.assertEquals(off[2], on[2], "match count differs between lease on/off");
        org.junit.jupiter.api.Assertions.assertEquals(off[1], on[1], "file count differs between lease on/off");
    }

    /** @return {dirs, files, matches} from a recursive walk. */
    private long[] walkCount(boolean leasing) throws Exception {
        SmbConfig config = SmbConfig.builder().withTimeout(30, TimeUnit.SECONDS)
            .withDirectoryLeasingEnabled(leasing).build();
        long dirs = 0, files = 0, matches = 0;
        try (SMBClient client = new SMBClient(config);
             Connection conn = client.connect(HOST, PORT)) {
            assumeTrue(!leasing || conn.getConnectionContext().supportsDirectoryLeasing(), "no directory leasing");
            try (Session session = conn.authenticate(new AuthenticationContext(USER, PASS.toCharArray(), null));
                 DiskShare share = (DiskShare) session.connectShare(SHARE)) {
                Deque<String> stack = new ArrayDeque<>();
                stack.push(TREE);
                while (!stack.isEmpty()) {
                    String dir = stack.pop();
                    dirs++;
                    List<FileIdBothDirectoryInformation> entries = share.list(dir);
                    for (FileIdBothDirectoryInformation e : entries) {
                        String name = e.getFileName();
                        if (".".equals(name) || "..".equals(name)) {
                            continue;
                        }
                        boolean isDir = (e.getFileAttributes() & FileAttributes.FILE_ATTRIBUTE_DIRECTORY.getValue()) != 0;
                        if (isDir) {
                            stack.push(dir + "\\" + name);
                        } else {
                            files++;
                            if (name.equals(NEEDLE)) {
                                matches++;
                            }
                        }
                    }
                }
            }
        }
        return new long[]{dirs, files, matches};
    }
}
