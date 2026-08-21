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

import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.LeasedDirectoryCache;

/**
 * Directory-lease performance benchmark over a deep tree (testshare/benchtree on .12).
 * Matrix: new server + lease ON / new server + lease OFF / old (lease-unaware) server.
 * Gated on SMBJ_BENCH=1 so it never runs in the normal IT suite. Results are written to
 * /tmp/smbj-bench.txt (gradle swallows forked-JVM stdout).
 *
 * Run:
 *   SMBJ_BENCH=1 SMBJ_IT_HOST=localhost ./gradlew integrationTest --tests "*DirectoryLeaseBenchmarkTest"
 */
@org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable(named = "SMBJ_IT_HOST", matches = ".+")
public class DirectoryLeaseBenchmarkTest {
    private static String env(String k, String def) {
        String v = System.getenv(k);
        return (v == null || v.isEmpty()) ? def : v;
    }

    private static final String HOST = env("SMBJ_IT_HOST", "localhost");
    private static final int NEW_PORT = Integer.parseInt(env("SMBJ_BENCH_NEW_PORT", "1445"));
    private static final int OLD_PORT = Integer.parseInt(env("SMBJ_BENCH_OLD_PORT", "1446"));
    private static final String USER = env("SMBJ_IT_USER", "smbj");
    private static final String PASS = env("SMBJ_IT_PASS", "changeit");
    private static final String SHARE = env("SMBJ_IT_SHARE", "testshare");
    private static final String TREE = env("SMBJ_BENCH_ROOT", "benchtree");
    private static final int WARM_ROUNDS = Integer.parseInt(env("SMBJ_BENCH_WARM_ROUNDS", "3"));

    private static final StringBuilder OUT = new StringBuilder();

    private static void line(String s) {
        OUT.append(s).append('\n');
    }

    @Test
    public void benchmark() throws Exception {
        assumeTrue("1".equals(System.getenv("SMBJ_BENCH")), "set SMBJ_BENCH=1 to run the benchmark");

        line("=== smbj directory-lease benchmark ===");
        line(String.format("host=%s share=%s tree=%s warmRounds=%d", HOST, SHARE, TREE, WARM_ROUNDS));
        line(String.format("%-22s %8s %10s %10s %10s %12s %10s", "arm", "dirs", "cold(ms)", "warm(ms)", "search(ms)", "wireEnum", "cacheHits"));

        runArm("new + lease ON", NEW_PORT, true);
        runArm("new + lease OFF", NEW_PORT, false);
        runArm("old (4.20, no lease)", OLD_PORT, true);

        line("");
        line("cold  = first recursive walk (all dirs listed once)");
        line("warm  = best of " + WARM_ROUNDS + " repeat walks of the same tree");
        line("search= recursive walk collecting files matching a name substring");
        line("wireEnum = real QUERY_DIRECTORY enumerations cached (populates); cacheHits = listings served from memory");
        line("With lease ON, warm/search collapse because repeat list()s are served from cache (wireEnum stays at #dirs, cacheHits grows).");

        String report = OUT.toString();
        try {
            Files.write(Paths.get("/tmp/smbj-bench.txt"), report.getBytes(),
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        } catch (Exception ignore) {
        }
        System.out.println(report);
    }

    private void runArm(String label, int port, boolean leaseEnabled) {
        SmbConfig config = SmbConfig.builder()
            .withTimeout(30, TimeUnit.SECONDS)
            .withDirectoryLeasingEnabled(leaseEnabled)
            .build();
        try (SMBClient client = new SMBClient(config);
             Connection conn = client.connect(HOST, port)) {
            try (Session session = conn.authenticate(new AuthenticationContext(USER, PASS.toCharArray(), null));
                 DiskShare share = (DiskShare) session.connectShare(SHARE)) {

                LeasedDirectoryCache.resetStats();
                boolean leasing = conn.getConnectionContext().supportsDirectoryLeasing();

                int[] counts = new int[2];                       // [dirs, files]
                long cold = time(() -> walk(share, TREE, counts, null));

                long warm = Long.MAX_VALUE;
                for (int i = 0; i < WARM_ROUNDS; i++) {
                    long t = time(() -> walk(share, TREE, new int[2], null));
                    warm = Math.min(warm, t);
                }

                int[] matches = new int[1];
                long search = time(() -> walk(share, TREE, new int[2], name -> {
                    if (name.contains("_7.dat")) {
                        matches[0]++;
                    }
                }));

                line(String.format("%-22s %8d %10d %10d %10d %12d %10d%s",
                    label, counts[0], ms(cold), ms(warm), ms(search),
                    LeasedDirectoryCache.totalPopulates(), LeasedDirectoryCache.totalHits(),
                    leasing ? "" : "  (server: no dir-lease cap)"));
            }
        } catch (Exception e) {
            line(String.format("%-22s  FAILED: %s", label, e));
        }
    }

    private interface NameSink {
        void accept(String name);
    }

    /** Recursively list every directory under {@code start}; count dirs/files; feed names to sink. */
    private static void walk(DiskShare share, String start, int[] counts, NameSink sink) {
        Deque<String> stack = new ArrayDeque<>();
        stack.push(start);
        while (!stack.isEmpty()) {
            String dir = stack.pop();
            counts[0]++;
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
                    counts[1]++;
                    if (sink != null) {
                        sink.accept(name);
                    }
                }
            }
        }
    }

    private interface Phase {
        void run() throws Exception;
    }

    private static long time(Phase p) {
        long t0 = System.nanoTime();
        try {
            p.run();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return System.nanoTime() - t0;
    }

    private static long ms(long nanos) {
        return TimeUnit.NANOSECONDS.toMillis(nanos);
    }
}
