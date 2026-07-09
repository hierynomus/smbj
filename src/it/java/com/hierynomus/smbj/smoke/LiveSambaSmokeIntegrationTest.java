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

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;

import com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;

/**
 * Live smoke test against the external Samba 4.23.8 dir-lease server on .12
 * (see server/ in this repo). NOT a Testcontainers test — it talks to a real
 * host so it is excluded from CI by default and only runs when SMBJ_IT_HOST is set.
 *
 * Run: SMBJ_IT_HOST=localhost ./gradlew integrationTest --tests "*LiveSambaSmokeIntegrationTest"
 *
 * It locks in the end-to-end baseline: smbj can negotiate SMB3, authenticate,
 * connect the share, enumerate it, AND the server advertises directory leasing
 * (the precondition for every later milestone).
 */
@org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable(named = "SMBJ_IT_HOST", matches = ".+")
public class LiveSambaSmokeIntegrationTest {

    private static String env(String k, String def) {
        String v = System.getenv(k);
        return (v == null || v.isEmpty()) ? def : v;
    }

    private static final String HOST = env("SMBJ_IT_HOST", "localhost");
    private static final int PORT = Integer.parseInt(env("SMBJ_IT_PORT", "1445"));
    private static final String USER = env("SMBJ_IT_USER", "smbj");
    private static final String PASS = env("SMBJ_IT_PASS", "changeit");
    private static final String SHARE = env("SMBJ_IT_SHARE", "testshare");

    @Test
    public void listsTestShareAndServerAdvertisesDirectoryLeasing() throws Exception {
        SmbConfig config = SmbConfig.builder()
                .withTimeout(10, TimeUnit.SECONDS)
                .build();

        try (SMBClient client = new SMBClient(config);
             Connection conn = client.connect(HOST, PORT)) {

            // Precondition for the whole feature: server must advertise SMB3 + DIRECTORY_LEASING (0x20).
            assertThat(conn.getConnectionContext().supportsDirectoryLeasing())
                    .as("server at %s:%d must advertise SMB2_GLOBAL_CAP_DIRECTORY_LEASING", HOST, PORT)
                    .isTrue();

            AuthenticationContext ac = new AuthenticationContext(USER, PASS.toCharArray(), null);
            try (Session session = conn.authenticate(ac);
                 DiskShare share = (DiskShare) session.connectShare(SHARE)) {

                List<String> names = new ArrayList<>();
                for (FileIdBothDirectoryInformation f : share.list("")) {
                    names.add(f.getFileName());
                }
                assertThat(names).contains("readme.txt", "subdir");
            }
        }
    }
}
