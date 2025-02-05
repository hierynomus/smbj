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
package com.hierynomus.smbj.testcontainers;

import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.testing.TestingUtils.ConsumerWithError;
import org.apache.commons.io.IOUtils;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;

import java.io.IOException;
import java.net.URI;

import static com.hierynomus.smbj.testing.TestingUtils.PASSWORD;
import static com.hierynomus.smbj.testing.TestingUtils.USER;
import static java.nio.charset.Charset.defaultCharset;

public class SambaContainer extends GenericContainer<SambaContainer> {

    public static final SambaContainer INSTANCE = new SambaContainer();

    public SambaContainer() {
        super("smbj/samba");
        withExposedPorts(445);
        addFixedExposedPort(445, 445);
        setWaitStrategy(Wait.forListeningPort());
        withLogConsumer(outputFrame -> {
            switch (outputFrame.getType()) {
                case STDOUT:
                    logger().info("sshd stdout: {}", outputFrame.getUtf8String().stripTrailing());
                    break;
                case STDERR:
                    logger().info("sshd stderr: {}", outputFrame.getUtf8String().stripTrailing());
                    break;
                default:
                    break;
            }
        });
    }


    public void withConnectedClient(SmbConfig config, ConsumerWithError<Connection> f) throws Exception {
        try (SMBClient client = new SMBClient(config)) {
            try (Connection connection = client.connect(getHost(), getFirstMappedPort())) {
                f.accept(connection);
            }
        }
    }


    public void withAuthenticatedClient(SmbConfig config, AuthenticationContext ctx,
            ConsumerWithError<Session> f) throws Exception {
        withConnectedClient(config, (connection) -> {
            try (Session session = connection.authenticate(ctx)) {
                f.accept(session);
            }
        });
    }

    public URI publicUri() {
        return URI.create("smb://" + USER + ":" + PASSWORD + "@" + getHost() + ":" + getFirstMappedPort() + "/public/");
    }

    public URI userUri() {
        return URI.create("smb://" + USER + ":" + PASSWORD + "@" + getHost() + ":" + getFirstMappedPort() + "/user/");
    }

    public String readFileFromContainer(String file) {
        return copyFileFromContainer(file, input -> IOUtils.toString(input, defaultCharset()));
    }

    public void mkdirInContainer(String path) throws IOException, InterruptedException {
        ensureOk(execInContainer("mkdir", path));
        chmodFileInContainer(path, "777");
    }

    public void deleteFromContainer(String path) throws IOException, InterruptedException {
        ensureOk(execInContainer("rm", "-rf", path));
    }

    public void chmodFileInContainer(String path, String permissions) throws IOException, InterruptedException {
        ensureOk(execInContainer("chmod", permissions, path));
    }

    public boolean fileExistsInContainer(String path) throws IOException, InterruptedException {
        ExecResult execResult = execInContainer("test", "-f", path);
        return execResult.getExitCode() == 0;
    }

    public boolean dirExistsInContainer(String path) throws IOException, InterruptedException {
        ExecResult execResult = execInContainer("test", "-d", path);
        return execResult.getExitCode() == 0;
    }

    private void ensureOk(ExecResult result) {
        if (result.getExitCode() != 0) {
            throw new ExecutionFailedException(result.getExitCode());
        }
    }
}

