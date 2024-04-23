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

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.testing.TestingUtils.ConsumerWithError;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.images.builder.dockerfile.DockerfileBuilder;
import org.testcontainers.utility.DockerLoggerFactory;

import java.net.URI;
import java.nio.file.Paths;
import java.util.concurrent.Future;
import java.util.function.Consumer;

import static com.hierynomus.smbj.testing.TestingUtils.PASSWORD;
import static com.hierynomus.smbj.testing.TestingUtils.USER;

public class SambaContainer extends GenericContainer<SambaContainer> {

    public static final SambaContainer INSTANCE = new SambaContainer.Builder().build();

    /**
     * A workaround for strange logger names of testcontainers. They contain no
     * dots, but contain slashes,
     * square brackets, and even emoji. It's uneasy to set the logging level via the
     * XML file of logback, the
     * result would be less readable than the code below.
     */
    public static class DebugLoggingImageFromDockerfile extends ImageFromDockerfile {
        public DebugLoggingImageFromDockerfile() {
            super();
            Logger logger = (Logger) LoggerFactory.getILoggerFactory()
                    .getLogger(DockerLoggerFactory.getLogger(getDockerImageName()).getName());
            logger.setLevel(Level.DEBUG);
        }
    }

    public static class Builder implements Consumer<DockerfileBuilder> {
        @Override
        public void accept(DockerfileBuilder t) {
            t.from("alpine:3.18.3");
            t.run("apk update && apk add --no-cache tini samba samba-common-tools supervisor bash");
            t.env("SMB_USER", "smbj");
            t.env("SMB_PASSWORD", "smbj");
            t.copy("smb.conf", "/etc/samba/smb.conf");
            t.copy("supervisord.conf", "/etc/supervisord.conf");
            t.copy("entrypoint.sh", "/entrypoint.sh");
            t.add("public", "/opt/samba/share");
            t.run("mkdir -p /opt/samba/readonly /opt/samba/user /opt/samba/dfs"
                    + " && chmod 777 /opt/samba/readonly /opt/samba/user /opt/samba/dfs"
                    + " && adduser -s /bin/false $SMB_USER -D $SMB_PASSWORD"
                    + " && (echo $SMB_PASSWORD; echo $SMB_PASSWORD ) | pdbedit -a -u $SMB_USER"
                    + " && chmod ugo+x /entrypoint.sh");
            t.expose(445);
            t.entryPoint("/sbin/tini", "/entrypoint.sh");
            t.cmd("supervisord");
        }

        public SambaContainer build() {
            return new SambaContainer(buildInner());
        }

        Future<String> buildInner() {
            return new DebugLoggingImageFromDockerfile()
                    .withDockerfileFromBuilder(this)
                    .withFileFromPath(".", Paths.get("src/it/docker-image"));
        }
    }


    public SambaContainer(SambaContainer.Builder builder) {
        this(builder.buildInner());
    }

    public SambaContainer(Future<String> imageName) {
        super(imageName);
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
        return URI.create("smb://" + USER + ":" + PASSWORD + "@" + getHost() + "/public");
    }
}

