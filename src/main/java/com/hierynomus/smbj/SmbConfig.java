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
package com.hierynomus.smbj;

import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.protocol.commons.Factory;
import com.hierynomus.protocol.commons.socket.ProxySocketFactory;
import com.hierynomus.security.SecurityProvider;
import com.hierynomus.security.jce.JceSecurityProvider;
import com.hierynomus.smbj.auth.Authenticator;
import com.hierynomus.smbj.auth.NtlmAuthenticator;
import com.hierynomus.smbj.auth.SpnegoAuthenticator;

import javax.net.SocketFactory;
import java.security.SecureRandom;
import java.util.*;

public final class SmbConfig {
    private static final int DEFAULT_BUFFER_SIZE = 1024 * 1024;
    private static final int DEFAULT_SO_TIMEOUT = 0;

    private Set<SMB2Dialect> dialects;
    private List<Factory.Named<Authenticator>> authenticators;
    private SocketFactory socketFactory;
    private Random random;
    private UUID clientGuid;
    private boolean signingRequired;
    private SecurityProvider securityProvider;
    private int readBufferSize;
    private int writeBufferSize;
    private int transactBufferSize;

    private int soTimeout;

    public static SmbConfig createDefaultConfig() {
        return builder().build();
    }

    public static Builder builder() {
        return new Builder()
            .withClientGuid(UUID.randomUUID())
            .withRandomProvider(new SecureRandom())
            .withSecurityProvider(new JceSecurityProvider())
            .withSocketFactory(new ProxySocketFactory())
            .withSigningRequired(false)
            .withBufferSize(DEFAULT_BUFFER_SIZE)
            .withSoTimeout(DEFAULT_SO_TIMEOUT)
            .withDialects(SMB2Dialect.SMB_2_1, SMB2Dialect.SMB_2_0_2)
            // order is important.  The authenticators listed first will be selected
            .withAuthenticators(new SpnegoAuthenticator.Factory(), new NtlmAuthenticator.Factory());
    }

    private SmbConfig() {
        dialects = EnumSet.noneOf(SMB2Dialect.class);
        authenticators = new ArrayList<>();
    }

    private SmbConfig(SmbConfig other) {
        this();
        dialects.addAll(other.dialects);
        authenticators.addAll(other.authenticators);
        socketFactory = other.socketFactory;
        random = other.random;
        clientGuid = other.clientGuid;
        signingRequired = other.signingRequired;
        securityProvider = other.securityProvider;
        readBufferSize = other.readBufferSize;
        writeBufferSize = other.writeBufferSize;
        transactBufferSize = other.transactBufferSize;
        soTimeout = other.soTimeout;
    }

    public Random getRandomProvider() {
        return random;
    }

    public SecurityProvider getSecurityProvider() {
        return securityProvider;
    }

    public Set<SMB2Dialect> getSupportedDialects() {
        return EnumSet.copyOf(dialects);
    }

    public UUID getClientGuid() {
        return clientGuid;
    }

    public List<Factory.Named<Authenticator>> getSupportedAuthenticators() {
        return new ArrayList<>(authenticators);
    }

    public boolean isSigningRequired() {
        return signingRequired;
    }

    public int getReadBufferSize() {
        return readBufferSize;
    }

    public int getWriteBufferSize() {
        return writeBufferSize;
    }

    public int getTransactBufferSize() {
        return transactBufferSize;
    }

    public int getSoTimeout() {
        return soTimeout;
    }

    public SocketFactory getSocketFactory() {
        return socketFactory;
    }

    public static class Builder {
        private SmbConfig config;

        Builder() {
            config = new SmbConfig();
        }

        public Builder withRandomProvider(Random random) {
            if (random == null) {
                throw new IllegalArgumentException("Random provider may not be null");
            }
            config.random = random;
            return this;
        }

        public Builder withSecurityProvider(SecurityProvider securityProvider) {
            if (securityProvider == null) {
                throw new IllegalArgumentException("Security provider may not be null");
            }
            config.securityProvider = securityProvider;
            return this;
        }

        public Builder withSocketFactory(SocketFactory socketFactory) {
            if (socketFactory == null) {
                throw new IllegalArgumentException("Cannot set a null SocketFactory");
            }
            config.socketFactory = socketFactory;
            return this;
        }

        public Builder withDialects(SMB2Dialect... dialects) {
            return withDialects(Arrays.asList(dialects));
        }

        public Builder withDialects(Iterable<SMB2Dialect> dialects) {
            if (dialects == null) {
                throw new IllegalArgumentException("Dialects may not be null");
            }

            config.dialects.clear();
            for (SMB2Dialect dialect : dialects) {
                if (dialect == null) {
                    throw new IllegalArgumentException("Dialect may not be null");
                }
                config.dialects.add(dialect);
            }
            return this;
        }

        public Builder withClientGuid(UUID clientGuid) {
            if (clientGuid == null) {
                throw new IllegalArgumentException("Client GUID may not be null");
            }
            config.clientGuid = clientGuid;
            return this;
        }

        public Builder withAuthenticators(Factory.Named<Authenticator>... authenticators) {
            return withAuthenticators(Arrays.asList(authenticators));
        }

        public Builder withAuthenticators(Iterable<Factory.Named<Authenticator>> authenticators) {
            if (authenticators == null) {
                throw new IllegalArgumentException("Authenticators may not be null");
            }

            config.authenticators.clear();
            for (Factory.Named<Authenticator> authenticator : authenticators) {
                if (authenticator == null) {
                    throw new IllegalArgumentException("Authenticator may not be null");
                }
                config.authenticators.add(authenticator);
            }
            return this;
        }

        public Builder withSigningRequired(boolean signingRequired) {
            config.signingRequired = signingRequired;
            return this;
        }

        public Builder withReadBufferSize(int readBufferSize) {
            if (readBufferSize <= 0) {
                throw new IllegalArgumentException("Read buffer size must be greater than zero");
            }
            config.readBufferSize = readBufferSize;
            return this;
        }

        public Builder withWriteBufferSize(int writeBufferSize) {
            if (writeBufferSize <= 0) {
                throw new IllegalArgumentException("Write buffer size must be greater than zero");
            }
            config.writeBufferSize = writeBufferSize;
            return this;
        }

        public Builder withTransactBufferSize(int transactBufferSize) {
            if (transactBufferSize <= 0) {
                throw new IllegalArgumentException("Transact buffer size must be greater than zero");
            }
            config.transactBufferSize = transactBufferSize;
            return this;
        }

        public Builder withNegotiatedBufferSize() {
            return withBufferSize(Integer.MAX_VALUE);
        }

        public Builder withBufferSize(int bufferSize) {
            if (bufferSize <= 0) {
                throw new IllegalArgumentException("Buffer size must be greater than zero");
            }
            return withReadBufferSize(bufferSize).withWriteBufferSize(bufferSize).withTransactBufferSize(bufferSize);
        }

        public Builder withSoTimeout(int soTimeout) {
            if (soTimeout < 0) {
                throw new IllegalArgumentException("Socket Timeout should be either 0 (no timeout) or a positive number expressed in milliseconds.");
            }
            config.soTimeout = soTimeout;
            return this;
        }

        public SmbConfig build() {
            if (config.dialects.isEmpty()) {
                throw new IllegalStateException("At least one SMB dialect should be specified");
            }
            return new SmbConfig(config);
        }
    }
}
