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
import com.hierynomus.security.SecurityProvider;
import com.hierynomus.security.jce.JceSecurityProvider;
import com.hierynomus.smbj.auth.Authenticator;
import com.hierynomus.smbj.auth.NtlmAuthenticator;
import com.hierynomus.smbj.auth.SpnegoAuthenticator;

import java.security.SecureRandom;
import java.util.*;

public final class Config {
    private static final int DEFAULT_BUFFER_SIZE = 1024 * 1024;
    private static final int DEFAULT_SO_TIMEOUT = 0;

    private Set<SMB2Dialect> dialects;
    private List<Factory.Named<Authenticator>> authenticators;
    private Random random;
    private UUID clientGuid;
    private boolean signingRequired;
    private boolean dfsEnabled;
    private SecurityProvider securityProvider;
    private int readBufferSize;
    private int writeBufferSize;
    private int transactBufferSize;

    private int soTimeout;

    public static Config createDefaultConfig() {
        return builder().build();
    }

    public static Builder builder() {
        return new Builder()
            .withClientGuid(UUID.randomUUID())
            .withRandomProvider(new SecureRandom())
            .withSecurityProvider(new JceSecurityProvider())
            .withSigningRequired(false)
            .witDfsEnabled(true)
            .withBufferSize(DEFAULT_BUFFER_SIZE)
            .withSoTimeout(DEFAULT_SO_TIMEOUT)
            .withDialects(SMB2Dialect.SMB_2_1, SMB2Dialect.SMB_2_0_2)
            // order is important.  The authenticators listed first will be selected
            .withAuthenticators(new SpnegoAuthenticator.Factory(), new NtlmAuthenticator.Factory());
    }

    private Config() {
        dialects = EnumSet.noneOf(SMB2Dialect.class);
        authenticators = new ArrayList<>();
    }

    private Config(Config other) {
        this();
        dialects.addAll(other.dialects);
        authenticators.addAll(other.authenticators);
        random = other.random;
        clientGuid = other.clientGuid;
        signingRequired = other.signingRequired;
        dfsEnabled = other.dfsEnabled;
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

    /**
     * Whether the client requires that messages from the server are signed.  When message signing is enforced a received message that is not signed properly
     * will result in an exception.
     */
    public boolean isSigningRequired() {
        return signingRequired;
    }

    public boolean isDfsEnabled() {
        return dfsEnabled;
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

    public static class Builder {
        private Config config;

        Builder() {
            config = new Config();
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

        public Config build() {
            if (config.dialects.isEmpty()) {
                throw new IllegalStateException("At least one SMB dialect should be specified");
            }
            return new Config(config);
        }

        public Builder witDfsEnabled(boolean dfsEnabled) {
            config.dfsEnabled = dfsEnabled;
            return this;
        }
    }
}
