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
import com.hierynomus.smb.SMBPacket;
import com.hierynomus.smbj.auth.Authenticator;
import com.hierynomus.smbj.auth.NtlmAuthenticator;
import com.hierynomus.smbj.auth.SpnegoAuthenticator;
import com.hierynomus.smbj.transport.TransportLayerFactory;
import com.hierynomus.smbj.transport.tcp.direct.DirectTcpTransportFactory;

import javax.net.SocketFactory;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.TimeUnit;

public final class SmbConfig {
    private static final int DEFAULT_BUFFER_SIZE = 1024 * 1024;

    private static final int DEFAULT_SO_TIMEOUT = 0;
    private static final TimeUnit DEFAULT_SO_TIMEOUT_UNIT = TimeUnit.SECONDS;

    private static final int DEFAULT_TIMEOUT = 60;
    private static final TimeUnit DEFAULT_TIMEOUT_UNIT = TimeUnit.SECONDS;

    private static final TransportLayerFactory<SMBPacket<?>> DEFAULT_TRANSPORT_LAYER_FACTORY = new DirectTcpTransportFactory();

    private Set<SMB2Dialect> dialects;
    private List<Factory.Named<Authenticator>> authenticators;
    private SocketFactory socketFactory;
    private Random random;
    private UUID clientGuid;
    private boolean signingRequired;
    private boolean dfsEnabled;
    private boolean useMultiProtocolNegotiate;
    private SecurityProvider securityProvider;
    private int readBufferSize;
    private long readTimeout;
    private int writeBufferSize;
    private long writeTimeout;
    private int transactBufferSize;
    private TransportLayerFactory<SMBPacket<?>> transportLayerFactory;
    private long transactTimeout;

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
            .withDfsEnabled(false)
            .withMultiProtocolNegotiate(false)
            .withBufferSize(DEFAULT_BUFFER_SIZE)
            .withTransportLayerFactory(DEFAULT_TRANSPORT_LAYER_FACTORY)
            .withSoTimeout(DEFAULT_SO_TIMEOUT, DEFAULT_SO_TIMEOUT_UNIT)
            .withDialects(SMB2Dialect.SMB_2_1, SMB2Dialect.SMB_2_0_2)
            // order is important.  The authenticators listed first will be selected
            .withAuthenticators(new SpnegoAuthenticator.Factory(), new NtlmAuthenticator.Factory())
            .withTimeout(DEFAULT_TIMEOUT, DEFAULT_TIMEOUT_UNIT);
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
        dfsEnabled = other.dfsEnabled;
        securityProvider = other.securityProvider;
        readBufferSize = other.readBufferSize;
        readTimeout = other.readTimeout;
        writeBufferSize = other.writeBufferSize;
        writeTimeout = other.writeTimeout;
        transactBufferSize = other.transactBufferSize;
        transactTimeout = other.transactTimeout;
        transportLayerFactory = other.transportLayerFactory;
        soTimeout = other.soTimeout;
        useMultiProtocolNegotiate = other.useMultiProtocolNegotiate;
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

    public boolean isUseMultiProtocolNegotiate() {
        return useMultiProtocolNegotiate;
    }

    public int getReadBufferSize() {
        return readBufferSize;
    }

    public long getReadTimeout() {
        return readTimeout;
    }

    public int getWriteBufferSize() {
        return writeBufferSize;
    }

    public long getWriteTimeout() {
        return writeTimeout;
    }

    public int getTransactBufferSize() {
        return transactBufferSize;
    }

    public long getTransactTimeout() {
        return transactTimeout;
    }

    public TransportLayerFactory<SMBPacket<?>> getTransportLayerFactory() {
        return transportLayerFactory;
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
                throw new IllegalArgumentException("Socket factory may not be null");
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

        public Builder withReadTimeout(long timeout, TimeUnit timeoutUnit) {
            config.readTimeout = timeoutUnit.toMillis(timeout);
            return this;
        }

        public Builder withWriteBufferSize(int writeBufferSize) {
            if (writeBufferSize <= 0) {
                throw new IllegalArgumentException("Write buffer size must be greater than zero");
            }
            config.writeBufferSize = writeBufferSize;
            return this;
        }

        public Builder withWriteTimeout(long timeout, TimeUnit timeoutUnit) {
            config.writeTimeout = timeoutUnit.toMillis(timeout);
            return this;
        }

        public Builder withTransactBufferSize(int transactBufferSize) {
            if (transactBufferSize <= 0) {
                throw new IllegalArgumentException("Transact buffer size must be greater than zero");
            }
            config.transactBufferSize = transactBufferSize;
            return this;
        }

        public Builder withTransactTimeout(long timeout, TimeUnit timeoutUnit) {
            config.transactTimeout = timeoutUnit.toMillis(timeout);
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

        public Builder withTransportLayerFactory(TransportLayerFactory<SMBPacket<?>> transportLayerFactory) {
            if (transportLayerFactory == null) {
                throw new IllegalArgumentException("Transport layer factory may not be null");
            }
            config.transportLayerFactory = transportLayerFactory;
            return this;
        }

        public Builder withTimeout(long timeout, TimeUnit timeoutUnit) {
            return withReadTimeout(timeout, timeoutUnit).withWriteTimeout(timeout, timeoutUnit).withTransactTimeout(timeout, timeoutUnit);
        }

        public Builder withSoTimeout(int timeout) {
            return withSoTimeout(timeout, TimeUnit.MILLISECONDS);
        }

        public Builder withSoTimeout(long timeout, TimeUnit timeoutUnit) {
            if (timeout < 0) {
                throw new IllegalArgumentException("Socket timeout should be either 0 (no timeout) or a positive value");
            }
            long timeoutMillis = timeoutUnit.toMillis(timeout);
            if (timeoutMillis > Integer.MAX_VALUE) {
                throw new IllegalArgumentException("Socket timeout should be less than " + Integer.MAX_VALUE + "ms");
            }

            config.soTimeout = (int) timeoutMillis;
            return this;
        }

        public SmbConfig build() {
            if (config.dialects.isEmpty()) {
                throw new IllegalStateException("At least one SMB dialect should be specified");
            }
            return new SmbConfig(config);
        }

        public Builder withDfsEnabled(boolean dfsEnabled) {
            config.dfsEnabled = dfsEnabled;
            return this;
        }

        public Builder withMultiProtocolNegotiate(boolean useMultiProtocolNegotiate) {
            config.useMultiProtocolNegotiate = useMultiProtocolNegotiate;
            return this;
        }
    }
}
