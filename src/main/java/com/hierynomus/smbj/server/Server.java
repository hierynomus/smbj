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
package com.hierynomus.smbj.server;

import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2GlobalCapability;

import java.util.Set;
import java.util.UUID;

public class Server {

    private boolean initialized;
    private String serverName;
    private int port;
    private UUID serverGUID;
    private SMB2Dialect dialectRevision;
    private int securityMode;
    private Set<SMB2GlobalCapability> capabilities;


    public Server(String serverName, int port) {
        this.serverName = serverName;
        this.port = port;
        this.initialized = false;
    }

    public void init(UUID serverGUID, SMB2Dialect dialectRevision, int securityMode, Set<SMB2GlobalCapability> capabilities) {
        if (initialized) {
            throw new IllegalStateException(String.format("Server object '%s' already initialized", serverName));
        }
        this.initialized = true;
        this.serverGUID = serverGUID;
        this.dialectRevision = dialectRevision;
        this.securityMode = securityMode;
        this.capabilities = capabilities;
    }

    public String getServerName() {
        return serverName;
    }

    public int getPort() {
        return port;
    }

    public UUID getServerGUID() {
        return serverGUID;
    }

    public SMB2Dialect getDialectRevision() {
        return dialectRevision;
    }

    public int getSecurityMode() {
        return securityMode;
    }

    public Set<SMB2GlobalCapability> getCapabilities() {
        return capabilities;
    }

    public boolean validate(Server other) {
        boolean guids = other.getServerGUID().equals(serverGUID);
        boolean dialects = other.getDialectRevision().equals(dialectRevision);
        boolean securityModes = other.getSecurityMode() == securityMode;
        boolean capabilities = other.getCapabilities().equals(this.capabilities);
        return guids && dialects && securityModes && capabilities;
    }
}
