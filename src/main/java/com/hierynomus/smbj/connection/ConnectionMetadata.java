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
package com.hierynomus.smbj.connection;

import com.hierynomus.mssmb2.SMB2Dialect;
import java.util.UUID;

public class ConnectionMetadata
{
    private int OSmajorVersion;
    private int OSminorVersion;
    private int OSbuildCode;
    private boolean signingEnabled;
    private boolean signingRequired;
    private boolean encryptionSupported;
    private SMB2Dialect dialectVersion;
    private UUID serverGUID;

    public boolean isEncryptionSupported()
    {
        return encryptionSupported;
    }

    public void setEncryptionSupported(boolean encryptionSupported)
    {
        this.encryptionSupported = encryptionSupported;
    }

    public int getOSmajorVersion()
    {
        return OSmajorVersion;
    }

    public void setOSmajorVersion(int OSmajorVersion)
    {
        this.OSmajorVersion = OSmajorVersion;
    }

    public int getOSminorVersion()
    {
        return OSminorVersion;
    }

    public void setOSminorVersion(int OSminorVersion)
    {
        this.OSminorVersion = OSminorVersion;
    }

    public int getOSbuildCode()
    {
        return OSbuildCode;
    }

    public void setOSbuildCode(int OSbuildCode)
    {
        this.OSbuildCode = OSbuildCode;
    }

    public boolean isSigningEnabled()
    {
        return signingEnabled;
    }

    public void setSigningEnabled(boolean signingEnabled)
    {
        this.signingEnabled = signingEnabled;
    }

    public boolean isSigningRequired()
    {
        return signingRequired;
    }

    public void setSigningRequired(boolean signingRequired)
    {
        this.signingRequired = signingRequired;
    }

    public SMB2Dialect getDialectVersion()
    {
        return dialectVersion;
    }

    public void setDialectVersion(SMB2Dialect dialectVersion)
    {
        this.dialectVersion = dialectVersion;
    }

    public UUID getServerGUID()
    {
        return serverGUID;
    }

    public void setServerGUID(UUID serverGUID)
    {
        this.serverGUID = serverGUID;
    }
}
