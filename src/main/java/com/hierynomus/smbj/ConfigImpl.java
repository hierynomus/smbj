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

import java.util.EnumSet;
import java.util.List;
import java.util.Random;
import java.util.UUID;
import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.protocol.commons.Factory;
import com.hierynomus.smbj.auth.Authenticator;

public class ConfigImpl implements Config {

    protected EnumSet<SMB2Dialect> dialects;
    protected List<Factory.Named<Authenticator>> authenticators;
    protected Random random;
    protected UUID clientGuid;
    protected boolean signingRequired;

    @Override
    public Random getRandomProvider() {
        return random;
    }

    @Override
    public EnumSet<SMB2Dialect> getSupportedDialects() {
        return dialects;
    }

    @Override
    public UUID getClientGuid() {
        return clientGuid;
    }

    @Override
    public boolean isStrictSigning() {
        return signingRequired;
    }

    @Override
    public List<Factory.Named<Authenticator>> getSupportedAuthenticators() {
        return authenticators;
    }

    @Override
    public boolean isSigningRequired() {
        return signingRequired;
    }
}
