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

public interface Config {

    Random getRandomProvider();

    EnumSet<SMB2Dialect> getSupportedDialects();

    List<Factory.Named<Authenticator>> getSupportedAuthenticators();

    UUID getClientGuid();

    /**
     * enforces message signing.  When message signing is enforced a received message that is not signed properly
     * will be dropped.
     */
    boolean isStrictSigning();
    
    /**
     * See [MS-SMB2] 2.2.3 SMB2 NEGOTIATE Request
     * SMB2_GLOBAL_CAP_DFS
     */
    boolean isDFSEnabled();
}
