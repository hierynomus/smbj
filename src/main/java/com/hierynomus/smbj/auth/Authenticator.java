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
package com.hierynomus.smbj.auth;

import com.hierynomus.security.SecurityProvider;
import com.hierynomus.smbj.session.Session;

import java.io.IOException;
import java.util.Random;

public interface Authenticator {

    void init(SecurityProvider securityProvider, Random random);

    boolean supports(AuthenticationContext context);

    // TODO remove session parameter.
    AuthenticateResponse authenticate(AuthenticationContext context, byte[] gssToken, Session session) throws IOException;
}
