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

import org.ietf.jgss.GSSCredential;

import javax.security.auth.Subject;

public class GSSAuthenticationContext extends AuthenticationContext {
    Subject subject;
    GSSCredential creds;

    public GSSAuthenticationContext(String username, String domain, Subject subject, GSSCredential creds) {
        super(username, new char[0], domain);
        this.subject = subject;
        this.creds = creds;
    }

    public Subject getSubject() {
        return subject;
    }

    public GSSCredential getCreds() {
        return creds;
    }

    @Override
    public String toString() {
        return "GSSAuthenticationContext[" + subject + ']';
    }
}
