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

import java.io.IOException;
import com.hierynomus.smbj.session.Session;

public class SpnegoAuthenticator implements Authenticator {

    public static class Factory implements com.hierynomus.protocol.commons.Factory.Named<SpnegoAuthenticator> {

        @Override
        public String getName() {
            // The OID for NEGOEX (Extended SPNEGO)
            return "1.3.6.1.4.1.311.2.2.30";
        }

        @Override
        public SpnegoAuthenticator create() {
            return null;
        }

    }
    @Override
    public byte[] authenticate(final AuthenticationContext context, final byte[] gssToken, final Session session) throws IOException {
        return new byte[0];
    }


    public void authenticate(String username, String password, String domain) {
//        try {
//            GSSManager gssManager = GSSManager.getInstance();
//            Oid spnegoOid = new Oid("1.3.6.1.5.5.2");
//            GSSName serverName = gssManager.createName(, GSSName.NT_HOSTBASED_SERVICE, spnegoOid);
//            GSSContext context = gssManager.createContext(serverName, spnegoOid, null, GSSContext.DEFAULT_LIFETIME);
//            byte[] bytes = context.acceptSecContext(gssToken, 0, gssToken.length);
//        } catch (GSSException e) {
//            e.printStackTrace();
//        }
    }
}
