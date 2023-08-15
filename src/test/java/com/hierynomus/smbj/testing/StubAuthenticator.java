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
package com.hierynomus.smbj.testing;

import java.io.IOException;

import com.hierynomus.protocol.commons.ByteArrayUtils;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticateResponse;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.auth.Authenticator;
import com.hierynomus.smbj.connection.ConnectionContext;
import com.hierynomus.spnego.RawToken;

public class StubAuthenticator implements Authenticator {
  public static class Factory implements com.hierynomus.protocol.commons.Factory.Named<Authenticator> {

    @Override
    public String getName() {
        return "stub";
    }

    @Override
    public StubAuthenticator create() {
        return new StubAuthenticator();
    }
  }

  @Override
  public void init(SmbConfig config) {

  }

  @Override
  public boolean supports(AuthenticationContext context) {
      return true;
  }

  @Override
  public AuthenticateResponse authenticate(AuthenticationContext context, byte[] gssToken, ConnectionContext connectionContext) throws IOException {
    AuthenticateResponse resp = new AuthenticateResponse(new RawToken(new byte[0]));
    resp.setSessionKey(ByteArrayUtils.parseHex("09921d4431b171b977370bf8910900f9"));
    return resp;
  }
}
