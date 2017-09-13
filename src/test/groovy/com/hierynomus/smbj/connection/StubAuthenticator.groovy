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
package com.hierynomus.smbj.connection

import com.hierynomus.security.SecurityProvider
import com.hierynomus.smbj.auth.AuthenticateResponse
import com.hierynomus.smbj.auth.AuthenticationContext
import com.hierynomus.smbj.auth.Authenticator
import com.hierynomus.smbj.session.Session

class StubAuthenticator implements Authenticator {
  static class Factory implements com.hierynomus.protocol.commons.Factory.Named<StubAuthenticator> {

    @Override
    String getName() {
      return "stub"
    }

    @Override
    StubAuthenticator create() {
      return new StubAuthenticator()
    }
  }

  @Override
  void init(SecurityProvider securityProvider, Random random) {

  }

  @Override
  boolean supports(AuthenticationContext context) {
    return true
  }

  @Override
  AuthenticateResponse authenticate(AuthenticationContext context, byte[] gssToken, Session session) throws IOException {
    return new AuthenticateResponse(new byte[0])
  }
}
