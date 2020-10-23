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

import com.hierynomus.protocol.transport.TransportException;
import org.ietf.jgss.GSSContext;

import java.lang.reflect.Method;
import java.security.Key;

class ExtendedGSSContext {
    private static final Method inquireSecContext = getInquireSecContextMethod();
    private static Object krb5GetSessionKeyConst;

    private static Method getInquireSecContextMethod() {
        Class<?> extendedContextClass;
        Class<?> inquireTypeClass;
        try {
            extendedContextClass = Class.forName("com.sun.security.jgss.ExtendedGSSContext", false, SpnegoAuthenticator.class.getClassLoader());
            inquireTypeClass = Class.forName("com.sun.security.jgss.InquireType");
        } catch (ClassNotFoundException e) {
            try {
                extendedContextClass = Class.forName("com.ibm.security.jgss.ExtendedGSSContext", false, SpnegoAuthenticator.class.getClassLoader());
                inquireTypeClass = Class.forName("com.ibm.security.jgss.InquireType");
            } catch (ClassNotFoundException e1) {
                IllegalStateException exception = new IllegalStateException("The code is running in an unknown java vm");
                exception.addSuppressed(e);
                exception.addSuppressed(e1);
                throw exception;
            }
        }
        krb5GetSessionKeyConst = Enum.valueOf(inquireTypeClass.asSubclass(Enum.class), "KRB5_GET_SESSION_KEY");
        try {
            return extendedContextClass.getDeclaredMethod("inquireSecContext", inquireTypeClass);
        } catch (NoSuchMethodException e) {
            throw new IllegalStateException(e);
        }
    }

    public static Key krb5GetSessionKey(GSSContext gssContext) throws TransportException {
        try {
            return (Key) inquireSecContext.invoke(gssContext, krb5GetSessionKeyConst);
        } catch (Throwable e) {
            throw new TransportException(e);
        }
    }

    private ExtendedGSSContext() {
    }
}
