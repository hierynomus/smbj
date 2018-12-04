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

import org.ietf.jgss.GSSContext;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.security.Key;


import com.hierynomus.protocol.transport.TransportException;

class ExtendedGSSContext {
    private static final MethodHandle krb5GetSessionKey = getKrb5GetSessionKeyFunction();

    private static MethodHandle getKrb5GetSessionKeyFunction() {
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
        @SuppressWarnings("unchecked")
        Object getSessionKeyConst = Enum.valueOf(inquireTypeClass.asSubclass(Enum.class), "KRB5_GET_SESSION_KEY");
        try {
            MethodHandle handle = MethodHandles.lookup().findVirtual(extendedContextClass, "inquireSecContext", MethodType.methodType(Object.class, inquireTypeClass));
            return MethodHandles.insertArguments(handle, 0, getSessionKeyConst).asType(MethodType.methodType(Key.class, GSSContext.class));
        } catch (NoSuchMethodException | IllegalAccessException e) {
            throw new IllegalStateException(e);
        }
    }

    public static Key krb5GetSessionKey(GSSContext gssContext) throws TransportException {
        try {
            return (Key) krb5GetSessionKey.invokeExact(gssContext);
        } catch (Throwable e) {
            throw new TransportException(e);
        }
    }

    private ExtendedGSSContext() {}
}
