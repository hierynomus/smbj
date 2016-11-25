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
package com.hierynomus.spnego;


import com.hierynomus.asn1.types.primitive.ASN1ObjectIdentifier;

public class ObjectIdentifiers {
    // {iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) spnego(2)}
    public static final ASN1ObjectIdentifier SPNEGO = new ASN1ObjectIdentifier("1.3.6.1.5.5.2");
}
