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
package com.hierynomus.mssmb2.dfs;

import java.util.Hashtable;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.session.Session;

/**
 * table to store Sessions indexed by domain/user and remote host name.
 * @author cherrmann
 *
 */
public class UserHostSessionTable {
    private Hashtable<Index,Session> table = new Hashtable<Index,Session>();
    public Session lookup(AuthenticationContext auth, String hostName) {
        Index i = new Index(auth,hostName);
        return table.get(i);
    }
    public void register(Session session) {
        table.put(new Index(session.getAuthenticationContext(),session.getConnection().getRemoteHostname()), session);
    }
    public void remove(Session session) {
        table.remove(new Index(session.getAuthenticationContext(),session.getConnection().getRemoteHostname()), session);
    }
    
    //helper class to merge the two keys into one key for the hash table
    class Index {
        AuthenticationContext auth;
        String hostName;
        Index(AuthenticationContext auth, String hostName) {
            if (auth == null || hostName == null)
                throw new NullPointerException();
            this.auth = auth;
            this.hostName = hostName;
        }
        public boolean equals(Object o) {
            if (this == o) 
                return true;
            if (o == null)
                return false;
            if (getClass() != o.getClass())
                return false;
            Index i = (Index) o;
            return (auth.getUsername().equals(i.auth.getUsername()) && auth.getDomain().equals(i.auth.getDomain()));
        }
        public int hashCode() {
            int h = (auth.getUsername().hashCode() ^ auth.getDomain().hashCode() ^ hostName.hashCode());
            return h;
        }
        public String toString() {
            return "["+auth.getUsername()+","+auth.getDomain()+","+hostName+"]";
        }
    }
}
