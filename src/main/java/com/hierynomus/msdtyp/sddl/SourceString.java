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
//=========================================================================
//
//  Part of PEG parser generator Mouse.
//
//  Copyright (C) 2009, 2010 by Roman R. Redziejowski (www.romanredz.se).
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//
//-------------------------------------------------------------------------
//
//  Change log
//    090701 License changed by the author to Apache v.2.
//    090810 Renamed from 'SourceString' and package name changed.
//   Version 1.2
//    091105 Modified where() to insert three dots.
//
//=========================================================================

package com.hierynomus.msdtyp.sddl;


//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH
//
//  Wrapper for parser input in the form of a string.
//
//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH

@SuppressWarnings("PMD")
class SourceString implements Source {
    //=====================================================================
    //
    //  Data.
    //
    //=====================================================================
    //-------------------------------------------------------------------
    //  The String.
    //  Note: it is the string given to the constructor, not a copy.
    //-------------------------------------------------------------------
    final String text;

    //=====================================================================
    //
    //  Constructor. Wraps the string 's'.
    //
    //=====================================================================
    public SourceString(final String s) {
        text = s;
    }


    //=====================================================================
    //
    //  Interface methods.
    //
    //=====================================================================
    //-------------------------------------------------------------------
    //  Is the wrapper correctly initialized?
    //-------------------------------------------------------------------
    public boolean created() {
        return true;
    }

    //-------------------------------------------------------------------
    //  Returns end position.
    //-------------------------------------------------------------------
    public int end() {
        return text.length();
    }

    //-------------------------------------------------------------------
    //  Returns character at position p.
    //-------------------------------------------------------------------
    public char at(int p) {
        return text.charAt(p);
    }

    //-------------------------------------------------------------------
    //  Returns characters at positions p through q-1.
    //-------------------------------------------------------------------
    public String at(int p, int q) {
        return text.substring(p, q);
    }

    //-------------------------------------------------------------------
    //  Describes position p in terms of preceding text.
    //-------------------------------------------------------------------
    public String where(int p) {
        if (p > 15)
            return "After '... " + text.substring(p - 15, p) + "'";
        else if (p > 0)
            return "After '" + text.substring(0, p) + "'";
        else
            return "At start";
    }
}
