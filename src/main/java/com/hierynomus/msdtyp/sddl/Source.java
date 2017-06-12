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
//    090810 Package name changed.
//
//=========================================================================

package com.hierynomus.msdtyp.sddl;


//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH
//
//  Interface to source text wrapper.
//  The generated parser accesses its input through a wrapper that
//  presents the input as a sequence of characters. These characters
//  can be individually accessed by specifying their position in the
//  sequence. The positions are numbered starting with 0.
//  For diagnostic purposes, the wrapper has the method 'where' that
//  describes a given position in terms compatible with the input
//  medium, for example, as line and column number for a file.
//
//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH

@SuppressWarnings("PMD")
public interface Source {
    //-------------------------------------------------------------------
    //  Is the wrapper correctly initialized?
    //  The wrapper's constructor may encounter errors that result
    //  in the object not being properly initialized.
    //  The method returns 'false' if this is the case.
    //-------------------------------------------------------------------
    boolean created();

    //-------------------------------------------------------------------
    //  Returns position of the last character plus 1
    //  (= length of the sequence).
    //-------------------------------------------------------------------
    int end();

    //-------------------------------------------------------------------
    //  Returns character at position p.
    //-------------------------------------------------------------------
    char at(int p);

    //-------------------------------------------------------------------
    //  Returns characters at positions p through q-1.
    //-------------------------------------------------------------------
    String at(int p, int q);

    //-------------------------------------------------------------------
    //  Describes position p in user's terms.
    //-------------------------------------------------------------------
    String where(int p);
}
