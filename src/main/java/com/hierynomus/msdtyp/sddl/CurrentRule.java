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
//  Copyright (C) 2009 by Roman R. Redziejowski (www.romanredz.se).
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
//    090717 Name changed from 'Parser' to 'CurrentRule'.
//
//=========================================================================

package com.hierynomus.msdtyp.sddl;


//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH
//
//  Current Rule seen by a semantic action
//
//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH

@SuppressWarnings("PMD")
public interface CurrentRule {
    //-------------------------------------------------------------------
    //  Left-hand side.
    //-------------------------------------------------------------------
    Phrase lhs();

    //-------------------------------------------------------------------
    //  Number of right-hand side items.
    //-------------------------------------------------------------------
    int rhsSize();

    //-------------------------------------------------------------------
    //  i-th item on the right-hand side.
    //-------------------------------------------------------------------
    Phrase rhs(int i);

    //-------------------------------------------------------------------
    //  String represented by right-hand side items i through j-1.
    //-------------------------------------------------------------------
    String rhsText(int i, int j);
}
