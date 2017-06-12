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

package com.hierynomus.msdtyp.sddl;

@SuppressWarnings("PMD")
class SddlParser extends com.hierynomus.msdtyp.sddl.ParserBase {
    final SddlParserSemantics sem;

    //=======================================================================
    //
    //  Initialization
    //
    //=======================================================================
    //-------------------------------------------------------------------
    //  Constructor
    //-------------------------------------------------------------------
    public SddlParser() {
        sem = new SddlParserSemantics();
        sem.rule = this;
        super.sem = sem;
    }

    //-------------------------------------------------------------------
    //  Run the parser
    //-------------------------------------------------------------------
    public boolean parse(Source src) {
        super.init(src);
        sem.init();
        boolean result = SDDL();
        closeParser(result);
        return result;
    }

    //-------------------------------------------------------------------
    //  Get semantics
    //-------------------------------------------------------------------
    public SddlParserSemantics semantics() {
        return sem;
    }

    //=======================================================================
    //
    //  Parsing procedures
    //
    //=======================================================================
    //=====================================================================
    //  SDDL = OwnerString? GroupString? DaclString? SaclString? !_ {sddl}
    //    ~{error} / _* ;
    //=====================================================================
    private boolean SDDL() {
        begin("SDDL");
        if (SDDL_0()) {
            sem.sddl();
            return accept();
        }
        sem.error();
        if (SDDL_1()) return accept();
        return reject();
    }

    //-------------------------------------------------------------------
    //  SDDL_0 = OwnerString? GroupString? DaclString? SaclString? !_
    //-------------------------------------------------------------------
    private boolean SDDL_0() {
        begin("");
        OwnerString();
        GroupString();
        DaclString();
        SaclString();
        if (!aheadNot()) return rejectInner();
        return acceptInner();
    }

    //-------------------------------------------------------------------
    //  SDDL_1 = _*
    //-------------------------------------------------------------------
    private boolean SDDL_1() {
        begin("");
        while (next()) ;
        return acceptInner();
    }

    //=====================================================================
    //  OwnerString = "O:" SidString {owner} ;
    //=====================================================================
    private boolean OwnerString() {
        begin("OwnerString");
        if (!next("O:")) return reject();
        if (!SidString()) return reject();
        sem.owner();
        return accept();
    }

    //=====================================================================
    //  GroupString = "G:" SidString {group} ;
    //=====================================================================
    private boolean GroupString() {
        begin("GroupString");
        if (!next("G:")) return reject();
        if (!SidString()) return reject();
        sem.group();
        return accept();
    }

    //=====================================================================
    //  DaclString = "D:" AclString {dacl} ;
    //=====================================================================
    private boolean DaclString() {
        begin("DaclString");
        if (!next("D:")) return reject();
        AclString();
        sem.dacl();
        return accept();
    }

    //=====================================================================
    //  SaclString = "S:" AclString {sacl} ;
    //=====================================================================
    private boolean SaclString() {
        begin("SaclString");
        if (!next("S:")) return reject();
        AclString();
        sem.sacl();
        return accept();
    }

    //=====================================================================
    //  AclString = AclFlagString Aces {acl} ;
    //=====================================================================
    private boolean AclString() {
        begin("AclString");
        AclFlagString();
        Aces();
        sem.acl();
        return accept();
    }

    //=====================================================================
    //  SidString = (SidToken / SidValue) {sid} ;
    //=====================================================================
    private boolean SidString() {
        begin("SidString");
        if (!SidToken()
            && !SidValue()
            ) return reject();
        sem.sid();
        return accept();
    }

    //=====================================================================
    //  SidValue = "S-1-" IdentifierAuthority SubAuthority+ ;
    //=====================================================================
    private boolean SidValue() {
        begin("SidValue");
        if (!next("S-1-")) return reject();
        if (!IdentifierAuthority()) return reject();
        if (!SubAuthority()) return reject();
        while (SubAuthority()) ;
        return accept();
    }

    //=====================================================================
    //  IdentifierAuthority = IdentifierAuthorityHex /
    //    IdentifierAuthorityDec ;
    //=====================================================================
    private boolean IdentifierAuthority() {
        begin("IdentifierAuthority");
        if (IdentifierAuthorityHex()) return accept();
        if (IdentifierAuthorityDec()) return accept();
        return reject();
    }

    //=====================================================================
    //  IdentifierAuthorityDec = Digit+ ;
    //=====================================================================
    private boolean IdentifierAuthorityDec() {
        begin("IdentifierAuthorityDec");
        if (!Digit()) return reject();
        while (Digit()) ;
        return accept();
    }

    //=====================================================================
    //  IdentifierAuthorityHex = "0x" HexDigit+ ;
    //=====================================================================
    private boolean IdentifierAuthorityHex() {
        begin("IdentifierAuthorityHex");
        if (!next("0x")) return reject();
        if (!HexDigit()) return reject();
        while (HexDigit()) ;
        return accept();
    }

    //=====================================================================
    //  SubAuthority = "-" Digit+ ;
    //=====================================================================
    private boolean SubAuthority() {
        begin("SubAuthority");
        if (!next('-')) return reject();
        if (!Digit()) return reject();
        while (Digit()) ;
        return accept();
    }

    //=====================================================================
    //  SidToken = "DA" / "DG" / "DU" / "ED" / "DD" / "DC" / "BA" / "BG" /
    //    "BU" / "LA" / "LG" / "AO" / "BO" / "PO" / "SO" / "AU" / "PS" /
    //    "CO" / "CG" / "SY" / "PU" / "WD" / "RE" / "IU" / "NU" / "SU" /
    //    "RC" / "WR" / "AN" / "SA" / "CA" / "RS" / "EA" / "PA" / "RU" /
    //    "LS" / "NS" / "RD" / "NO" / "MU" / "LU" / "IS" / "CY" / "OW" /
    //    "ER" / "RO" / "CD" / "AC" / "RA" / "ES" / "MS" / "UD" / "HA" /
    //    "CN" / "AA" / "RM" / "LW" / "ME" / "MP" / "HI" / "SI" ;
    //=====================================================================
    private boolean SidToken() {
        begin("SidToken");
        if (next("DA")) return accept();
        if (next("DG")) return accept();
        if (next("DU")) return accept();
        if (next("ED")) return accept();
        if (next("DD")) return accept();
        if (next("DC")) return accept();
        if (next("BA")) return accept();
        if (next("BG")) return accept();
        if (next("BU")) return accept();
        if (next("LA")) return accept();
        if (next("LG")) return accept();
        if (next("AO")) return accept();
        if (next("BO")) return accept();
        if (next("PO")) return accept();
        if (next("SO")) return accept();
        if (next("AU")) return accept();
        if (next("PS")) return accept();
        if (next("CO")) return accept();
        if (next("CG")) return accept();
        if (next("SY")) return accept();
        if (next("PU")) return accept();
        if (next("WD")) return accept();
        if (next("RE")) return accept();
        if (next("IU")) return accept();
        if (next("NU")) return accept();
        if (next("SU")) return accept();
        if (next("RC")) return accept();
        if (next("WR")) return accept();
        if (next("AN")) return accept();
        if (next("SA")) return accept();
        if (next("CA")) return accept();
        if (next("RS")) return accept();
        if (next("EA")) return accept();
        if (next("PA")) return accept();
        if (next("RU")) return accept();
        if (next("LS")) return accept();
        if (next("NS")) return accept();
        if (next("RD")) return accept();
        if (next("NO")) return accept();
        if (next("MU")) return accept();
        if (next("LU")) return accept();
        if (next("IS")) return accept();
        if (next("CY")) return accept();
        if (next("OW")) return accept();
        if (next("ER")) return accept();
        if (next("RO")) return accept();
        if (next("CD")) return accept();
        if (next("AC")) return accept();
        if (next("RA")) return accept();
        if (next("ES")) return accept();
        if (next("MS")) return accept();
        if (next("UD")) return accept();
        if (next("HA")) return accept();
        if (next("CN")) return accept();
        if (next("AA")) return accept();
        if (next("RM")) return accept();
        if (next("LW")) return accept();
        if (next("ME")) return accept();
        if (next("MP")) return accept();
        if (next("HI")) return accept();
        if (next("SI")) return accept();
        return reject();
    }

    //=====================================================================
    //  AclFlagString = AclFlag* {aclFlags} ;
    //=====================================================================
    private boolean AclFlagString() {
        begin("AclFlagString");
        while (AclFlag()) ;
        sem.aclFlags();
        return accept();
    }

    //=====================================================================
    //  AclFlag = ("P" / "AR" / "AI") {aclFlag} ;
    //=====================================================================
    private boolean AclFlag() {
        begin("AclFlag");
        if (!next('P')
            && !next("AR")
            && !next("AI")
            ) return reject();
        sem.aclFlag();
        return accept();
    }

    //=====================================================================
    //  Aces = (Ace / ConditionalAce / ResourceAttributeAce)* {aces} ;
    //=====================================================================
    private boolean Aces() {
        begin("Aces");
        while (Aces_0()) ;
        sem.aces();
        return accept();
    }

    //-------------------------------------------------------------------
    //  Aces_0 = Ace / ConditionalAce / ResourceAttributeAce
    //-------------------------------------------------------------------
    private boolean Aces_0() {
        begin("");
        if (Ace()) return acceptInner();
        if (ConditionalAce()) return acceptInner();
        if (ResourceAttributeAce()) return acceptInner();
        return rejectInner();
    }

    //=====================================================================
    //  Ace = "(" AceType ";" AceFlagString ";" AceRights ";" Guid ";" Guid
    //    ";" SidString ")" {ace} ;
    //=====================================================================
    private boolean Ace() {
        begin("Ace");
        if (!next('(')) return reject();
        if (!AceType()) return reject();
        if (!next(';')) return reject();
        AceFlagString();
        if (!next(';')) return reject();
        AceRights();
        if (!next(';')) return reject();
        Guid();
        if (!next(';')) return reject();
        Guid();
        if (!next(';')) return reject();
        if (!SidString()) return reject();
        if (!next(')')) return reject();
        sem.ace();
        return accept();
    }

    //=====================================================================
    //  AceType = ("AU" / "A" / "D" / "OA" / "OD" / "OU" / "ML" / "SP")
    //    {aceType} ;
    //=====================================================================
    private boolean AceType() {
        begin("AceType");
        if (!next("AU")
            && !next('A')
            && !next('D')
            && !next("OA")
            && !next("OD")
            && !next("OU")
            && !next("ML")
            && !next("SP")
            ) return reject();
        sem.aceType();
        return accept();
    }

    //=====================================================================
    //  ConditionalAce = "(" ConditionalAceType ";" AceFlagString ";"
    //    AceRights ";" Guid ";" Guid ";" SidString ";(" CondExpr "))"
    //    {conditionalAce} ;
    //=====================================================================
    private boolean ConditionalAce() {
        begin("ConditionalAce");
        if (!next('(')) return reject();
        if (!ConditionalAceType()) return reject();
        if (!next(';')) return reject();
        AceFlagString();
        if (!next(';')) return reject();
        AceRights();
        if (!next(';')) return reject();
        Guid();
        if (!next(';')) return reject();
        Guid();
        if (!next(';')) return reject();
        if (!SidString()) return reject();
        if (!next(";(")) return reject();
        if (!CondExpr()) return reject();
        if (!next("))")) return reject();
        sem.conditionalAce();
        return accept();
    }

    //=====================================================================
    //  ConditionalAceType = ("XA" / "XD" / "ZA" / "XU")
    //    {conditionalAceType} ;
    //=====================================================================
    private boolean ConditionalAceType() {
        begin("ConditionalAceType");
        if (!next("XA")
            && !next("XD")
            && !next("ZA")
            && !next("XU")
            ) return reject();
        sem.conditionalAceType();
        return accept();
    }

    //=====================================================================
    //  ResourceAttributeAce = "(" ResourceAttributeAceType ";"
    //    AceFlagString ";;;;" ResourceAttributeAceSid ";(" AttributeData
    //    "))" {resourceAttributeAce} ;
    //=====================================================================
    private boolean ResourceAttributeAce() {
        begin("ResourceAttributeAce");
        if (!next('(')) return reject();
        if (!ResourceAttributeAceType()) return reject();
        if (!next(';')) return reject();
        AceFlagString();
        if (!next(";;;;")) return reject();
        if (!ResourceAttributeAceSid()) return reject();
        if (!next(";(")) return reject();
        if (!AttributeData()) return reject();
        if (!next("))")) return reject();
        sem.resourceAttributeAce();
        return accept();
    }

    //=====================================================================
    //  ResourceAttributeAceType = "RA" {resourceAttributeAceType} ;
    //=====================================================================
    private boolean ResourceAttributeAceType() {
        begin("ResourceAttributeAceType");
        if (!next("RA")) return reject();
        sem.resourceAttributeAceType();
        return accept();
    }

    //=====================================================================
    //  ResourceAttributeAceSid = ("WD" / "S-1-1-0") {sid} ;
    //=====================================================================
    private boolean ResourceAttributeAceSid() {
        begin("ResourceAttributeAceSid");
        if (!next("WD")
            && !next("S-1-1-0")
            ) return reject();
        sem.sid();
        return accept();
    }

    //=====================================================================
    //  AttributeData = DQUOTE AttrChar2+ DQUOTE "," (TIAttr / TUAttr /
    //    TSAttr / TDAttr / TXAttr / TBAttr) ;
    //=====================================================================
    private boolean AttributeData() {
        begin("AttributeData");
        if (!DQUOTE()) return reject();
        if (!AttrChar2()) return reject();
        while (AttrChar2()) ;
        if (!DQUOTE()) return reject();
        if (!next(',')) return reject();
        if (!TIAttr()
            && !TUAttr()
            && !TSAttr()
            && !TDAttr()
            && !TXAttr()
            && !TBAttr()
            ) return reject();
        return accept();
    }

    //=====================================================================
    //  TIAttr = "TI" "," AttrFlags ("," Int64)* ;
    //=====================================================================
    private boolean TIAttr() {
        begin("TIAttr");
        if (!next("TI")) return reject();
        if (!next(',')) return reject();
        if (!AttrFlags()) return reject();
        while (TIAttr_0()) ;
        return accept();
    }

    //-------------------------------------------------------------------
    //  TIAttr_0 = "," Int64
    //-------------------------------------------------------------------
    private boolean TIAttr_0() {
        begin("");
        if (!next(',')) return rejectInner();
        if (!Int64()) return rejectInner();
        return acceptInner();
    }

    //=====================================================================
    //  TUAttr = "TU" "," AttrFlags ("," UInt64) ;
    //=====================================================================
    private boolean TUAttr() {
        begin("TUAttr");
        if (!next("TU")) return reject();
        if (!next(',')) return reject();
        if (!AttrFlags()) return reject();
        if (!next(',')) return reject();
        if (!UInt64()) return reject();
        return accept();
    }

    //=====================================================================
    //  TSAttr = "TS" "," AttrFlags ("," CharString)* ;
    //=====================================================================
    private boolean TSAttr() {
        begin("TSAttr");
        if (!next("TS")) return reject();
        if (!next(',')) return reject();
        if (!AttrFlags()) return reject();
        while (TSAttr_0()) ;
        return accept();
    }

    //-------------------------------------------------------------------
    //  TSAttr_0 = "," CharString
    //-------------------------------------------------------------------
    private boolean TSAttr_0() {
        begin("");
        if (!next(',')) return rejectInner();
        if (!CharString()) return rejectInner();
        return acceptInner();
    }

    //=====================================================================
    //  TDAttr = "TD" "," AttrFlags ("," SidString)* ;
    //=====================================================================
    private boolean TDAttr() {
        begin("TDAttr");
        if (!next("TD")) return reject();
        if (!next(',')) return reject();
        if (!AttrFlags()) return reject();
        while (TDAttr_0()) ;
        return accept();
    }

    //-------------------------------------------------------------------
    //  TDAttr_0 = "," SidString
    //-------------------------------------------------------------------
    private boolean TDAttr_0() {
        begin("");
        if (!next(',')) return rejectInner();
        if (!SidString()) return rejectInner();
        return acceptInner();
    }

    //=====================================================================
    //  TXAttr = "TX" "," AttrFlags ("," OctetString)* ;
    //=====================================================================
    private boolean TXAttr() {
        begin("TXAttr");
        if (!next("TX")) return reject();
        if (!next(',')) return reject();
        if (!AttrFlags()) return reject();
        while (TXAttr_0()) ;
        return accept();
    }

    //-------------------------------------------------------------------
    //  TXAttr_0 = "," OctetString
    //-------------------------------------------------------------------
    private boolean TXAttr_0() {
        begin("");
        if (!next(',')) return rejectInner();
        if (!OctetString()) return rejectInner();
        return acceptInner();
    }

    //=====================================================================
    //  TBAttr = "TB" "," AttrFlags ("," ("0" / "1"))* ;
    //=====================================================================
    private boolean TBAttr() {
        begin("TBAttr");
        if (!next("TB")) return reject();
        if (!next(',')) return reject();
        if (!AttrFlags()) return reject();
        while (TBAttr_0()) ;
        return accept();
    }

    //-------------------------------------------------------------------
    //  TBAttr_0 = "," ("0" / "1")
    //-------------------------------------------------------------------
    private boolean TBAttr_0() {
        begin("");
        if (!next(',')) return rejectInner();
        if (!next('0')
            && !next('1')
            ) return rejectInner();
        return acceptInner();
    }

    //=====================================================================
    //  AttrFlags = "0x"? HexDigit+ ;
    //=====================================================================
    private boolean AttrFlags() {
        begin("AttrFlags");
        next("0x");
        if (!HexDigit()) return reject();
        while (HexDigit()) ;
        return accept();
    }

    //=====================================================================
    //  AceFlagString = AceFlag* {aceFlags} ;
    //=====================================================================
    private boolean AceFlagString() {
        begin("AceFlagString");
        while (AceFlag()) ;
        sem.aceFlags();
        return accept();
    }

    //=====================================================================
    //  AceFlag = ("CI" / "OI" / "NP" / "IO" / "ID" / "SA" / "FA")
    //    {aceFlag} ;
    //=====================================================================
    private boolean AceFlag() {
        begin("AceFlag");
        if (!next("CI")
            && !next("OI")
            && !next("NP")
            && !next("IO")
            && !next("ID")
            && !next("SA")
            && !next("FA")
            ) return reject();
        sem.aceFlag();
        return accept();
    }

    //=====================================================================
    //  AceRights = (TextRightsString / UInt64)? {aceRights} ;
    //=====================================================================
    private boolean AceRights() {
        begin("AceRights");
        AceRights_0();
        sem.aceRights();
        return accept();
    }

    //-------------------------------------------------------------------
    //  AceRights_0 = TextRightsString / UInt64
    //-------------------------------------------------------------------
    private boolean AceRights_0() {
        begin("");
        if (TextRightsString()) return acceptInner();
        if (UInt64()) return acceptInner();
        return rejectInner();
    }

    //=====================================================================
    //  TextRightsString = TextRight+ {textRights} ;
    //=====================================================================
    private boolean TextRightsString() {
        begin("TextRightsString");
        if (!TextRight()) return reject();
        while (TextRight()) ;
        sem.textRights();
        return accept();
    }

    //=====================================================================
    //  TextRight = (GenericRight / StandardRight / ObjectSpecificRight)
    //    {textRight} ;
    //=====================================================================
    private boolean TextRight() {
        begin("TextRight");
        if (!GenericRight()
            && !StandardRight()
            && !ObjectSpecificRight()
            ) return reject();
        sem.textRight();
        return accept();
    }

    //=====================================================================
    //  GenericRight = "GA" / "GW" / "GR" / "GX" ;
    //=====================================================================
    private boolean GenericRight() {
        begin("GenericRight");
        if (next("GA")) return accept();
        if (next("GW")) return accept();
        if (next("GR")) return accept();
        if (next("GX")) return accept();
        return reject();
    }

    //=====================================================================
    //  StandardRight = "WO" / "WD" / "RC" / "SD" ;
    //=====================================================================
    private boolean StandardRight() {
        begin("StandardRight");
        if (next("WO")) return accept();
        if (next("WD")) return accept();
        if (next("RC")) return accept();
        if (next("SD")) return accept();
        return reject();
    }

    //=====================================================================
    //  ObjectSpecificRight = FileAccessRight / RegistryKeyAccessRight /
    //    DirectoryAccessRight / MandatoryLabelAccessRight ;
    //=====================================================================
    private boolean ObjectSpecificRight() {
        begin("ObjectSpecificRight");
        if (FileAccessRight()) return accept();
        if (RegistryKeyAccessRight()) return accept();
        if (DirectoryAccessRight()) return accept();
        if (MandatoryLabelAccessRight()) return accept();
        return reject();
    }

    //=====================================================================
    //  FileAccessRight = "FA" / "FW" / "FR" / "FX" ;
    //=====================================================================
    private boolean FileAccessRight() {
        begin("FileAccessRight");
        if (next("FA")) return accept();
        if (next("FW")) return accept();
        if (next("FR")) return accept();
        if (next("FX")) return accept();
        return reject();
    }

    //=====================================================================
    //  RegistryKeyAccessRight = "KA" / "KW" / "KR" / "KX" ;
    //=====================================================================
    private boolean RegistryKeyAccessRight() {
        begin("RegistryKeyAccessRight");
        if (next("KA")) return accept();
        if (next("KW")) return accept();
        if (next("KR")) return accept();
        if (next("KX")) return accept();
        return reject();
    }

    //=====================================================================
    //  DirectoryAccessRight = "CR" / "LO" / "DT" / "WP" / "RP" / "SW" /
    //    "LC" / "DC" / "CC" ;
    //=====================================================================
    private boolean DirectoryAccessRight() {
        begin("DirectoryAccessRight");
        if (next("CR")) return accept();
        if (next("LO")) return accept();
        if (next("DT")) return accept();
        if (next("WP")) return accept();
        if (next("RP")) return accept();
        if (next("SW")) return accept();
        if (next("LC")) return accept();
        if (next("DC")) return accept();
        if (next("CC")) return accept();
        return reject();
    }

    //=====================================================================
    //  MandatoryLabelAccessRight = "NR" / "NW" / "NX" ;
    //=====================================================================
    private boolean MandatoryLabelAccessRight() {
        begin("MandatoryLabelAccessRight");
        if (next("NR")) return accept();
        if (next("NW")) return accept();
        if (next("NX")) return accept();
        return reject();
    }

    //=====================================================================
    //  Guid = (HexDigit8 "-" HexDigit4 "-" HexDigit4 "-" HexDigit4 "-"
    //    HexDigit12)? {guid} ;
    //=====================================================================
    private boolean Guid() {
        begin("Guid");
        Guid_0();
        sem.guid();
        return accept();
    }

    //-------------------------------------------------------------------
    //  Guid_0 = HexDigit8 "-" HexDigit4 "-" HexDigit4 "-" HexDigit4 "-"
    //    HexDigit12
    //-------------------------------------------------------------------
    private boolean Guid_0() {
        begin("");
        if (!HexDigit8()) return rejectInner();
        if (!next('-')) return rejectInner();
        if (!HexDigit4()) return rejectInner();
        if (!next('-')) return rejectInner();
        if (!HexDigit4()) return rejectInner();
        if (!next('-')) return rejectInner();
        if (!HexDigit4()) return rejectInner();
        if (!next('-')) return rejectInner();
        if (!HexDigit12()) return rejectInner();
        return acceptInner();
    }

    //=====================================================================
    //  CondExpr = CondAndExpr (wspace? "||" wspace? CondExpr)? ;
    //=====================================================================
    private boolean CondExpr() {
        begin("CondExpr");
        if (!CondAndExpr()) return reject();
        CondExpr_0();
        return accept();
    }

    //-------------------------------------------------------------------
    //  CondExpr_0 = wspace? "||" wspace? CondExpr
    //-------------------------------------------------------------------
    private boolean CondExpr_0() {
        begin("");
        wspace();
        if (!next("||")) return rejectInner();
        wspace();
        if (!CondExpr()) return rejectInner();
        return acceptInner();
    }

    //=====================================================================
    //  CondAndExpr = UnaryExpr (wspace? "&&" wspace? CondAndExpr)? ;
    //=====================================================================
    private boolean CondAndExpr() {
        begin("CondAndExpr");
        if (!UnaryExpr()) return reject();
        CondAndExpr_0();
        return accept();
    }

    //-------------------------------------------------------------------
    //  CondAndExpr_0 = wspace? "&&" wspace? CondAndExpr
    //-------------------------------------------------------------------
    private boolean CondAndExpr_0() {
        begin("");
        wspace();
        if (!next("&&")) return rejectInner();
        wspace();
        if (!CondAndExpr()) return rejectInner();
        return acceptInner();
    }

    //=====================================================================
    //  UnaryExpr = "!" wspace? UnaryExpr / "(" wspace? CondExpr wspace?
    //    ")" / Term ;
    //=====================================================================
    private boolean UnaryExpr() {
        begin("UnaryExpr");
        if (UnaryExpr_0()) return accept();
        if (UnaryExpr_1()) return accept();
        if (Term()) return accept();
        return reject();
    }

    //-------------------------------------------------------------------
    //  UnaryExpr_0 = "!" wspace? UnaryExpr
    //-------------------------------------------------------------------
    private boolean UnaryExpr_0() {
        begin("");
        if (!next('!')) return rejectInner();
        wspace();
        if (!UnaryExpr()) return rejectInner();
        return acceptInner();
    }

    //-------------------------------------------------------------------
    //  UnaryExpr_1 = "(" wspace? CondExpr wspace? ")"
    //-------------------------------------------------------------------
    private boolean UnaryExpr_1() {
        begin("");
        if (!next('(')) return rejectInner();
        wspace();
        if (!CondExpr()) return rejectInner();
        wspace();
        if (!next(')')) return rejectInner();
        return acceptInner();
    }

    //=====================================================================
    //  Term = wspace? (MemberofOp / ExistsOp / RelOp / ContainsOp /
    //    AnyofOp / RelOp2 / AttrName) wspace? ;
    //=====================================================================
    private boolean Term() {
        begin("Term");
        wspace();
        if (!MemberofOp()
            && !ExistsOp()
            && !RelOp()
            && !ContainsOp()
            && !AnyofOp()
            && !RelOp2()
            && !AttrName()
            ) return reject();
        wspace();
        return accept();
    }

    //=====================================================================
    //  MemberofOp = ("Member_of" / "Not_Member_of" / "Member_of_Any" /
    //    "Not_Member_of_Any" / "Device_Member_of" / "Device_Member_of_Any"
    //    / "Not_Device_Member_of" / "Not_Device_Member_of_Any") wspace
    //    SidArray ;
    //=====================================================================
    private boolean MemberofOp() {
        begin("MemberofOp");
        if (!next("Member_of")
            && !next("Not_Member_of")
            && !next("Member_of_Any")
            && !next("Not_Member_of_Any")
            && !next("Device_Member_of")
            && !next("Device_Member_of_Any")
            && !next("Not_Device_Member_of")
            && !next("Not_Device_Member_of_Any")
            ) return reject();
        if (!wspace()) return reject();
        if (!SidArray()) return reject();
        return accept();
    }

    //=====================================================================
    //  ExistsOp = ("Exists" / "Not_exists") wspace AttrName ;
    //=====================================================================
    private boolean ExistsOp() {
        begin("ExistsOp");
        if (!next("Exists")
            && !next("Not_exists")
            ) return reject();
        if (!wspace()) return reject();
        if (!AttrName()) return reject();
        return accept();
    }

    //=====================================================================
    //  RelOp = AttrName wspace? ("<" / "<=" / ">" / ">=") wspace?
    //    (AttrName2 / Value) ;
    //=====================================================================
    private boolean RelOp() {
        begin("RelOp");
        if (!AttrName()) return reject();
        wspace();
        if (!next('<')
            && !next("<=")
            && !next('>')
            && !next(">=")
            ) return reject();
        wspace();
        if (!AttrName2()
            && !Value()
            ) return reject();
        return accept();
    }

    //=====================================================================
    //  RelOp2 = AttrName wspace? ("==" / "!=") wspace? (AttrName2 /
    //    ValueArray) ;
    //=====================================================================
    private boolean RelOp2() {
        begin("RelOp2");
        if (!AttrName()) return reject();
        wspace();
        if (!next("==")
            && !next("!=")
            ) return reject();
        wspace();
        if (!AttrName2()
            && !ValueArray()
            ) return reject();
        return accept();
    }

    //=====================================================================
    //  ContainsOp = AttrName wspace? ("Contains" / "Not_Contains") wspace?
    //    (AttrName2 / ValueArray) ;
    //=====================================================================
    private boolean ContainsOp() {
        begin("ContainsOp");
        if (!AttrName()) return reject();
        wspace();
        if (!next("Contains")
            && !next("Not_Contains")
            ) return reject();
        wspace();
        if (!AttrName2()
            && !ValueArray()
            ) return reject();
        return accept();
    }

    //=====================================================================
    //  AnyofOp = AttrName wspace? ("Any_of" / "Not_Any_of") wspace?
    //    (AttrName2 / ValueArray) ;
    //=====================================================================
    private boolean AnyofOp() {
        begin("AnyofOp");
        if (!AttrName()) return reject();
        wspace();
        if (!next("Any_of")
            && !next("Not_Any_of")
            ) return reject();
        wspace();
        if (!AttrName2()
            && !ValueArray()
            ) return reject();
        return accept();
    }

    //=====================================================================
    //  AttrName1 = AttrChar1 (AttrChar1 / "@")* ;
    //=====================================================================
    private boolean AttrName1() {
        begin("AttrName1");
        if (!AttrChar1()) return reject();
        while (AttrName1_0()) ;
        return accept();
    }

    //-------------------------------------------------------------------
    //  AttrName1_0 = AttrChar1 / "@"
    //-------------------------------------------------------------------
    private boolean AttrName1_0() {
        begin("");
        if (AttrChar1()) return acceptInner();
        if (next('@')) return acceptInner();
        return rejectInner();
    }

    //=====================================================================
    //  AttrChar1 = (Alpha / Digit / ":" / "." / "/" / "_")+ ;
    //=====================================================================
    private boolean AttrChar1() {
        begin("AttrChar1");
        if (!AttrChar1_0()) return reject();
        while (AttrChar1_0()) ;
        return accept();
    }

    //-------------------------------------------------------------------
    //  AttrChar1_0 = Alpha / Digit / ":" / "." / "/" / "_"
    //-------------------------------------------------------------------
    private boolean AttrChar1_0() {
        begin("");
        if (Alpha()) return acceptInner();
        if (Digit()) return acceptInner();
        if (next(':')) return acceptInner();
        if (next('.')) return acceptInner();
        if (next('/')) return acceptInner();
        if (next('_')) return acceptInner();
        return rejectInner();
    }

    //=====================================================================
    //  AttrName2 = ("@" [uU] [sS] [eE] [rR] "." / "@" [dD] [eE] [vV] [iI]
    //    [cC] [eE] "." / "@" [rR] [eE] [sS] [oO] [uU] [rR] [cC] [eE] ".")
    //    AttrChar2+ ;
    //=====================================================================
    private boolean AttrName2() {
        begin("AttrName2");
        if (!AttrName2_0()
            && !AttrName2_1()
            && !AttrName2_2()
            ) return reject();
        if (!AttrChar2()) return reject();
        while (AttrChar2()) ;
        return accept();
    }

    //-------------------------------------------------------------------
    //  AttrName2_0 = "@" [uU] [sS] [eE] [rR] "."
    //-------------------------------------------------------------------
    private boolean AttrName2_0() {
        begin("");
        if (!next('@')) return rejectInner();
        if (!nextIn("uU")) return rejectInner();
        if (!nextIn("sS")) return rejectInner();
        if (!nextIn("eE")) return rejectInner();
        if (!nextIn("rR")) return rejectInner();
        if (!next('.')) return rejectInner();
        return acceptInner();
    }

    //-------------------------------------------------------------------
    //  AttrName2_1 = "@" [dD] [eE] [vV] [iI] [cC] [eE] "."
    //-------------------------------------------------------------------
    private boolean AttrName2_1() {
        begin("");
        if (!next('@')) return rejectInner();
        if (!nextIn("dD")) return rejectInner();
        if (!nextIn("eE")) return rejectInner();
        if (!nextIn("vV")) return rejectInner();
        if (!nextIn("iI")) return rejectInner();
        if (!nextIn("cC")) return rejectInner();
        if (!nextIn("eE")) return rejectInner();
        if (!next('.')) return rejectInner();
        return acceptInner();
    }

    //-------------------------------------------------------------------
    //  AttrName2_2 = "@" [rR] [eE] [sS] [oO] [uU] [rR] [cC] [eE] "."
    //-------------------------------------------------------------------
    private boolean AttrName2_2() {
        begin("");
        if (!next('@')) return rejectInner();
        if (!nextIn("rR")) return rejectInner();
        if (!nextIn("eE")) return rejectInner();
        if (!nextIn("sS")) return rejectInner();
        if (!nextIn("oO")) return rejectInner();
        if (!nextIn("uU")) return rejectInner();
        if (!nextIn("rR")) return rejectInner();
        if (!nextIn("cC")) return rejectInner();
        if (!nextIn("eE")) return rejectInner();
        if (!next('.')) return rejectInner();
        return acceptInner();
    }

    //=====================================================================
    //  AttrChar2 = AttrChar1 / LitChar ;
    //=====================================================================
    private boolean AttrChar2() {
        begin("AttrChar2");
        if (AttrChar1()) return accept();
        if (LitChar()) return accept();
        return reject();
    }

    //=====================================================================
    //  AttrName = AttrName2 / AttrName1 ;
    //=====================================================================
    private boolean AttrName() {
        begin("AttrName");
        if (AttrName2()) return accept();
        if (AttrName1()) return accept();
        return reject();
    }

    //=====================================================================
    //  SidArray = LiteralSID wspace? / "{" wspace? LiteralSID wspace? (","
    //    wspace? LiteralSID wspace?)* "}" ;
    //=====================================================================
    private boolean SidArray() {
        begin("SidArray");
        if (SidArray_0()) return accept();
        if (SidArray_1()) return accept();
        return reject();
    }

    //-------------------------------------------------------------------
    //  SidArray_0 = LiteralSID wspace?
    //-------------------------------------------------------------------
    private boolean SidArray_0() {
        begin("");
        if (!LiteralSID()) return rejectInner();
        wspace();
        return acceptInner();
    }

    //-------------------------------------------------------------------
    //  SidArray_1 = "{" wspace? LiteralSID wspace? ("," wspace?
    //    LiteralSID wspace?)* "}"
    //-------------------------------------------------------------------
    private boolean SidArray_1() {
        begin("");
        if (!next('{')) return rejectInner();
        wspace();
        if (!LiteralSID()) return rejectInner();
        wspace();
        while (SidArray_2()) ;
        if (!next('}')) return rejectInner();
        return acceptInner();
    }

    //-------------------------------------------------------------------
    //  SidArray_2 = "," wspace? LiteralSID wspace?
    //-------------------------------------------------------------------
    private boolean SidArray_2() {
        begin("");
        if (!next(',')) return rejectInner();
        wspace();
        if (!LiteralSID()) return rejectInner();
        wspace();
        return acceptInner();
    }

    //=====================================================================
    //  LiteralSID = "SID(" SidString ")" ;
    //=====================================================================
    private boolean LiteralSID() {
        begin("LiteralSID");
        if (!next("SID(")) return reject();
        if (!SidString()) return reject();
        if (!next(')')) return reject();
        return accept();
    }

    //=====================================================================
    //  ValueArray = "{" wspace? Value wspace? (wspace? Value wspace?)* "}"
    //    / Value wspace? ;
    //=====================================================================
    private boolean ValueArray() {
        begin("ValueArray");
        if (ValueArray_0()) return accept();
        if (ValueArray_1()) return accept();
        return reject();
    }

    //-------------------------------------------------------------------
    //  ValueArray_0 = "{" wspace? Value wspace? (wspace? Value wspace?)*
    //    "}"
    //-------------------------------------------------------------------
    private boolean ValueArray_0() {
        begin("");
        if (!next('{')) return rejectInner();
        wspace();
        if (!Value()) return rejectInner();
        wspace();
        while (ValueArray_2()) ;
        if (!next('}')) return rejectInner();
        return acceptInner();
    }

    //-------------------------------------------------------------------
    //  ValueArray_1 = Value wspace?
    //-------------------------------------------------------------------
    private boolean ValueArray_1() {
        begin("");
        if (!Value()) return rejectInner();
        wspace();
        return acceptInner();
    }

    //-------------------------------------------------------------------
    //  ValueArray_2 = wspace? Value wspace?
    //-------------------------------------------------------------------
    private boolean ValueArray_2() {
        begin("");
        wspace();
        if (!Value()) return rejectInner();
        wspace();
        return acceptInner();
    }

    //=====================================================================
    //  Value = Int64 / CharString / OctetString ;
    //=====================================================================
    private boolean Value() {
        begin("Value");
        if (Int64()) return accept();
        if (CharString()) return accept();
        if (OctetString()) return accept();
        return reject();
    }

    //=====================================================================
    //  Int64 = [+-]? ("0x" HexDigit+ / "0" OctalDigit+ / Digit+) {int64}
    //    ;
    //=====================================================================
    private boolean Int64() {
        begin("Int64");
        nextIn("+-");
        if (!Int64_0()
            && !Int64_1()
            && !Int64_2()
            ) return reject();
        sem.int64();
        return accept();
    }

    //-------------------------------------------------------------------
    //  Int64_0 = "0x" HexDigit+
    //-------------------------------------------------------------------
    private boolean Int64_0() {
        begin("");
        if (!next("0x")) return rejectInner();
        if (!HexDigit()) return rejectInner();
        while (HexDigit()) ;
        return acceptInner();
    }

    //-------------------------------------------------------------------
    //  Int64_1 = "0" OctalDigit+
    //-------------------------------------------------------------------
    private boolean Int64_1() {
        begin("");
        if (!next('0')) return rejectInner();
        if (!OctalDigit()) return rejectInner();
        while (OctalDigit()) ;
        return acceptInner();
    }

    //-------------------------------------------------------------------
    //  Int64_2 = Digit+
    //-------------------------------------------------------------------
    private boolean Int64_2() {
        begin("");
        if (!Digit()) return rejectInner();
        while (Digit()) ;
        return acceptInner();
    }

    //=====================================================================
    //  UInt64 = ("0x" HexDigit+ / "0" OctalDigit+ / Digit+) {uint64} ;
    //=====================================================================
    private boolean UInt64() {
        begin("UInt64");
        if (!Int64_0()
            && !Int64_1()
            && !Int64_2()
            ) return reject();
        sem.uint64();
        return accept();
    }

    //=====================================================================
    //  CharString = DQUOTE Char* DQUOTE ;
    //=====================================================================
    private boolean CharString() {
        begin("CharString");
        if (!DQUOTE()) return reject();
        while (Char()) ;
        if (!DQUOTE()) return reject();
        return accept();
    }

    //=====================================================================
    //  Char = [\u0001-!] / [#-] ;
    //=====================================================================
    private boolean Char() {
        begin("Char");
        if (nextIn('\u0001', '!')) return accept();
        if (nextIn('#', '\u007f')) return accept();
        return reject();
    }

    //=====================================================================
    //  OctetString = "#" HexDigit2* ;
    //=====================================================================
    private boolean OctetString() {
        begin("OctetString");
        if (!next('#')) return reject();
        while (HexDigit2()) ;
        return accept();
    }

    //=====================================================================
    //  LitChar = ("#" / "$" / "'" / "*" / "+" / "-" / "." / "/" / ":" /
    //    ";" / "?" / "@" / "[" / BACKSLASH / RBRACKET / "^" / "_" / "`" /
    //    "{" / "}" / "~" / [-\uffff] / "%" HexDigit4) ;
    //=====================================================================
    private boolean LitChar() {
        begin("LitChar");
        if (!next('#')
            && !next('$')
            && !next('\'')
            && !next('*')
            && !next('+')
            && !next('-')
            && !next('.')
            && !next('/')
            && !next(':')
            && !next(';')
            && !next('?')
            && !next('@')
            && !next('[')
            && !BACKSLASH()
            && !RBRACKET()
            && !next('^')
            && !next('_')
            && !next('`')
            && !next('{')
            && !next('}')
            && !next('~')
            && !nextIn('\u0080', '\uffff')
            && !LitChar_0()
            ) return reject();
        return accept();
    }

    //-------------------------------------------------------------------
    //  LitChar_0 = "%" HexDigit4
    //-------------------------------------------------------------------
    private boolean LitChar_0() {
        begin("");
        if (!next('%')) return rejectInner();
        if (!HexDigit4()) return rejectInner();
        return acceptInner();
    }

    //=====================================================================
    //  Alpha = [a-z] / [A-Z] ;
    //=====================================================================
    private boolean Alpha() {
        begin("Alpha");
        if (nextIn('a', 'z')) return accept();
        if (nextIn('A', 'Z')) return accept();
        return reject();
    }

    //=====================================================================
    //  Digit = [0-9] ;
    //=====================================================================
    private boolean Digit() {
        begin("Digit");
        if (!nextIn('0', '9')) return reject();
        return accept();
    }

    //=====================================================================
    //  OctalDigit = [01234567] ;
    //=====================================================================
    private boolean OctalDigit() {
        begin("OctalDigit");
        if (!nextIn("01234567")) return reject();
        return accept();
    }

    //=====================================================================
    //  HexDigit = [0123456789abcdefABCDEF] ;
    //=====================================================================
    private boolean HexDigit() {
        begin("HexDigit");
        if (!nextIn("0123456789abcdefABCDEF")) return reject();
        return accept();
    }

    //=====================================================================
    //  HexDigit2 = HexDigit HexDigit ;
    //=====================================================================
    private boolean HexDigit2() {
        begin("HexDigit2");
        if (!HexDigit()) return reject();
        if (!HexDigit()) return reject();
        return accept();
    }

    //=====================================================================
    //  HexDigit4 = HexDigit HexDigit HexDigit HexDigit ;
    //=====================================================================
    private boolean HexDigit4() {
        begin("HexDigit4");
        if (!HexDigit()) return reject();
        if (!HexDigit()) return reject();
        if (!HexDigit()) return reject();
        if (!HexDigit()) return reject();
        return accept();
    }

    //=====================================================================
    //  HexDigit8 = HexDigit4 HexDigit4 ;
    //=====================================================================
    private boolean HexDigit8() {
        begin("HexDigit8");
        if (!HexDigit4()) return reject();
        if (!HexDigit4()) return reject();
        return accept();
    }

    //=====================================================================
    //  HexDigit12 = HexDigit8 HexDigit4 ;
    //=====================================================================
    private boolean HexDigit12() {
        begin("HexDigit12");
        if (!HexDigit8()) return reject();
        if (!HexDigit4()) return reject();
        return accept();
    }

    //=====================================================================
    //  wspace = [ \r\n\t]+ ;
    //=====================================================================
    private boolean wspace() {
        begin("wspace");
        if (!nextIn(" \r\n\t")) return reject();
        while (nextIn(" \r\n\t")) ;
        return accept();
    }

    //=====================================================================
    //  DQUOTE = ["] ;
    //=====================================================================
    private boolean DQUOTE() {
        begin("DQUOTE");
        if (!next('"')) return reject();
        return accept();
    }

    //=====================================================================
    //  BACKSLASH = "\" ;
    //=====================================================================
    private boolean BACKSLASH() {
        begin("BACKSLASH");
        if (!next('\\')) return reject();
        return accept();
    }

    //=====================================================================
    //  RBRACKET = "]" ;
    //=====================================================================
    private boolean RBRACKET() {
        begin("RBRACKET");
        if (!next(']')) return reject();
        return accept();
    }

}
