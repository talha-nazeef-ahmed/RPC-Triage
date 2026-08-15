#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 
#@runtime Jython


#TODO Add User Code Here

import jarray
import os
import json
import java.lang.Exception
from collections import OrderedDict

# Dict that maps ndr opcodes with some semantic string
NDR_OPCODE_MAP = {
    # Scalars (Boring and low risk)
    0x01: "FC_BYTE | Boring",
    0x02: "FC_CHAR | Boring",
    0x03: "FC_SMALL | Boring",
    0x04: "FC_USMALL | Boring",
    0x05: "FC_WCHAR | Boring",
    0x06: "FC_SHORT | Boring",
    0x07: "FC_USHORT | Boring",
    0x08: "FC_LONG | Boring",
    0x09: "FC_ULONG | Boring",
    0x0a: "FC_FLOAT | Boring",
    0x0b: "FC_HYPER | Boring",
    0x0c: "FC_DOUBLE | Boring",
    0x0d: "FC_ENUM16 | Low", # 16 bit on wire & 32 bit in memory
    0x0e: "FC_ENUM32 | Boring",
    0x0f: "FC_IGNORE | Boring",
    0x10: "FC_ERROR_STATUS_T | Boring",
    # Pointers (Moderate risk)
    0x11: "FC_RP | Moderate",
    0x12: "FC_UP | Moderate",
    0x13: "FC_OP | High", # If IID isnt validated the vtable type confusion occurs
    0x14: "FC_FP | High", # Bugs in translation table could lead to UAF
    # Structures (High risk as it req parsing logic)
    0x15: "FC_STRUCT | Moderate", # Flat structure with fixed size
    0x16: "FC_PSTRUCT | High",
    0x17: "FC_CSTRUCT | High",
    0x18: "FC_CPSTRUCT | High",
    0x19: "FC_CVSTRUCT | High",
    0x1a: "FC_BOGUS_STRUCT | Red",
    # Arrays (Red, cool targets for buffer overflow & Moderate ones r fixed size)
    0x1b: "FC_CARRAY | Red",
    0x1c: "FC_CVARRAY | Red",
    0x1d: "FC_SMFARRAY | Moderate",
    0x1e: "FC_LGFARRAY | Moderate",
    0x1f: "FC_SMVARRAY | Red",
    0x20: "FC_LGVARRAY | Red",
    0x21: "FC_BOGUS_ARRAY | Red",
    # Strings (Red, cool targets for memory corruption & Moderate ones r fixed size)
    0x22: "FC_C_CSTRING | Red",
    0x23: "FC_C_BSTRING | Red",
    0x24: "FC_C_SSTRING | Red",
    0x25: "FC_C_WSTRING | Red",
    0x26: "FC_CSTRING | Moderate",
    0x27: "FC_BSTRING | Moderate",
    0x28: "FC_SSTRING | Moderate",
    0x29: "FC_WSTRING | Moderate",
    # Unions (High, targets for type confusion)
    0x2a: "FC_ENCAPSULATED_UNION | High",
    0x2b: "FC_NON_ENCAPSULATED_UNION | Red", # External discriminant could enable TOCTOU style confusion
    # Handles & Interfaces (High, state manipulation)
    0x2f: "FC_IP | High",
    0x30: "FC_BIND_CONTEXT | High",
    0x31: "FC_BIND_GENERIC | High",
    0x3c: "FC_SYSTEM_HANDLE (Win8+) / FC_UNUSED4 | High / Boring", 
    # Advanced/Special opcodes
    0xb1: "FC_HARD_STRUCT | High",
    0xb2: "FC_TRANSMIT_AS_PTR | Red", # External arbitrary code on attacker data
    0xb3: "FC_REPRESENT_AS_PTR | Red", # Same reason as 0xb2
    0xb4: "FC_USER_MARSHAL | Red", # If you find this then boy its bad for the interface, maybe I am glazing but it has quite some potential
    0xb7: "FC_RANGE | Low", # Its just a validator, maybe moderate in some cases
    0xb8: "FC_INT3264 | Boring",
    0xb9: "FC_UINT3264 | Boring",
    # Useful ones
    0x2c: "FC_BYTE_COUNT_POINTER | Red", # Memory size is defined by separate variable
    0x2d: "FC_TRANSMIT_AS | Red", # Pass the data to external developer written routines
    0x2e: "FC_REPRESENT_AS | Red", # Functionally quite similar as 0x2d 
    0xb5: "FC_PIPE | High", # Possibility of UAF or state confusion 
    0x32: "FC_BIND_PRIMITIVE | Low", # No state context attached
    0xb6: "FC_BLKHOLE | Boring" # Just to be helpful when fuzzing
}


# AHP DERIVED SURFACE WEIGHTS (The "Danger" Axis)
# See 'Surface_Scoring_Methodology.md' for the complete mathematical proof.
SURFACE_SIGNAL_WEIGHTS = {
    "HasUserMarshal": {"Weight": 100, "Targets": ["FC_USER_MARSHAL"]},
    "HasTransmitAs": {"Weight": 83, "Targets": ["FC_TRANSMIT_AS", "FC_REPRESENT_AS"]},
    "HasBogusStruct": {"Weight": 61, "Targets": ["FC_BOGUS_STRUCT"]},
    "HasCallerSizedBuffer": {"Weight": 49, "Targets": ["FC_CARRAY", "FC_CVARRAY", "FC_C_WSTRING", "FC_C_CSTRING", "FC_SMVARRAY", "FC_LGVARRAY", "FC_BOGUS_ARRAY"]},
    "HasByteCountPointer": {"Weight": 38, "Targets": ["FC_BYTE_COUNT_POINTER"]},
    "HasNonEncapUnion": {"Weight": 29, "Targets": ["FC_NON_ENCAPSULATED_UNION"]},
    "HasObjectPointer": {"Weight": 21, "Targets": ["FC_OP"]},
    "HasPipe": {"Weight": 19, "Targets": ["FC_PIPE"]},
    "HasInterfacePointer": {"Weight": 14, "Targets": ["FC_IP"]},
    "HasSystemHandle": {"Weight": 13, "Targets": ["FC_SYSTEM_HANDLE (Win8+) / FC_UNUSED4"]}
}

# AHP DERIVED GATE WEIGHTS (The "Reachability" Axis)
GATE_TRANSPORT_BASE = {
    "All": 100,             
    "ncacn_ip_tcp": 77,    
    "ncacn_nb": 55,
    "ncacn_np": 41,
    "Dynamic / epmapper": 29,
    "ncalrpc": 18,          
    "lrpc": 18,             
}

# GATE MODIFIERS (Security Flags)
GATE_MODIFIERS = {
    "LocalCallOnly": -100,   
    "SecureOnly": -65,
    "HasBouncer": -46,
    "DirectPassToBouncer": 35, 
    "BouncerIsNotCaching": 25, 
    "PerProcessCache": 21,  # (There was a calculator slip in initial calculations which was 19, 21 is the correct one)
    "BaseVariant": 16        
}


def decodeNdrOpcode(byte):
    return NDR_OPCODE_MAP.get(byte, "Unknown Opcode (" + hex(byte) + ") | Consult Docs")

def littleEndianReader(byteArray):
    pointer = 0
    for i in range(len(byteArray)):
        cleanByte = byteArray[i] & 0xFF
        pointer = pointer | (cleanByte << (8 * i))
    return pointer

def bigEndianReader(byteArray):
    pointer = 0
    for i in range(len(byteArray)):
        cleanByte = byteArray[i] & 0xFF
        pointer = pointer | (cleanByte << (8 * (((len(byteArray) - 1 ) -i))))      
    return pointer

def getUuid(address):
    chunk1 = jarray.zeros(4, "b")
    chunk2 = jarray.zeros(2, "b")
    chunk3 = jarray.zeros(2, "b")
    chunk4 = jarray.zeros(2, "b")
    chunk5 = jarray.zeros(6, "b")
    uuidMemory = getCurrentProgram().getMemory()
    uuidMemory.getBytes(address.add(4), chunk1)
    uuidMemory.getBytes(address.add(8), chunk2)
    uuidMemory.getBytes(address.add(10), chunk3)
    uuidMemory.getBytes(address.add(12), chunk4)
    uuidMemory.getBytes(address.add(14), chunk5)
    part1 = littleEndianReader(chunk1)
    part2 = littleEndianReader(chunk2)
    part3 = littleEndianReader(chunk3)
    part4 = bigEndianReader(chunk4)
    part5 = bigEndianReader(chunk5)
    result = '{:08x}-{:04x}-{:04x}-{:04x}-{:012x}'.format(part1, part2, part3, part4, part5)
    return result

def getCallSites(checkList):
    symTable = getCurrentProgram().getSymbolTable()
    symImports = []
    callSites = []
    for server in checkList:
        symList = symTable.getSymbols(server)
        if symList:
            for sym in symList:
                if sym.isExternal():
                    symImports.append((server, sym.getAddress()))
        else:   
            continue
    refManager = getCurrentProgram().getReferenceManager()  
    for data in symImports:
        name, address = data
        references = refManager.getReferencesTo(address)
        if references:
            for reference in references:
                if reference.getReferenceType().isCall():
                    callSites.append((name, reference.getFromAddress()))
        else:
            continue
    return callSites

def getReg(address, regName):
    instruction = getCurrentProgram().getListing().getInstructionAt(address)
    for i in range(50):
        prevInstruction = instruction.getPrevious()
        if prevInstruction is None:
            break
        if prevInstruction.getMnemonicString() == "LEA" or prevInstruction.getMnemonicString() == "MOV":
            register = prevInstruction.getRegister(0)
            if register is not None and register.getName().upper() == regName:
                references = prevInstruction.getReferencesFrom()
                if references:
                    reference = references[0].getToAddress()
                    if reference.isMemoryAddress():
                        return reference
                    else:
                        pass
        instruction = prevInstruction
    return None

def getMidlServerInfo(address):
    if address is None:
        return None
    try:
        offset = address.add(0x50)
        byteBuffer = jarray.zeros(8, "b")
        midlMemory = getCurrentProgram().getMemory()
        midlMemory.getBytes(offset, byteBuffer)
        cleanBytes = littleEndianReader(byteBuffer)
        midlAddress = toAddr(cleanBytes)
        return midlAddress 
    except (Exception, java.lang.Exception) as e:
        errorMsg = "Error: " + str(e)
        return None

def getStubDesc(address):
    byteBuffer = jarray.zeros(8, "b")
    try:
        getCurrentProgram().getMemory().getBytes(address, byteBuffer)
        cleanBytes = littleEndianReader(byteBuffer)
        stubDescAddress = toAddr(cleanBytes)
        return stubDescAddress
    except:
        return None
    
def getStoredCount(address):
    if address is None:
        return 0
    try:
        byteBuffer = jarray.zeros(8, "b")
        getCurrentProgram().getMemory().getBytes(address.add(0x30), byteBuffer)
        dispatchTablePtr = toAddr(littleEndianReader(byteBuffer))
        countBuffer = jarray.zeros(4, "b")
        getCurrentProgram().getMemory().getBytes(dispatchTablePtr, countBuffer)
        cleanBytes = littleEndianReader(countBuffer)
        return cleanBytes
    except (Exception, java.lang.Exception) as e:
        errorMsg = "Error: " + str(e)
        return 0

def getDispatchTable(address):
    if address is None:
        return "Memory Error", 0
    try:
        byteBuffer = jarray.zeros(8, "b")
        memory = getCurrentProgram().getMemory()
        memory.getBytes(address.add(0x08), byteBuffer)
        cleanBytes = littleEndianReader(byteBuffer)
        dispatchTableAddress = toAddr(cleanBytes)
        safeCopyDispatchTableAddress = dispatchTableAddress
        totalFunc = 0
        while True:
            if monitor.isCancelled():
                raise Exception("[-] Walk cancelled by the monitor! Infinite loop detected.")
            memory.getBytes(dispatchTableAddress, byteBuffer)
            cleanBytes = littleEndianReader(byteBuffer)
            if cleanBytes == 0:
                break
            funcAddress = toAddr(cleanBytes)
            memoryBlock = memory.getBlock(funcAddress)
            if memoryBlock is not None and memoryBlock.isExecute():
                totalFunc += 1
            else:
                break
            dispatchTableAddress = dispatchTableAddress.add(0x08)
        return safeCopyDispatchTableAddress, totalFunc
    except (Exception, java.lang.Exception) as e:
        errorMsg = "Error: " + str(e)
        return "Memory Error", 0
    
def getFormatString(address, totalFunc):
    if address is None:
        return []
    try:
        byteBuffer = jarray.zeros(8, "b")
        getCurrentProgram().getMemory().getBytes(address.add(0x18), byteBuffer)
        cleanBytes = littleEndianReader(byteBuffer)
        formatStringAddress = toAddr(cleanBytes)
        formatString = []
        byteBuffer = jarray.zeros(2, "b")
        for i in range(totalFunc):
            getCurrentProgram().getMemory().getBytes(formatStringAddress, byteBuffer)        
            cleanBytes = littleEndianReader(byteBuffer)
            formatString.append(cleanBytes)
            formatStringAddress = formatStringAddress.add(0x02)
        return formatString
    except (Exception, java.lang.Exception) as e:
        errorMsg = "Error: " + str(e)
        return errorMsg, []
    
def getNameString(address, isWide):
    size = 2 if isWide else 1
    offset = 0
    result = ""
    try:
        byteBuffer = jarray.zeros(size, "b")
        memory = getCurrentProgram().getMemory()
        for check in range(100):
            memory.getBytes(address.add(offset), byteBuffer)
            cleanBytes = littleEndianReader(byteBuffer)
            if cleanBytes == 0x00:
                break
            if 32 <= cleanBytes < 256:
                result += chr(cleanBytes)
            else:
                result += "?"
            offset += size
    except Exception:
        pass 
    return result
    
def getFlag(address):
    instruction = getCurrentProgram().getListing().getInstructionAt(address)
    for i in range(15):
        prevInstruction = instruction.getPrevious()
        if prevInstruction is None:
            break
        if prevInstruction.getMnemonicString() == "LEA" or prevInstruction.getMnemonicString() == "MOV":
            register = prevInstruction.getRegister(0)
            if register is not None and register.getName().upper() == "R9":
                scalar = prevInstruction.getScalar(1)
                if scalar is not None:
                    return scalar.getValue()
                else:
                    return None
        instruction = prevInstruction
    return None
    
def checkBouncer(address, stackInsString):
    instruction = getCurrentProgram().getListing().getInstructionAt(address)
    for i in range(15):
        prevInstruction = instruction.getPrevious()
        if prevInstruction is None:
            break
        if prevInstruction.getMnemonicString() == "MOV":
            insString = prevInstruction.toString()
            if stackInsString in insString.upper():
                scalar = prevInstruction.getScalar(1)
                if scalar is not None:
                    value = scalar.getValue()  
                    if value == 0x00:
                        return False 
                return True 
        instruction = prevInstruction
    return False
    
    
def getBitmaskFlag(scalarValue, checkFlagValue):
    if scalarValue & checkFlagValue != 0:
        return True
    return False
    
def decodeFlags(r9Flag):
    flagValues = OrderedDict([
                ("AutoListen", False),
                ("OleFlag", False),
                ("ThirdPartyAuth", False),
                ("SecureOnly", False),
                ("DirectPassToBouncer", False),
                ("LocalCallOnly", False),
                ("BouncerIsNotCaching", False),
                ("PerProcessCache", False)
            ])
    if r9Flag is None:
        flagsList = ["N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A"]
    else:
        flagsList = []
        autoListen = getBitmaskFlag(r9Flag, 1)
        flagsList.append(autoListen)
        flagValues["AutoListen"] = autoListen
        oleFlag = getBitmaskFlag(r9Flag, 2)
        flagsList.append(oleFlag)
        flagValues["OleFlag"] = oleFlag
        thirdPartyAuth = getBitmaskFlag(r9Flag, 4)
        flagsList.append(thirdPartyAuth)
        flagValues["ThirdPartyAuth"] = thirdPartyAuth
        secureOnly = getBitmaskFlag(r9Flag, 8)
        flagsList.append(secureOnly)
        flagValues["SecureOnly"] = secureOnly
        directPassToBouncer = getBitmaskFlag(r9Flag, 16)
        flagsList.append(directPassToBouncer)
        flagValues["DirectPassToBouncer"] = directPassToBouncer
        localCallOnly = getBitmaskFlag(r9Flag, 32)
        flagsList.append(localCallOnly)
        flagValues["LocalCallOnly"] = localCallOnly 
        bouncerIsNotCaching = getBitmaskFlag(r9Flag, 64)
        flagsList.append(bouncerIsNotCaching)
        flagValues["BouncerIsNotCaching"] = bouncerIsNotCaching
        perProcessCache = getBitmaskFlag(r9Flag, 128)
        flagsList.append(perProcessCache)
        flagValues["PerProcessCache"] = perProcessCache
    
    return flagsList, flagValues
    
    
def getSecDesc(callSite):
    checkList = ["ConvertStringSecurityDescriptorToSecurityDescriptorW", "ConvertStringSecurityDescriptorToSecurityDescriptorA"]
    instruction = getCurrentProgram().getListing().getInstructionAt(callSite)
    for i in range(100):
        prevInstruction = instruction.getPrevious()
        if prevInstruction is None:
            break
        if prevInstruction.getMnemonicString() == "CALL":
            flows = prevInstruction.getFlows()
            if flows:
                targetAddr = flows[0]
                symTable = getCurrentProgram().getSymbolTable()
                sym = symTable.getPrimarySymbol(targetAddr)
                if sym is not None:
                    symName = sym.getName()
                    if "ConvertStringSecurityDescriptorToSecurityDescriptor" in symName:
                        isWide = "W" in symName
                        callAddr = prevInstruction.getAddress()
                        rcxAddress = getReg(callAddr, "RCX")
                        if rcxAddress is not None:
                            secDescStr = getNameString(rcxAddress, isWide)
                            if len(secDescStr) > 0:
                                return secDescStr
        instruction = prevInstruction
    return None
    
def getFormatTypes(stubDescAddress):
    if stubDescAddress is None:
        return "Memory Error", 0
    try:
        byteBuffer = jarray.zeros(8, "b")
        memory = getCurrentProgram().getMemory()
        memory.getBytes(stubDescAddress.add(0x40), byteBuffer)
        cleanBytes = littleEndianReader(byteBuffer)
        formatTypeAddress = toAddr(cleanBytes)
        return formatTypeAddress
    except (Exception, java.lang.Exception) as e:
        return []  
        

    
    
def readProcString(formatString, midlAddress, stubDescAddress):
    if midlAddress is None or stubDescAddress is None:
        return []
    try:
        byteBuffer = jarray.zeros(8, "b")
        memory = getCurrentProgram().getMemory()
        memory.getBytes(midlAddress.add(0x10), byteBuffer)
        cleanBytes = littleEndianReader(byteBuffer)
        procStringAddr = toAddr(cleanBytes)
        methodList = []
        for i in range(len(formatString)):
            # Reading the header
            offset = procStringAddr.add(formatString[i])
            handleTypeBuffer = jarray.zeros(1, "b")
            memory.getBytes(offset, handleTypeBuffer)
            cleanBytes = littleEndianReader(handleTypeBuffer)
            handleType = "Implicit"
            if cleanBytes == 0x00:
                handleType = "Explicit"
            oiFlagsBuffer = jarray.zeros(1, "b")
            memory.getBytes(offset.add(0x01), oiFlagsBuffer)
            oiFlags = littleEndianReader(oiFlagsBuffer)
            hasRpc = getBitmaskFlag(oiFlags, 0x08)
            offset = offset.add(0x02) # Adding handleType and oiFlag bytes
            if hasRpc:
                offset = offset.add(0x04)
            procNumBuffer = jarray.zeros(2, "b")
            memory.getBytes(offset, procNumBuffer)
            procNum = littleEndianReader(procNumBuffer)
            offset = offset.add(0x04) # Adding procNum + skipping stackSize
            if handleType == "Explicit":
                handleDescSizeBuffer = jarray.zeros(1, "b")
                memory.getBytes(offset, handleDescSizeBuffer)
                handleDescSize = littleEndianReader(handleDescSizeBuffer)
                if handleDescSize == 0x32:
                    offset = offset.add(0x04) # FC_BIND_PRIMITIVE is 4 bytes
                else:
                    offset = offset.add(0x06) # FC_BIND_CONTEXT or GENERIC is 6 bytes
            offset = offset.add(0x04) # Skipping buffer hints
            memory.getBytes(offset, oiFlagsBuffer)
            oi2Flags = littleEndianReader(oiFlagsBuffer)
            serverMustSize = getBitmaskFlag(oi2Flags, 0x01)
            clientMustSize = getBitmaskFlag(oi2Flags, 0x02)
            hasExtensions = getBitmaskFlag(oi2Flags, 0x40)
            noOfParamBuffer = jarray.zeros(1, "b")
            memory.getBytes(offset.add(0x01), noOfParamBuffer)
            noOfParam = littleEndianReader(noOfParamBuffer)
            offset = offset.add(0x02) # Adding oi2Flag and noOfParam
            methodDict = OrderedDict([
                ("MethodIndex", i),
                ("Opnum", procNum),
                ("HandleType", handleType),
                ("MethodFlags", []),
                ("ParamCount", noOfParam),
                ("Parameters", [])
            ])
            if serverMustSize:
                methodDict["MethodFlags"].append("ServerMustSize")
            if clientMustSize:
                methodDict["MethodFlags"].append("ClientMustSize")
            if hasExtensions:
                extensionHeaderSizeBuffer = jarray.zeros(1, "b")
                memory.getBytes(offset, extensionHeaderSizeBuffer)
                extHeaderSize = littleEndianReader(extensionHeaderSizeBuffer)
                offset = offset.add(extHeaderSize) # Skipping extension header
                copyOffset = offset
            # Test
            if (i + 1) != len(formatString):
                copyOffset = copyOffset.add(0x06 * noOfParam)
                checkOffset = procStringAddr.add(formatString[i + 1])
                if copyOffset.toString() != checkOffset.toString():
                    methodDict["Status"] = "Boundary Test Failed (My Math Offset: {} | ProcString Offset: {})".format(copyOffset.toString(), checkOffset.toString())
                else:
                    methodDict["Status"] = "OK"
            else:
                methodDict["Status"] = "OK (Last Method)"
            
            for i in range(noOfParam):
                param = readParam(offset, stubDescAddress)
                param["ParameterNo"] = str(i)
                offset = offset.add(0x06)
                methodDict["Parameters"].append(param)
            methodList.append(methodDict)
        return methodList
    except (Exception, java.lang.Exception) as e:
        errorMsg = "Error: " + str(e)
        return [{"Status": errorMsg}]
        
        
def readParam(paramOffset, stubDescAddress):
    memory = getCurrentProgram().getMemory()
    paramAttributeBuffer = jarray.zeros(2, "b")
    memory.getBytes(paramOffset, paramAttributeBuffer)
    paramAttribute = littleEndianReader(paramAttributeBuffer)
    isBaseType = getBitmaskFlag(paramAttribute, 0x0040)
    isIn = getBitmaskFlag(paramAttribute, 0x0008)
    isOut = getBitmaskFlag(paramAttribute, 0x0010)
    func = "Undetermined"
    if isIn & isOut:
        func = "[in, out]"
    elif isOut:
        func = "[out]"
    elif isIn:
        func = "[in]"
    paramType = "Complex"
    opCodeBuffer = jarray.zeros(1, "b")
    paramOffset = paramOffset.add(0x04)
    if isBaseType:
        paramType = "Simple"
        memory.getBytes(paramOffset, opCodeBuffer)
        opCode = littleEndianReader(opCodeBuffer)
        decOpCode = decodeNdrOpcode(opCode)
    else:
        offsetBuffer = jarray.zeros(2, "b")
        memory.getBytes(paramOffset, offsetBuffer)
        offset = littleEndianReader(offsetBuffer)
        formatTypeAddr = getFormatTypes(stubDescAddress)
        finalAddr = formatTypeAddr.add(offset)
        memory.getBytes(finalAddr, opCodeBuffer)
        opCode = littleEndianReader(opCodeBuffer)
        decOpCode = decodeNdrOpcode(opCode)
        
    paramDict = OrderedDict([
        ("ParameterNo", "N/A"), # Would be declared in the parent loop
        ("Type", paramType),
        ("IsSimpleRef", getBitmaskFlag(paramAttribute, 0x0100)),
        ("Functionality", func), 
        ("Opcode", hex(opCode)),
        ("DecodedOpcode", decOpCode)
    ])
    return paramDict
    
def computeSurfaceSignals(methodsList, storedCount):
    signalDict = OrderedDict([
                ("FiredSignals", OrderedDict()),
                ("InPointerCount", 0),
                ("CountContribution", 0),
                ("TopSignalsForReceipt", []),
                ("SignatureConfidence", "High"),
                ("RawSignalTotal", 0)
            ])
    
    pointersList = ["FC_RP", "FC_UP", "FC_OP", "FC_FP", "FC_IP", "FC_STRUCT", "FC_ARRAY", "FC_UNION", "FC_BOGUS"]
    for method in methodsList:
        opnum = method.get("Opnum")
        parametersList = method.get("Parameters", [])
        status = method.get("Status", "")
        if "Boundary Test Failed" in status:
            signalDict["SignatureConfidence"] = "Low"
        for parameter in parametersList:
            func = parameter.get("Functionality", "")
            opcode = parameter.get("DecodedOpcode", "")
            if func in ("[in]", "[in, out]"):
                for pointer in pointersList:
                    if pointer in opcode:
                        signalDict["InPointerCount"] += 1
                        break
            if func in ("[in]", "[in, out]") or "FC_SYSTEM_HANDLE" in opcode:
                for signalName, data in SURFACE_SIGNAL_WEIGHTS.items():
                    for target in data["Targets"]:
                        if target in opcode:
                            if signalName not in signalDict["FiredSignals"]:                               
                                signalDict["FiredSignals"][signalName] = {
                                    "Count": 1, "Opnums": [str(opnum)], "Func": func, "Target": target, "Weight": data["Weight"]
                                }
                            else:                                
                                signalDict["FiredSignals"][signalName]["Count"] += 1
                                if str(opnum) not in signalDict["FiredSignals"][signalName]["Opnums"]:
                                    signalDict["FiredSignals"][signalName]["Opnums"].append(str(opnum))
    
    if not methodsList or (len(methodsList) > 0 and "Error" in methodsList[0].get("Status", "")):
        signalDict["SignatureConfidence"] = "Low"
    if storedCount > 0:
        signalDict["CountContribution"] = 2 * (storedCount.bit_length() - 1)
        
    for sigName, data in signalDict["FiredSignals"].items():
        opnumsStr = ",".join(data["Opnums"])
        signalDict["TopSignalsForReceipt"].append((sigName, data["Count"], opnumsStr, data["Func"], data["Target"], data["Weight"]))
        signalDict["RawSignalTotal"] += data["Weight"]
        
    signalDict["TopSignalsForReceipt"].sort(key = lambda x: x[5], reverse = True) # Sorting by weight desc
    
    return signalDict
    

def rankInterface(r9Flag, bouncer, allEndpoints, surfaceSignals, registrationVariant, storedCount):
    # First calculating the gate score
    flagsList, flagValues = decodeFlags(r9Flag)
    transportScore = 0
    transportName = "Unknown"
    for key, value in GATE_TRANSPORT_BASE.items():
        if key == "All" and "Protocol: All |" in allEndpoints:
            transportScore = value
            transportName = key
        elif key != "All" and key.lower() in allEndpoints.lower() and value > transportScore:
            transportScore = value
            transportName = key
    if transportScore == 0:
        transportScore = 40 # If no endpoint is resolved then a fallback hardcoded value
        transportName = "Unknown"
    gateReceiptList = ["{}:{}".format(transportName, transportScore)]
    uniqueTransports = len(allEndpoints.split(" ||| "))
    if uniqueTransports > 1:
        bonus = min(15, (uniqueTransports - 1) * 5) # More transport means more ways but capped at 15
        transportScore = min(100, transportScore + bonus)
        gateReceiptList.append("MultiEndpointBonus:{}".format(bonus))
    modScore = 0
    if flagValues.get("LocalCallOnly"):
        modScore += GATE_MODIFIERS["LocalCallOnly"]
        gateReceiptList.append("LocalCallOnly:{}".format(GATE_MODIFIERS["LocalCallOnly"]))
    if flagValues.get("SecureOnly"):
        modScore += GATE_MODIFIERS["SecureOnly"]
        gateReceiptList.append("SecureOnly:{}".format(GATE_MODIFIERS["SecureOnly"]))
    if bouncer:
        modScore += GATE_MODIFIERS["HasBouncer"]
        gateReceiptList.append("HasBouncer:{}".format(GATE_MODIFIERS["HasBouncer"]))
    if flagValues.get("DirectPassToBouncer") and not flagValues.get("SecureOnly"):
        modScore += GATE_MODIFIERS["DirectPassToBouncer"]
        gateReceiptList.append("DirectPassToBouncer:{}".format(GATE_MODIFIERS["DirectPassToBouncer"]))
    if not flagValues.get("BouncerIsNotCaching"):
        modScore += GATE_MODIFIERS["BouncerIsNotCaching"]
        gateReceiptList.append("BouncerIsNotCaching:{}".format(GATE_MODIFIERS["BouncerIsNotCaching"]))
    if flagValues.get("PerProcessCache"):
        modScore += GATE_MODIFIERS["PerProcessCache"]
        gateReceiptList.append("PerProcessCache:{}".format(GATE_MODIFIERS["PerProcessCache"]))
    if registrationVariant == "RpcServerRegisterIf":
        modScore += GATE_MODIFIERS["BaseVariant"]
        gateReceiptList.append("BaseVariant:{}".format(GATE_MODIFIERS["BaseVariant"]))
    gateScore = max(5, min(100, transportScore + modScore)) # This clamping is done cz later i will use a compound formula so cant make 0 or -ive and max ceiling is 100
    
    # Calculating the surface Score
    rawSignals = surfaceSignals["RawSignalTotal"]
    inPtrContrib = min(18, (surfaceSignals["InPointerCount"] * 3)) # Pointer Contributions but max at 18
    attackSurfaceContrib = min(12, surfaceSignals["CountContribution"]) # How big the surface is but max at 12
    preCapSurface = rawSignals + inPtrContrib + attackSurfaceContrib
    capNote = ""
    rawSurface = min(100, rawSignals + inPtrContrib + attackSurfaceContrib)
    # If the confidence is low the score gets to half
    multiplier = 1.0
    if surfaceSignals["SignatureConfidence"] == "Low":
        multiplier = 0.5
    surfaceScore = int(round(rawSurface * multiplier))
    
    # Now the final composite score
    compositeScore = int(round((gateScore * surfaceScore) / 100.0))
    if surfaceScore == 0:
        tier = "Low" # No surface to attack
    elif compositeScore >= 75:
        tier = "Critical"
    elif compositeScore >= 50:
        tier = "High"
    elif compositeScore >= 25:
        tier = "Moderate"
    else:
        tier = "Low"
    
    # Now building the receipt which is just a pretty formatted string
    if preCapSurface > 100:
        capNote = " [capped to {}]".format(rawSurface)
    gateReceiptStr = "Gate:{} [{}]".format(gateScore, ", ".join(gateReceiptList))
    surfaceReceiptList = []
    for sigName, count, opnumsStr, direction, target, weight in surfaceSignals["TopSignalsForReceipt"]:
        surfaceReceiptList.append("{}:{}x(opnums {}):{}:{}".format(sigName, count, opnumsStr, direction, weight))  
    surfaceReceiptList.append("InPtrs:{}:{}".format(surfaceSignals["InPointerCount"], inPtrContrib))
    surfaceReceiptList.append("Count:{}:{}".format(storedCount, attackSurfaceContrib))
    surfaceReceiptStr = "Surface:{} [{} -> raw:{}{} * {} -> {}]".format(surfaceScore, ", ".join(surfaceReceiptList), preCapSurface, capNote, multiplier, surfaceScore)
    receipt = "{}/{} | {} | {} | ({} * {}) / 100 = {}".format(tier, compositeScore, gateReceiptStr, surfaceReceiptStr, gateScore, surfaceScore, compositeScore)
    
    return flagsList, tier, compositeScore, gateScore, surfaceScore, receipt
    
def getTag(uuid, dispatchTableAddress, displayCount):
    isAscii = True
    cleanUuid = uuid.replace("-", "")
    try:
        for j in range(0, 32, 2):
            b = int(cleanUuid[j:j+2], 16)
            if not (b == 0 or 0x20 <= b <= 0x7E):
                isAscii = False
                break
    except Exception:
        isAscii = False
    isMemoryError = ("Memory Error" in str(dispatchTableAddress)) or ("Memory Error" in str(displayCount))
    hasFlag = "FLAG" in str(displayCount)
    if isAscii and isMemoryError:
        tag = "Diagnostics (2)"
        tagDesc = "[1] Fake UUID (Latched an ASCII str pointer instead of an interface)\n[2] Corrupt MIDL memory pointer"
    elif isAscii:
        tag = "Diagnostics"
        tagDesc = "Fake UUID (Latched an ASCII str pointer instead of an interface)"
    elif isMemoryError:
        tag = "Diagnostics"
        tagDesc = "Corrupt MIDL memory pointer"
    elif hasFlag:
        tag = "Needs-Review"
        tagDesc = "Dispatch Table walk overshoot (Probable thunk block)"
    else:
        tag = "Clean"
        tagDesc = "Clean"
    return tag, tagDesc
    

# SO FROM HERE THE MAIN STARTS................................. 

outputFileArgs = getScriptArgs() 
if len(outputFileArgs) < 1:
    print("[-] Error! No output file path provided.")
else:
    outputFilePath = outputFileArgs[0]
    fileExists = os.path.exists(outputFilePath) and os.path.getsize(outputFilePath) > 0
    binaryName = getCurrentProgram().getName()
    binaryInterfaces = []       
    print("\n\n============================================================================\n")
    print("[*] extract_rpc_interfaces.py: Scanning {}...".format(binaryName))
        
    try:
        interfaceApis = ["RpcServerRegisterIf", "RpcServerRegisterIf2", "RpcServerRegisterIfEx", "RpcServerRegisterIf3"]
        endpointApis = ["RpcServerUseProtseqEpA", "RpcServerUseProtseqEpW", "RpcServerUseProtseqEpExA", "RpcServerUseProtseqEpExW", "RpcServerUseProtseqA", "RpcServerUseProtseqW", "RpcServerUseAllProtseqs", "RpcServerUseAllProtseqsEx"]
            
        endpointCallSites = getCallSites(endpointApis)
        extractedEndpoints = []
        allEndpoints = ""
        if not endpointCallSites:
            print("[-] No endpoint found! Skipping")
        else:
            for data in endpointCallSites:
                name, address = data
                if name == "RpcServerUseAllProtseqs" or name == "RpcServerUseAllProtseqsEx":
                    protocolString = "All"
                    endpointString = "Dynamic/None"
                    extractedEndpoints.append("Protocol: {} | Endpoint: {}".format(protocolString, endpointString))
                    continue
                protocolString = "Unknown"
                endpointString = "Dynamic/None"
                isWide = False
                if "W" in name:
                    isWide = True
                protocolAddress = getReg(address, "RCX")
                if protocolAddress is not None:
                    parsedStr = getNameString(protocolAddress, isWide).strip()
                    if len(parsedStr) > 1:
                        protocolString = parsedStr
                    else:
                        protocolString = "[Runtime Ptr: {}]".format(protocolAddress.toString())
                if "Ep" in name:
                    endpointAddress = getReg(address, "R8")
                    if endpointAddress is not None:
                        parsedStr = getNameString(endpointAddress, isWide).strip()
                        if len(parsedStr) > 1:
                            endpointString = parsedStr
                        else:
                            endpointString = "[Runtime Ptr: {}]".format(endpointAddress.toString())    
                extractedEndpoints.append("Protocol: {} | Endpoint: {}".format(protocolString, endpointString))
        if extractedEndpoints:
            allEndpoints = " ||| ".join(extractedEndpoints)
        else:
            allEndpoints = "Dynamic / epmapper"
                
        callSites = getCallSites(interfaceApis)
        if not callSites:
            print("[-] No interfaces found! Skipping")
        else:
            print("[+] Found {} potential interfaces containing the endpoints. Extracting data...".format(len(callSites)))
            for data in callSites:
                try: 
                    name, callSite = data
                    interfaceAddress = getReg(callSite, "RCX")
                    securityDescriptor = "N/A (Unsupported API)"
                        
                    #Bouncer & If3 free pointer to Security Descriptor Logic
                    bouncer = False
                    if name == "RpcServerRegisterIf2" or name == "RpcServerRegisterIf3":
                        bouncer = checkBouncer(callSite, "RSP + 0X30")
                        if "If3" in name:
                            securityDescriptor = "Unresolved"
                            secDescStr = getSecDesc(callSite)
                            if secDescStr is not None:
                                securityDescriptor = secDescStr       
                    elif name == "RpcServerRegisterIfEx":
                        bouncer = checkBouncer(callSite, "RSP + 0X28")
                            
                        
                    autoListen = oleFlag = thirdPartyAuth = secureOnly = directPassToBouncer = localCallOnly = bouncerIsNotCaching = perProcessCache = rank = details = "N/A"
                    r9Flag = None
                    if name != "RpcSeverRegisterIf":
                        r9Flag = (getFlag(callSite))
                    if r9Flag is not None:
                        flagsList, flagValues = decodeFlags(r9Flag)
                        autoListen = flagsList[0]
                        oleFlag = flagsList[1]
                        thirdPartyAuth = flagsList[2]
                        secureOnly = flagsList[3]
                        directPassToBouncer = flagsList[4]
                        localCallOnly = flagsList[5]
                        bouncerIsNotCaching = flagsList[6]
                        perProcessCache = flagsList[7]
                    
                    if interfaceAddress is None:
                        continue
                    uuid = getUuid(interfaceAddress)
                    midlAddress = getMidlServerInfo(interfaceAddress)
                    try:
                        stubDescAddress = getStubDesc(midlAddress)
                        stubStr = stubDescAddress.toString() if stubDescAddress else "None"
                    except Exception:
                        stubStr = "Memory Error"
                    try:
                        storedCount = getStoredCount(interfaceAddress)
                        dispatchTableAddress, totalFunc = getDispatchTable(midlAddress)
                        displayCount = str(storedCount)
                        if storedCount != totalFunc:
                            displayCount += " (FLAG: Walked {} != Stored {})".format(totalFunc, storedCount)
                    except Exception:
                        dispatchTableAddress = "Memory Error"
                        displayCount = "Memory Error"      
                    try:
                        formatString = getFormatString(midlAddress, storedCount)
                        procString = readProcString(formatString, midlAddress, stubDescAddress)
                        surfaceSignals = computeSurfaceSignals(procString, storedCount)
                    except Exception:
                        formatString = "Memory Error"
                        procString = "Memory Error"
                        surfaceSignals = computeSurfaceSignals([], 0)
                        
                    # Cleaning some bad data like memory errors and junk uuid
                    tag, tagDesc = getTag(uuid, dispatchTableAddress, displayCount)
                    if tag != "Diagnostics" and tag != "Diagnostics (2)":
                        flagsList, tier, composite, gate, surface, receipt = rankInterface(r9Flag, bouncer, allEndpoints, surfaceSignals, name, storedCount)
                        rank = "{}/{}".format(tier, composite)
                        details = receipt
                        if tag == "Needs-Review":
                            details += " [Provisional]"
                    else:
                        rank = "N/A"
                        details = "N/A"
                            
                    interfaceDict = OrderedDict([
                        ("CallSite", callSite.toString()),
                        ("Tag", tag),
                        ("TagDesc", tagDesc),
                        ("Rank", rank),
                        ("RankDetail", details),
                        ("InterfaceAddress", interfaceAddress.toString()),
                        ("UUID", uuid),
                        ("DispatchAddress", dispatchTableAddress.toString() if isinstance(dispatchTableAddress, ghidra.program.model.address.Address) else dispatchTableAddress),
                        ("FunctionsCount", displayCount),
                        ("Endpoints", allEndpoints),
                        ("Security", OrderedDict([
                            ("HasBouncer", bouncer),
                            ("SecurityDescriptor", securityDescriptor),
                            ("SecureOnly", secureOnly),
                            ("LocalCallOnly", localCallOnly)
                            ])),
                        ("Methods", procString)
                        ])
                    binaryInterfaces.append(interfaceDict)
            
                except Exception as inner_e:
                    print("[-] Skipping broken interface at {}: {}".format(callSite.toString(), str(inner_e)))
                    continue
            
            binaryData = OrderedDict([
                ("BinaryName", binaryName),
                ("Interfaces", binaryInterfaces)
            ])
            masterJsonList = []
            if fileExists:
                with open(outputFilePath, "r") as f:
                    try:
                        masterJsonList = json.load(f, object_pairs_hook = OrderedDict)
                    except:
                        masterJsonList = []
            masterJsonList.append(binaryData)
            jsonOutput = json.dumps(masterJsonList, indent = 4)
            with open(outputFilePath, "w") as f:
                f.write(jsonOutput)
            print("[+] Successfully logged JSON data for {}.".format(binaryName))
    except Exception as e:
        print("[-] Error processing {}: {}".format(binaryName, str(e)))
    print("\n============================================================================\n")
