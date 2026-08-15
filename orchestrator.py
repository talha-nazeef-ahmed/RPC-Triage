import os
import shutil
import argparse
import tempfile
import subprocess
import pefile
from pathlib import Path

def getGhidraExecutable(ghidraPath):
    ghidraDir = Path(ghidraPath)
    if os.name == "nt": # Its a windows
        headless = ghidraDir / "support" / "analyzeHeadless.bat"
    else: # For linux and mac
        headless = ghidraDir / "support" / "analyzeHeadless" 
    if not headless.exists():
        raise FileNotFoundError(f"\n[-] Could not find ghidra headless at: {headless}")
    return headless

def filterBinaries(dirPathStr):
    dirPath = Path(dirPathStr)
    filteredBinaries = []
    if dirPath.exists():
        for file in dirPath.iterdir():
            if file.is_file():
                try:
                    pe = pefile.PE(file)
                    found = False
                    dirToCheck = []
                    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                        dirToCheck.append(pe.DIRECTORY_ENTRY_IMPORT)
                    if hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
                        dirToCheck.append(pe.DIRECTORY_ENTRY_DELAY_IMPORT)
                    for importTable in dirToCheck:
                        if found:
                            break
                        for importsArray in importTable:
                            dllName = importsArray.dll.decode("utf-8", errors = "ignore").lower()
                            if dllName == "rpcrt4.dll":
                                for dllFunctions in importsArray.imports:
                                    targetFunc = ["RpcServerRegisterIf", "RpcServerRegisterIfEx", "RpcServerRegisterIf2", "RpcServerRegisterIf3"]
                                    func = dllFunctions.name.decode("utf-8", errors = "ignore")
                                    if func in targetFunc:
                                        filteredBinaries.append(file.resolve())
                                        break
                except pefile.PEFormatError:
                    pass
                except Exception as e:
                    print(f"\n[-] Error processing file: {file.name}\nError details: {e}")
                    
    print(f"\n[+] Found {len(filteredBinaries)} binaries containing a RPC interface")
    return filteredBinaries
    
    
# So here the main starts...................................

# Setting up the command arguments
parser = argparse.ArgumentParser(description = "Filter RPC binaries and extract RPC interfaces via Ghidra")
parser.add_argument("-t", "--target", required = True, help = "Directory containing the binaries to scan")
parser.add_argument("-g", "--ghidra", required = True, help = "Path to the Ghidra installation folder")
parser.add_argument("-s", "--script", required = True, help = "Path to the script; extract_rpc_interfaces.py")
parser.add_argument("-o", "--output", required = True, help = "Path to save the output JSON")
parser.add_argument("--stagedir", required = True, help = "Permanent directory to save the filtered RPC binaries")
parser.add_argument("--projdir", required = True, help = "Directory to save the persistent Ghidra project")
parser.add_argument("--projname", required = True, help = "Name of the Ghidra project (e.g; RPC_Atlas)")
args = parser.parse_args()

# Converting user given str to the Path object
targetDir = Path(args.target)
scriptPath = Path(args.script).resolve()
outputPath = Path(args.output).resolve()
stageDir = Path(args.stagedir).resolve()
ghidraProjDir = Path(args.projdir).resolve()

# Creating the dir if its not there
stageDir.mkdir(parents = True, exist_ok = True)
ghidraProjDir.mkdir(parents = True, exist_ok = True)

headlessExe = getGhidraExecutable(args.ghidra)

projDatabase = ghidraProjDir / f"{args.projname}.rep"

gprFile = ghidraProjDir / f"{args.projname}.gpr"

checkFile = ghidraProjDir / ".analysisComplete"

# Well during testing a crash happened mid analysis so now have to add some safety check to make this script know when analysis is completed fully and when not
if (projDatabase.exists() or gprFile.exists()) and not checkFile.exists():
    print(f"\n[-] WARNING: Found an incomplete Ghidra Project, the previous run likely crashed\n[*] Cleaning up corrupted data...\n")
    if projDatabase.exists():
        shutil.rmtree(projDatabase)
    if gprFile.exists():
        gprFile.unlink()  

if checkFile.exists():
    print(f"\n[*] Found healthy existing Ghidra project: {args.projname}. Skipping import\n")
    modeArgs = ["-process"]
    analysisFlag = ["-noanalysis"]
    targetProj = f"{args.projname}/{stageDir.name}"
    isFreshImport = False
else:
    print(f"\n[*] No existing Ghidra project found. Starting fresh scan of {targetDir}\n")
    filteredBin = filterBinaries(args.target)
    if not filteredBin:
        print(f"\n[-] No RPC binaries found, exiting...\n")
        exit(0)
    # Now we have to copy those filtered bin to the given Ghidra proj folder
    print(f"\nCopying {len(filteredBin)} binaries to {stageDir}...\n")
    for binary in filteredBin:
        dest = stageDir / binary.name
        if not dest.exists():
            shutil.copy2(binary, dest)
    modeArgs = ["-import", str(stageDir)]
    analysisFlag = []
    targetProj = args.projname
    isFreshImport = True
    
ghidraCommand = [
    str(headlessExe),
    str(ghidraProjDir),
    targetProj,
] + modeArgs + [
    "-scriptPath", str(scriptPath.parent),
    "-postScript", scriptPath.name, str(outputPath)
] + analysisFlag

print(f"\n[*] Launching Ghidra Headless...\n")
try:
    subprocess.run(ghidraCommand, check = True)
    if isFreshImport:
        checkFile.touch()
    print(f"\n[+] Success! All data processed\n")
except subprocess.CalledProcessError as e:
    print(f"\n[-] Error encountered while trying to execute ghidra headless\nError details: {e}\n")
