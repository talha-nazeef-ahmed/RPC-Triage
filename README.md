# RPC-Triage

> **Static vs dynamic, read this first.** It is worth being clear about the line between _dynamic_ and _static_ analysis up front: **this tool does its ranking purely through static analysis.** It reads the compiled MIDL / NDR structures straight out of the binary and never executes anything. 
  

**Static triage for the Windows RPC attack surface.** Point it at a folder of PE binaries; it finds every one that registers an RPC server, recovers each interface's NDR method signatures, transport bindings and registration flags straight out of the compiled MIDL structures, and then ranks every interface by **reachability x danger** with a full arithmetic receipt attached to every score so you can check the math by hand.

Existing RPC tooling will happily recover an interface's method signatures and its registration flags. What none of it does is take both and answer the one question that actually decides where you spend your time: _given that I can reach this interface, and given what its methods accept as input, how urgently should I look at it compared to everything else on the machine?_ That gap is what this fills.

## What it does

- **Filters** the target folder so Ghidra only ever auto-analyzes binaries that actually register an RPC server (they import `rpcrt4.dll` and call one of the `RpcServerRegisterIf\*` APIs). On System32 that is the difference between an afternoon and a week.
    
- **Extracts**, per interface: UUID, the `RPC_SERVER_INTERFACE` / `MIDL_SERVER_INFO` chain, the authoritative `DispatchTableCount`, every method's opnum + parameter directions + decoded NDR opcodes, the registration flags (R9), the security-callback ("bouncer") presence, the security descriptor (best-effort), and the endpoint / transport bindings.
    
- **Ranks** every clean interface on two independent axes and multiplies them into one 0-100 composite, bucketed Critical / High / Moderate / Low.
    
- **Explains itself**: every score ships with a receipt string listing each component and the arithmetic that produced the final number.
    

## How it works

```
target dir --(pefile filter) --> only RPC-registering PEs
          --(Ghidra headless auto-analysis) --> analyzed program DB
          --(extract_rpc_interfaces.py script) --> interfaces + NDR + flags + endpoints
          --(two-axis AHP ranking engine) --> ranked interfaces + receipts
           --> single JSON report

 ```

## Requirements

- **Ghidra 11.x** (uses the bundled `support/analyzeHeadless`). Needs a **JDK 17+** on PATH.
    
- **Python 3.8+** on the driver side, with **pefile**.
    
- The extraction script runs under Ghidra's bundled **Jython 2.7** - no third-party imports, nothing to install there.
    
- Targets: Windows x64 PE files. Analysis itself is OS-independent (Ghidra is cross-platform), so you do not have to run this on Windows.
    

## Install

``` bash
git clone https://github.com/talha-nazeef-ahmed/RPC-Triage
cd RPC-Triage/
python -m pip install -r requirements.txt   # just pefile

 ```

`requirements.txt`: `pefile>=2023.2.7`

## Usage

Everything is driven by `orchestrator.py`: it filters, imports, analyzes and runs the extractor for you.

``` bash
python orchestrator.py \
  -t \"C:\Windows\System32\" \
  -g \"C:\ghidra_11.1.2_PUBLIC\" \
  -s \".\extract_rpc_interfaces.py\" \
  -o \".\out\report.json\" \
  --stagedir \".\out\staged\" \
  --projdir  \".\out\ghidra_proj\" \
  --projname RPC_Atlas

 ```

| flag | meaning |
| --- | --- |
| `-t` / `--target` | folder of binaries to scan |
| `-g` / `--ghidra` | Ghidra install folder (the one containing `support/analyzeHeadless`) |
| `-s` / `--script` | path to `extract_rpc_interfaces.py` |
| `-o` / `--output` | path of the JSON report to write |
| `--stagedir` | folder the filtered RPC binaries are copied into (kept) |
| `--projdir` | folder for the persistent Ghidra project |
| `--projname` | Ghidra project name (e.g. `RPC_Atlas`) |

**First run vs re-run (important).** The first run does the slow part: it filters, imports the matching binaries, runs full auto-analysis, then drops a `.analysisComplete` marker in `--projdir`. Every later run against the same project skips import/analysis (`-process -noanalysis`) and just re-runs the script over the already-analyzed programs. So analyzing System32 is a one-time cost and iterating on output is cheap. If analysis is interrupted the marker is not written and deletes the partial project (`.rep` / `.gpr`) and starts fresh.

## Output

One JSON file: a list of binaries, each with an `Interfaces` array. A complete run over System32 is included in this repo at `output/FullBatchRun.json` it is the raw, uncurated output (ghidra was behaving weirdly on my machine for some reason and dropped 5-6 binaries) so you can see exactly what the tool produces at scale (not a hand-picked highlight reel). Per interface:

| field | meaning |
| --- | --- |
| `CallSite` | address of the `RpcServerRegisterIf\*` call |
| `Tag` / `TagDesc` | data-quality bucket (see below) |
| `Rank` | `\"{Tier}/{Composite}\"`, e.g. `Critical/91` |
| `RankDetail` | the full scoring receipt (see below) |
| `UUID` | interface UUID |
| `InterfaceAddress` / `DispatchAddress` | recovered structure addresses |
| `FunctionsCount` | authoritative stored method count; may carry `(FLAG: Walked X != Stored Y)` |
| `Endpoints` | transport / endpoint bindings |
| `Security` | `HasBouncer`, `SecurityDescriptor`, `SecureOnly`, `LocalCallOnly` |
| `Methods` | per-opnum parameter list with decoded NDR opcodes |

**Tags; the data-hygiene gate:**

- **Clean**: recovered cleanly; ranked normally.
    
- **Needs-Review**: ranked, but the dispatch table walk overshot the stored count (usually a trailing thunk block). The score is real but carries `[Provisional]`; verify the method count before you quote it.
    
- **Diagnostics / Diagnostics (2)**: the row is an extraction artifact (an ASCII string mislatched as a UUID and/or a corrupt MIDL pointer). **Not scored** (`Rank: N/A`). These are kept on purpose: they report tool health, they are not attack surface.
    

**The** **`FLAG: Walked X != Stored Y`** **note.** The stored `DispatchTableCount` is authoritative and is what every score uses. The walked count is an independent executability cross-check; when the two disagree (commonly a clean 2x) the interface is tagged Needs-Review so you know to eyeball it. It never silently changes a score.

## How to read a Rank receipt

This is the part that makes a score arguable:

```
Moderate/35 | Gate:35 [ncacn_np:41, MultiEndpointBonus:15, HasBouncer:-46, BouncerIsNotCaching:25] | Surface:100 [HasBogusStruct:1x(opnums 5):[in]:61, HasCallerSizedBuffer:5x(opnums 0,6,11):[in]:49, InPtrs:6:18, Count:12:6 -> raw:134 [capped to 100] * 1.0 -> 100] | (35 * 100) / 100 = 35 [Provisional]

 ```

Read it left to right:

1. **`Moderate/35`**: tier and composite score.
    
2. **`Gate:35 [...]`**: the reachability axis. It starts from the transport base (`ncacn_np:41`, a named pipe), then lists each registration modifier with its signed contribution: `MultiEndpointBonus:15` (registered on several transports), `HasBouncer:-46` (a security callback is present, which lowers reachability), and `BouncerIsNotCaching:+25`. Summed and then clamped to \[5,100\] -> **35**.
    
3. **`Surface:100 [...]`**: the danger axis. Each fired signal is `Name:count x(opnums):direction:weight`, e.g. `HasBogusStruct` fired on 1 param (opnums 5) and its weight is 61. Then a count-based contribution: `InPtrs:6:18` = 117 caller-controlled in-pointers contributing +18, `Count:12:6` = 12 methods added +6. The `raw:134` is the pre-cap sum, `[capped to 100]`, `\* 1.0` is the confidence multiplier (drops to 0.5 when signatures are uncertain); final Surface **100**.
    
4. **`(35 \* 100) / 100 = 35 [Provisional]`**: composite = Gate x Surface / 100. Reachability and danger are multiplied, not averaged, because danger only matters if you can reach it: a maximally dangerous interface you cannot touch must not float to the top. The `[Provisional]` flag at the end warns that the dynamic memory walk slightly mismatched the stored method count, meaning a human should verify the boundaries.
    

A second example showing the clamp and the low-confidence discount:

```
Low/3 | Gate:5 [Dynamic / epmapper:29, LocalCallOnly:-100, SecureOnly:-65, HasBouncer:-46, BouncerIsNotCaching:25] | Surface:50 [... -> raw:140 [capped to 100] * 0.5 -> 50] | (5 * 50) / 100 = 3

 ```

`LocalCallOnly:-100` alone drives the gate below zero so it clamps to the floor of 5; signatures were uncertain so Surface is halved (`\* 0.5`); composite lands at 3. Dangerous input space, but effectively unreachable -> correctly deprioritized.

## Tiers

**Critical >= 75**, **High >= 50**, **Moderate >= 25**, **Low** otherwise (an interface with zero recovered surface is Low regardless of gate). Thresholds sit on the composite; the model behind them is in `docs/SCORING_METHODOLOGY.md`.

## The scoring model

All three weight tables (transport bases, gate modifiers, surface signals) are derived with the Analytic Hierarchy Process; pairwise comparisons, geometric-mean weights, and a measured consistency ratio. The full derivation, matrices, consistency numbers and the hand-worked notes are in `docs/SCORING_METHODOLOGY.md`.

## Validation

So the extraction is not just self-confirming, the interfaces this tool recovers were cross-checked against an independent, well-established RPC IDL extractor (the RpcServer parser in James Forshaw's NtObjectManager) run on the same binaries. Reference dumps for `lsass`, `samsrv` and `winlogon` are in `validation/`, and the full walkthrough is in `validation/VALIDATION.md`. Compare any of them against the matching binary in `output/FullBatchRun.json`: the interface UUIDs, method/opnum counts and per-parameter directions line up (for example, winlogon's `12E65DD8-...` interface shows five methods, Proc0-Proc4, in both). The reference tool stops at recovering the IDL; this tool takes the same recovered surface and adds the reachability x danger ranking on top. No affiliation with that project, it is used purely as an independent ground-truth check.

## Limitations (read before you quote a number)

- **Static only.** Nothing is invoked. Reachability is inferred from registration, not at runtime.
    
- **Needs-Review scores are provisional** until the method count is eyeballed.

## Stay Updated

This tool is part of my ongoing research into ALPC/RPC and Windows internals. I will be publishing further findings and releasing companion tools in the near future. If you found this useful, consider following me on GitHub or my socials below to be notified of future drops.

[![Twitter](https://img.shields.io/badge/Twitter-%231DA1F2.svg?style=flat-square&logo=Twitter&logoColor=white)](https://x.com/Sphinx_321) [![LinkedIn](https://img.shields.io/badge/LinkedIn-%230077B5.svg?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/talha-nazeef-ahmed/)
    

## Responsible use

A static triage / mapping tool for vulnerability research on systems you own. It reports attack _surface_, not vulnerabilities. Anything you go on to find in the interfaces it highlights should go through coordinated disclosure (MSRC) before any public detail.

## License

MIT.
