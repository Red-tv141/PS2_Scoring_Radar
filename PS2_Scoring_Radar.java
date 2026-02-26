// PS2 Scoring Radar V11 - Final Edition (Safety First + 4 Categories + Firewalls)
// @author Puggsy + Gemini + Claude
// @category PlayStation2

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import java.util.*;
import java.io.*;

public class PS2_Scoring_Radar extends GhidraScript {

    // =========================================================
    // SCORING CONSTANTS (V11 - Safety First + 4 Categories)
    // =========================================================
    private static final long PS2_BASE = 0x00100000L;

    // DNA Scores
    private static final int DNA_VU0              = 45;  // VU0 coprocessor
    private static final int DNA_TIMER_PATTERN    = 45;  // Frame counter (tick + compare)
    private static final int DNA_STATE_MACHINE    = 35;  // AI/Entity logic
    private static final int DNA_HEAVY_FPU        = 35;  // Physics vectors
    private static final int DNA_MACRO_SCRIPT     = 30;  // Global cutscenes/events
    private static final int DNA_ANIMATION        = 40;  // Animation speed modifiers

    // =========================================================
    // ANIMATION KEYWORDS (target function name patterns)
    // =========================================================
    private static final String[] ANIM_KEYWORDS = {
        "motion", "anim", "pose", "skeleton", "blend",
        "setframe", "settime", "changemotion", "setmotion", "updatebone"
    };

    // Address Bonus (max 25)
    private static final int ADDR_SAFE        = 25;  // offset >= 0x100000
    private static final int ADDR_VECTORS_MID = 20;  // offset >= 0x050000 (VECTORS only)
    private static final int ADDR_MID         = 10;  // offset >= 0x080000
    private static final int ADDR_SUBSYSTEM   =  0;  // offset >= 0x040000
    // offset < 0x040000 -> HARD REJECT (SDK/Hardware)

    // Depth/Safety Bonus (max 20)
    // -1 (orphan) = 20, deep tree = 15, etc.

    // Nexus Bonus (max 10)
    private static final int NEXUS_BONUS           = 10;  // VECTORS & TIMERS only
    private static final int ANIM_NEXUS_BONUS      = 40;  // Animation + confirmed Nexus (Mode A)
    private static final int ANIM_HEURISTIC_BONUS  = 25;  // Animation, no Nexus (Mode B)
    private static final int ANIM_FPU_THRESHOLD    =  8;  // floatOps required in Mode B
    private static final int ANIM_BRANCH_THRESHOLD =  5;  // branchOps required in Mode B

    private static final int SCORE_THRESHOLD = 50;
    private static final int FPU_THRESHOLD   = 12;

    // =========================================================
    // V12 SNIPER - Pattern Recognition Constants
    // =========================================================
    private static final int EULER_WINDOW      = 5;   // configurable: max JAL distance Scale->Add
    private static final int EULER_BONUS       = 25;  // Euler integration: ScaleVector->AddVector
    private static final int KINEMATIC_BONUS   = 20;  // Kinematic: sinf/cosf->CopyVector (player)
    private static final int SINGLETON_BONUS   = 15;  // called once per frame (Hierarchy Matrix)
    private static final int BATCH_PENALTY     = -10; // called in loop (particles, UI blink)
    private static final int GLOBAL_WRITE_BONUS = 20; // #2: target writes to global address (State mutator)
    private static final int STRUCT_WRITE_BONUS = 15; // #3: target writes swc1/sqc2 to low struct offsets
    private static final long STRUCT_OFFSET_MAX = 0x60L; // max offset considered "entity struct"
    // PS2 RAM starts at 0x00100000; global writes are addresses above this threshold
    private static final long GLOBAL_ADDR_MIN  = 0x00100000L;

    // =========================================================
    // FIREWALLS - Static Library Prefixes (Sony & libc)
    // =========================================================
    private static final String[] STATIC_FIREWALL_PREFIXES = {
        // Sony Hardware Libraries (block all except sceVu0)
        "sceCd", "sceMc", "scePad", "sceSif", "sceVif", "sceDma",
        "sceIpu", "sceGs", "sceVu1",  // VU1 is graphics pipeline only
        // Standard C Library (the functions themselves, not callers)
        "malloc", "free", "realloc", "calloc", "memcpy", "memset", "memmove",
        "printf", "sprintf", "vsprintf", "strcpy", "strlen", "strcmp", "strcat",
        "sin", "cos", "tan", "atan", "atan2", "sqrt", "pow", "exp", "log",
        "fabs", "floor", "ceil"
    };

    // =========================================================
    // FIREWALLS - IOP Module Strings (I/O Processor)
    // =========================================================
    private static final String[] IOP_MODULE_STRINGS = {
        // Core IOP
        "loadcore", "iopmac", "iopheap", "threadman", "sysclib",
        "sifman", "sifcmd",
        // Storage & Media
        "cdvdman", "cdvdfsv", "mcman", "xmcman", "mcserv",
        "atad", "hdd", "pfs",
        // Input/Output
        "sio2man", "padman", "xpadman", "mtapman",
        "libsd", "sdrdrv", "audsrv", "modmidi",
        "usbd",
        // Network (DEV9)
        "dev9", "smap", "ps2smap", "ps2ip",
        // File extensions (loading functions)
        ".IRX", ".irx", ".BIN", ".bin", ".DAT", ".dat"
    };

    // =========================================================
    // MAINLOOP ANCHORS (for auto-detection)
    // =========================================================
    private static final String[] MAINLOOP_ANCHORS = {
        "sceGsSyncV", "sceGsSwapDB", "scePadRead", "scePadGetState", "FlushCache"
    };

    // =========================================================
    // INNER CLASSES
    // =========================================================
    class FuncTraits {
        int     floatOps = 0, branchOps = 0, mathOps = 0;
        long    byteSize = 0;
        int     calledCount = 0;
        boolean isVu0 = false, isThunk = false;
        boolean hasTickIncrement = false, hasTimerCompare = false;
        boolean hasFrameCounterPattern = false;
        boolean writesToGlobal = false;
        boolean usesCop1 = false; // NEW: Hardware-level FPU move detection
        boolean usesCop2 = false; // NEW: Hardware-level VU0 macro detection
        Set<Long> constants = new TreeSet<>();
    }

    class ScoredJAL implements Comparable<ScoredJAL> {
        String pnachLine;
        int    score;
        String jalAddr;
        ScoredJAL(String line, int s, String addr) {
            pnachLine = line; score = s; jalAddr = addr;
        }
        @Override public int compareTo(ScoredJAL o) {
            return Integer.compare(o.score, this.score);
        }
    }

    class ScoreBreakdown {
        int     dnaScore = 0, depthBonus = 0, nexusBonus = 0, addressBonus = 0;
        boolean isKilled = false;
        String  killReason = "";
        String  category = "UNKNOWN";
        List<String> reasons = new ArrayList<>();
        int total() {
            if (isKilled) return 0;
            return dnaScore + depthBonus + nexusBonus + addressBonus;
        }
    }

    class MainLoopCandidate {
        Address addr;
        String  name;
        Set<String> anchorsHit;
        int score;
        MainLoopCandidate(Address a, String n, Set<String> hits) {
            addr = a; name = n; anchorsHit = hits; score = hits.size();
        }
    }

    // =========================================================
    // STATE
    // =========================================================
    private FunctionManager          funcManager;
    private ReferenceManager         refManager;
    private SymbolTable              symbolTable;
    private DecompInterface          decomp;
    private Map<Address, Integer>    mainLoop1Tree   = new HashMap<>();
    private Map<Address, Integer>    mainLoop2Tree   = new HashMap<>();
    private Map<Address, String>     frameRateNexus  = new HashMap<>();
    private Map<Address, FuncTraits>    cache              = new HashMap<>();
    private Map<Address, HighFunction>  highFuncCache      = new HashMap<>();  // #1: Parent decompile cache
    private Map<Address, Boolean>       staticFwCache      = new HashMap<>();  // #4: Firewall result cache
    private Map<Address, Boolean>       iopFwCache         = new HashMap<>();  // #4: IOP firewall result cache
    private Map<Address, Boolean>                       eulerPatternCache  = new HashMap<>();  // V12: Euler per JAL address
    private Map<Address, List<long[]>>                  parentJalListCache = new HashMap<>();  // V12: ordered JAL list per parent
    private Map<Address, Boolean>                       animDetectCache    = new HashMap<>();  // V12: Animation per JAL address
    private Map<Address, Boolean>                       globalWriteCache   = new HashMap<>();  // #2: target writes to global
    private Map<Address, Boolean>                       structWriteCache   = new HashMap<>();  // #3: target writes to low struct offset
    private Map<Address, Boolean>       kinematicCache     = new HashMap<>();  // V12: Kinematic per parent
    private Map<Address, String>        hierarchyCache     = new HashMap<>();  // V12: SINGLETON/BATCH

    // Statistics
    private int staticFirewallBlocked = 0;
    private int iopFirewallBlocked    = 0;
    private int dependencyBlocked     = 0;
    private int killedByZone          = 0;
    private int thunksSkipped         = 0;

    // =========================================================
    // ENTRY POINT
    // =========================================================
    @Override
    public void run() throws Exception {
        funcManager  = currentProgram.getFunctionManager();
        refManager   = currentProgram.getReferenceManager();
        symbolTable  = currentProgram.getSymbolTable();
        decomp       = new DecompInterface();
        decomp.openProgram(currentProgram);

        println("=========================================================");
        println("PS2 RADAR V11 - FINAL EDITION");
        println("Safety First + 4 Categories + Firewalls + Auto-Detection");
        println("=========================================================\n");

        // === STEP 1: MainLoop Auto-Detection (Hybrid approach) ===
        Address mainLoop1Addr = null;
        Address mainLoop2Addr = null;

        boolean autoDetect = false;
        try {
            autoDetect = askYesNo("MainLoop Auto-Detection", 
                "Do you want to automatically detect MainLoop candidates?\n(Select 'No' to input them manually for Stripped games)");
        } catch (Exception e) {
            // אם המשתמש סגר את החלון, נניח שהוא רוצה להזין ידנית
            autoDetect = false;
        }

        if (autoDetect) {
            List<MainLoopCandidate> loopCandidates = findMainLoopCandidates();
            if (!loopCandidates.isEmpty()) {
                println("[AUTO-DETECT] Found " + loopCandidates.size() + " MainLoop candidate(s):");
                for (int i = 0; i < Math.min(5, loopCandidates.size()); i++) {
                    MainLoopCandidate c = loopCandidates.get(i);
                    println("  [" + (i+1) + "] " + c.name + " @ " + c.addr +
                            " (score: " + c.score + ", anchors: " +
                            String.join(", ", c.anchorsHit) + ")");
                }
                // Use top 2 automatically
                if (loopCandidates.size() >= 1) {
                    mainLoop1Addr = loopCandidates.get(0).addr;
                    println("[AUTO-DETECT] Using #1 as Gameplay Loop: " + mainLoop1Addr);
                }
                if (loopCandidates.size() >= 2) {
                    mainLoop2Addr = loopCandidates.get(1).addr;
                    println("[AUTO-DETECT] Using #2 as Menu Loop: " + mainLoop2Addr);
                }
                println();
            } else {
                println("[AUTO-DETECT] No MainLoop anchors found (stripped symbols?).");
                println("[FALLBACK] Asking for manual input...\n");
                autoDetect = false; // Fallback to manual
            }
        }

        // ירוץ אם המשתמש בחר "לא", או אם החיפוש האוטומטי לא מצא כלום
        if (!autoDetect) {
            println("[MANUAL INPUT] Asking for manual MainLoop addresses...\n");
            mainLoop1Addr = askAddressOptional(
                "Main Loop 1 (Gameplay)",
                "Enter Gameplay MainLoop address.\nExample: 00190cb0\n(Cancel to skip)");
            mainLoop2Addr = askAddressOptional(
                "Main Loop 2 (Menu)",
                "Enter Menu MainLoop address.\nExample: 00233fc0\n(Cancel to skip)");
        }

        // FrameRate variable (optional)
        Address frameRateAddr = askAddressOptional(
            "FrameRate Variable",
            "Enter global FrameRate variable address.\nExample: 00376c50\n(Cancel to skip Nexus analysis)");

        File outputFile = askFile("Save PNACH output", "Save as...");

        // === STEP 2: Build Trees ===
        if (mainLoop1Addr != null) {
            buildCallTree(funcManager.getFunctionAt(mainLoop1Addr), 15, mainLoop1Tree);
            println("[*] Gameplay Loop Tree: " + mainLoop1Tree.size() + " functions.");
        }
        if (mainLoop2Addr != null) {
            buildCallTree(funcManager.getFunctionAt(mainLoop2Addr), 15, mainLoop2Tree);
            println("[*] Menu Loop Tree: " + mainLoop2Tree.size() + " functions.");
        }
        if (frameRateAddr != null) {
            buildFrameRateNexus(frameRateAddr);
            println("[*] FrameRate Nexus: " + frameRateNexus.size() + " functions.");
        }
        println();

        // === STEP 4a: Pre-Scan (count total JALs for ETA) ===
        println("[*] Pre-scanning to count JAL instructions...");
        int totalJals = 0;
        {
            InstructionIterator preIter = currentProgram.getListing().getInstructions(true);
            while (preIter.hasNext() && !monitor.isCancelled()) {
                if (preIter.next().getMnemonicString().equals("jal")) totalJals++;
            }
        }
        println("[*] Found " + totalJals + " JAL instructions. Starting main scan...\n");

        // === STEP 4b: Main Scan ===
        List<ScoredJAL> catVectors       = new ArrayList<>();
        List<ScoredJAL> catTimers        = new ArrayList<>();
        List<ScoredJAL> catStateMachines = new ArrayList<>();
        List<ScoredJAL> catMacroScripts  = new ArrayList<>();
        List<ScoredJAL> catAnimations    = new ArrayList<>();
        List<ScoredJAL> catThunks        = new ArrayList<>();
        List<ScoredJAL> catPureMath = new ArrayList<>();
        // NEW: Map to store unique Target Functions for Global Hooking
        Map<Long, String> globalHooks    = new TreeMap<>();

        InstructionIterator instIter = currentProgram.getListing().getInstructions(true);
        int  processed      = 0;   // JALs that passed all filters (reach scoring)
        int  jalsSeen       = 0;   // every JAL encountered in the binary
        long scanStart      = System.currentTimeMillis();
        int  lastPrintedPct = -1;

        while (instIter.hasNext() && !monitor.isCancelled()) {
            Instruction inst = instIter.next();

            // V11: JAL only (jalr removed by design)
            if (!inst.getMnemonicString().equals("jal")) continue;

            jalsSeen++;

            // --- Progress + ETA (every 1%) ---
            if (totalJals > 0) {
                int pct = (jalsSeen * 100) / totalJals;
                if (pct != lastPrintedPct && pct % 10 == 0) {
                    lastPrintedPct = pct;
                    long elapsed = System.currentTimeMillis() - scanStart;
                    String eta;
                    if (pct > 0) {
                        long totalEstMs = (elapsed * 100L) / pct;
                        long remainMs   = totalEstMs - elapsed;
                        long remSec     = remainMs / 1000;
                        if (remSec >= 60)
                            eta = String.format("%dm %02ds", remSec / 60, remSec % 60);
                        else
                            eta = remSec + "s";
                    } else {
                        eta = "calculating...";
                    }
                    int filled = pct / 5;
                    String bar = "[" + "#".repeat(filled) + ".".repeat(20 - filled) + "]";
                    println(String.format("[SCAN] %s %3d%% | JALs: %d/%d | ETA: %s",
                        bar, pct, jalsSeen, totalJals, eta));
                }
            }

            Reference[] refs = inst.getReferencesFrom();
            if (refs.length == 0) continue;

            Function parentFunc = funcManager.getFunctionContaining(inst.getAddress());
            Function targetFunc = funcManager.getFunctionAt(refs[0].getToAddress());
            if (parentFunc == null || targetFunc == null) continue;
            if (parentFunc.equals(targetFunc)) continue;

            // Thunk Resolution (Ghidra issue #113):
            // If targetFunc is a bare `j` wrapper, resolve to the real destination.
            // We still NOP the original JAL — only trait analysis uses the resolved target.
            Function resolvedTarget = resolveThunkTarget(targetFunc);
            boolean wasResolved = !resolvedTarget.equals(targetFunc);

            // === FIREWALL 1: Static Library Check (Parent & Target, both original and resolved) ===
            if (isStaticLibraryFunction(parentFunc) || isStaticLibraryFunction(targetFunc) ||
                (wasResolved && isStaticLibraryFunction(resolvedTarget))) {
                staticFirewallBlocked++;
                continue;
            }

            // === FIREWALL 2: IOP Module Check (Parent & Target, both original and resolved) ===
            if (referencesIopModule(parentFunc) || referencesIopModule(targetFunc) ||
                (wasResolved && referencesIopModule(resolvedTarget))) {
                iopFirewallBlocked++;
                continue;
            }

            // Thunk guard
            if (isThunkFunction(parentFunc)) {
                thunksSkipped++;
                continue;
            }

            // BOUNCER 2: Leaf filter — use resolved target for trait analysis
            FuncTraits target = getTraits(resolvedTarget);
            // FIX: Restore calledCount protection to prevent Utility function spam,
            // UNLESS it's a known hardware/math function (like mgSetProjection)
            if (target.byteSize < 8 || (target.calledCount > 15 && !target.usesCop1 && !target.usesCop2)) {
                continue;
            }

            FuncTraits parent = getTraits(parentFunc);

            // === FIREWALL 3: UNIVERSAL DEPENDENCY BOUNCER ===
            if (isReturnValueUsed(parentFunc, inst.getAddress())) {
                dependencyBlocked++;
                continue; 
            }

            Address parentEntry = parentFunc.getEntryPoint();
            int depth1      = mainLoop1Tree.getOrDefault(parentEntry, -1);
            int depth2      = mainLoop2Tree.getOrDefault(parentEntry, -1);
            int dangerDepth = calcDangerDepth(depth1, depth2);

            ScoreBreakdown bd = calculateScore(
                parent, target, parentEntry, inst.getAddress(), dangerDepth);

            if (bd.isKilled) {
                killedByZone++;
                continue;
            }

            // Pure Math Vector Guard (#2): if Target is VECTORS but never writes to global state,
            // it's a stateless math function (MatrixMultiply, etc.) that only fills a pointer.
            // NOPing it would corrupt the output buffer → crash or invisible model.
            // Kill it here so the Parent (which holds the real timer/logic) can be found instead.
            if (bd.category.equals("VECTORS") && target.isVu0 && !target.writesToGlobal) {
                bd.category = "PURE_MATH_HOOKS";
                bd.reasons.add("Pure Math (Hook Target)");
            }

            // === V12 SNIPER: Pattern Recognition Bonuses ===
            int v12Bonus = 0;
            List<String> v12Tags = new ArrayList<>();

            // Module A: Euler Hunter — only the AddVector JAL itself gets the bonus
            if (detectEulerPattern(parentFunc, targetFunc, inst.getAddress())) {
                v12Bonus += EULER_BONUS;
                v12Tags.add("EulerHunter(+" + EULER_BONUS + ")");
                if (!bd.category.equals("VECTORS") && !bd.category.equals("TIMERS"))
                    bd.category = "VECTORS"; // promote
            }
            // Module B: Kinematic Hunter (sinf/cosf->CopyVector)
            else if (detectKinematicPattern(parentFunc, targetFunc, inst.getAddress())) {
                v12Bonus += KINEMATIC_BONUS;
                v12Tags.add("KinematicHunter(+" + KINEMATIC_BONUS + ")");
                bd.category = "VECTORS"; // always physical movement
            }

            // Module C: Hierarchy Matrix (Singleton vs Batch)
            String hierarchy = calcHierarchyType(parentFunc);
            if (hierarchy.equals("SINGLETON")) {
                v12Bonus += SINGLETON_BONUS;
                v12Tags.add("Singleton(+" + SINGLETON_BONUS + ")");
            } else if (hierarchy.equals("BATCH")) {
                v12Bonus += BATCH_PENALTY;
                v12Tags.add("Batch(" + BATCH_PENALTY + ")");
            }

            // Module E: Animation Hunter (float-param data flow + no COP2 + FPU in parent)
            boolean isAnim = detectAnimationModifier(parentFunc, targetFunc, inst.getAddress());
            if (isAnim) {
                // NEW FIX: Animation overrides both UNKNOWN and generic VECTORS.
                // This steals float-based animation functions back from Category 1 into Category 5!
                if (bd.category.equals("UNKNOWN") || bd.category.equals("VECTORS")) {
                    bd.dnaScore = DNA_ANIMATION;
                    bd.category = "ANIMATION_MODIFIERS";
                }

                boolean nexusAvailable = !frameRateNexus.isEmpty();
                boolean inNexus        = frameRateNexus.containsKey(parentEntry);

                if (nexusAvailable && inNexus) {
                    // MODE A: Nexus confirmed — high confidence
                    v12Bonus += ANIM_NEXUS_BONUS;
                    v12Tags.add("AnimNexus(+" + ANIM_NEXUS_BONUS + ")");
                } else if (!nexusAvailable) {
                    // MODE B: No nexus address provided — strict heuristic fallback
                    if (parent.floatOps > ANIM_FPU_THRESHOLD && parent.branchOps > ANIM_BRANCH_THRESHOLD) {
                        v12Bonus += ANIM_HEURISTIC_BONUS;
                        v12Tags.add("AnimHunter: Heuristic Mode(+" + ANIM_HEURISTIC_BONUS + ")");
                    } else {
                        // Parent too simple for heuristic confidence — skip
                        isAnim = false;
                        if (bd.category.equals("ANIMATION_MODIFIERS")) bd.category = "UNKNOWN";
                    }
                } else {
                    // Nexus exists but parent is NOT in it — penalty
                    v12Bonus -= 10;
                    v12Tags.add("AnimOutsideNexus(-10)");
                }
                if (isAnim) v12Tags.add("AnimHunter");
            }

            // Module F: Global State Writer (#2) — Parent writes to absolute global address
            if (parentWritesToGlobal(parentFunc, inst.getAddress())) {
                v12Bonus += GLOBAL_WRITE_BONUS;
                v12Tags.add("GlobalWriter(+" + GLOBAL_WRITE_BONUS + ")");
                if (bd.category.equals("UNKNOWN")) {
                    bd.dnaScore = DNA_STATE_MACHINE;
                    bd.category = "STATE_MACHINES";
                }
            }

            // Module G: Struct Position Writer (#3) — Parent writes swc1/sqc2 to low entity offset
            if (parentWritesToEntityStruct(parentFunc, inst.getAddress())) {
                v12Bonus += STRUCT_WRITE_BONUS;
                v12Tags.add("StructWriter(+" + STRUCT_WRITE_BONUS + ")");
                if (!bd.category.equals("VECTORS") && !bd.category.equals("TIMERS"))
                    bd.category = "VECTORS";
            }

            processed++; // count all JALs that reached scoring

            // Final Orphan Kill (moved here AFTER Module E has a chance to save it)
            // An orphan that's still UNKNOWN after all V12 hunters is spam — kill it.
            if (dangerDepth == -1 && bd.category.equals("UNKNOWN")) {
                killedByZone++;
                continue;
            }

            if (bd.total() + v12Bonus >= SCORE_THRESHOLD && !bd.category.equals("UNKNOWN")) {
                int finalScore = Math.min(bd.total() + v12Bonus, 100);
                String v12Info = v12Tags.isEmpty() ? "" : " | V12:[" + String.join(", ", v12Tags) + "]";
                String debugInfo = String.format(
                    "[P:%db F:%d B:%d C:%d] -> [T:%db F:%d B:%d C:%d] [Hier:%s]",
                    parent.byteSize, parent.floatOps, parent.branchOps, parent.calledCount,
                    target.byteSize, target.floatOps, target.branchOps, target.calledCount,
                    hierarchy);
                String targetLabel = wasResolved
                    ? targetFunc.getName() + "->" + resolvedTarget.getName()
                    : targetFunc.getName();

                // Thunk Override: resolved targets go to THUNKS category,
                // preserving original category as [ProxyFor: X] tag in the comment.
                String effectiveCategory = bd.category;
                String thunkTag = "";
                if (wasResolved) {
                    thunkTag = " | [ProxyFor: " + bd.category + "]";
                    effectiveCategory = "THUNKS";
                }

                String line = String.format(
                    "patch=1,EE,%08X,word,00000000 // [%d/100] %s -> %s | %s%s%s | %s",
                    inst.getAddress().getOffset(), finalScore,
                    parentFunc.getName(), targetLabel,
                    String.join(", ", bd.reasons), v12Info, thunkTag, debugInfo);
                String addrStr = String.format("%08X", inst.getAddress().getOffset());

                // NEW: Capture the Target Function itself for global hooking
                long targetAddrOffset = targetFunc.getEntryPoint().getOffset();
                
                // SAFEGUARD: Address check AND Firewall check for the Target itself
                if ((targetAddrOffset - PS2_BASE) >= 0x040000L) {
                    if (!isStaticLibraryFunction(targetFunc) && !referencesIopModule(targetFunc)) {
                        if (!globalHooks.containsKey(targetAddrOffset)) {
                            String hookLine = String.format(
                                "patch=1,EE,%08X,word,00000000 // [GLOBAL HOOK] %s | %s",
                                targetAddrOffset, targetLabel, effectiveCategory);
                            globalHooks.put(targetAddrOffset, hookLine);
                        }
                    }
                }

                if      (effectiveCategory.equals("VECTORS"))             catVectors.add(new ScoredJAL(line, finalScore, addrStr));
                else if (effectiveCategory.equals("TIMERS"))              catTimers.add(new ScoredJAL(line, finalScore, addrStr));
                else if (effectiveCategory.equals("STATE_MACHINES"))      catStateMachines.add(new ScoredJAL(line, finalScore, addrStr));
                else if (effectiveCategory.equals("MACRO_SCRIPTS"))       catMacroScripts.add(new ScoredJAL(line, finalScore, addrStr));
                else if (effectiveCategory.equals("ANIMATION_MODIFIERS")) catAnimations.add(new ScoredJAL(line, finalScore, addrStr));
                else if (effectiveCategory.equals("THUNKS"))              catThunks.add(new ScoredJAL(line, finalScore, addrStr));
                else if (effectiveCategory.equals("PURE_MATH_HOOKS"))     catPureMath.add(new ScoredJAL(line, finalScore, addrStr));
            }
        }

        // Final timing summary
        long totalSec = (System.currentTimeMillis() - scanStart) / 1000;
        println(String.format("\n[SCAN] Done! %d JALs scanned in %dm %02ds. %d candidates found.",
            totalJals, totalSec / 60, totalSec % 60, processed));

        decomp.dispose();

        // === STEP 5: Statistics ===
        println("\n[*] Scan Statistics:");
        println("    JAL instructions evaluated  : " + processed);
        println("    Static Firewall blocked     : " + staticFirewallBlocked);
        println("    IOP Firewall blocked        : " + iopFirewallBlocked);
        println("    Dependency Bouncer blocked  : " + dependencyBlocked);
        println("    Killed by Dynamic KillZone  : " + killedByZone);
        println("    Thunks skipped (bug guard)  : " + thunksSkipped);

        // === STEP 6: Sort & Write ===
        Collections.sort(catVectors);
        Collections.sort(catTimers);
        Collections.sort(catStateMachines);
        Collections.sort(catMacroScripts);
        Collections.sort(catAnimations);
        Collections.sort(catThunks);
        int total = catVectors.size() + catTimers.size() +
                    catStateMachines.size() + catMacroScripts.size() +
                    catAnimations.size() + catThunks.size();

        PrintWriter writer = new PrintWriter(new FileWriter(outputFile));
        writer.println("// =========================================================");
        writer.println("// PS2 RADAR V12 SNIPER - Multi-Hunter Edition");
        writer.println("// Euler + Kinematic + Hierarchy Matrix + Tracer Bullets");
        writer.println("// =========================================================");
        writer.println("// Main Loop : " + (mainLoop1Addr != null ? mainLoop1Addr : "N/A"));
        writer.println("// Secondary Loop     : " + (mainLoop2Addr != null ? mainLoop2Addr : "N/A"));
        writer.println("// FrameRate Var : " + (frameRateAddr != null ? frameRateAddr : "N/A"));
        writer.println("// Threshold     : " + SCORE_THRESHOLD);
        writer.println("// Euler Window  : " + EULER_WINDOW + " instructions");
        writer.println("// =========================================================\n");
        writeCategory(writer, "CATEGORY 1: VECTORS & PHYSICS",       catVectors);
        writeCategory(writer, "CATEGORY 2: TIMERS & TICKERS",        catTimers);
        writeCategory(writer, "CATEGORY 3: ENTITY STATE MACHINES",   catStateMachines);
        writeCategory(writer, "CATEGORY 4: GLOBAL MACRO SCRIPTS",    catMacroScripts);
        writeCategory(writer, "CATEGORY 5: ANIMATION MODIFIERS",     catAnimations);
        writeCategory(writer, "CATEGORY 6: THUNKS (Indirect Calls)", catThunks);
        writer.println("// =========================================================");
        writer.println("// CATEGORY 8: GLOBAL HOOK POINTS (TARGET FUNCTIONS)");
        writer.println("// Use these central addresses to plant custom assembly hooks (e.g., 'j 000DF000')");
        writer.println("// Count: " + globalHooks.size());
        writer.println("// =========================================================");
        for (String hook : globalHooks.values()) {
            writer.println(hook);
        }
        writer.println();
        writer.println("// =========================================================");
        writer.println("// STATISTICS");
        writer.println("// =========================================================");
        writer.println("// Vectors        : " + catVectors.size());
        writer.println("// Timers         : " + catTimers.size());
        writer.println("// State Machines : " + catStateMachines.size());
        writer.println("// Macro Scripts  : " + catMacroScripts.size());
        writer.println("// Animations     : " + catAnimations.size());
        writer.println("// Thunks         : " + catThunks.size());
        writer.println("// Total Without Global Hook Points : " + total);
        writer.println("//");
        writer.println("// Firewall Stats:");
        writer.println("// Static Lib blocked : " + staticFirewallBlocked);
        writer.println("// IOP blocked        : " + iopFirewallBlocked);
        writer.println("// Dependency blocked : " + dependencyBlocked);
        writer.close();

        // === STEP 7: Tracer Bullets (sorted by score, written into main file) ===
        // All results are already written above by category. No extra chunk files.

        println("\n[SUCCESS] Output: " + outputFile.getAbsolutePath());
        println("  Vectors        : " + catVectors.size());
        println("  Timers         : " + catTimers.size());
        println("  State Machines : " + catStateMachines.size());
        println("  Macro Scripts  : " + catMacroScripts.size());
        println("  Animations     : " + catAnimations.size());
        println("  Thunks         : " + catThunks.size());
        println("  TOTAL          : " + total);
    }

    // =========================================================
    // V16: TOPOLOGY-BASED MAINLOOP DETECTION (With Hierarchy Tiering)
    // Identifies "Manager" functions by analyzing code density, 
    // call graph breadth, internal loop structures, and frame heartbeat.
    // =========================================================
    private List<MainLoopCandidate> findMainLoopCandidates() throws Exception {
        Map<Address, Double> topologyScores = new HashMap<>();
        Map<Address, Set<String>> anchorMap = new HashMap<>();
        BasicBlockModel blockModel = new BasicBlockModel(currentProgram);

        // 1. Gather hardware anchor addresses once
        Map<Address, String> anchorAddrs = new HashMap<>();
        for (String name : MAINLOOP_ANCHORS) {
            SymbolIterator syms = symbolTable.getSymbols(name);
            while (syms.hasNext()) anchorAddrs.put(syms.next().getAddress(), name);
        }

        // 2. Pre-gather all candidates to allow cross-referencing (Hierarchy check)
        List<Function> candidates = new ArrayList<>();
        for (Function func : funcManager.getFunctions(true)) {
            if (monitor.isCancelled()) break;
            if (func.isThunk() || func.getBody().getNumAddresses() < 50) continue;
            candidates.add(func);
        }

        // 3. Analyze each candidate
        for (Function func : candidates) {
            long instCount = 0;
            InstructionIterator it = currentProgram.getListing().getInstructions(func.getBody(), true);
            while (it.hasNext()) { it.next(); instCount++; }
            if (instCount < 100) continue; // Real PS2 Loops are rarely small

            Set<Function> callees = func.getCalledFunctions(monitor);
            int callCount = callees.size();

            // Metric C: Internal Loops / Back-edges
            int backEdges = 0;
            CodeBlockIterator blocks = blockModel.getCodeBlocksContaining(func.getBody(), monitor);
            while (blocks.hasNext()) {
                CodeBlock block = blocks.next();
                CodeBlockReferenceIterator dests = block.getDestinations(monitor);
                while (dests.hasNext()) {
                    CodeBlockReference ref = dests.next();
                    if (ref.getDestinationAddress().compareTo(block.getFirstStartAddress()) <= 0 &&
                        func.getBody().contains(ref.getDestinationAddress())) {
                        backEdges++;
                    }
                }
            }
            if (backEdges == 0) continue; // A MainLoop must loop

            // Metric D & E: Anchor Breadth and Frame Heartbeat
            Set<String> hits = new HashSet<>();
            boolean hasBeginFrame = false;
            boolean hasEndFrame = false;

            for (Function callee : callees) {
                String cName = callee.getName().toLowerCase();
                if (cName.contains("beginframe") || cName.contains("gssetsync")) hasBeginFrame = true;
                if (cName.contains("endframe") || cName.contains("gssyncv")) hasEndFrame = true;
                
                if (anchorAddrs.containsKey(callee.getEntryPoint())) {
                    hits.add(anchorAddrs.get(callee.getEntryPoint()));
                }
                // Shallow recursive check (one level deep)
                for (Function grandCallee : callee.getCalledFunctions(monitor)) {
                    if (anchorAddrs.containsKey(grandCallee.getEntryPoint())) {
                        hits.add(anchorAddrs.get(grandCallee.getEntryPoint()));
                    }
                }
            }

            // Calculation adjustment
            double score = (instCount * 0.1) + (callCount * 2.5) + (backEdges * 10);
            
            if (hasBeginFrame && hasEndFrame) {
                score *= 2.0; // Double score for confirmed Frame Managers
                hits.add("HEARTBEAT_FOUND");
            }

            // === HIERARCHY TIERING (CRITICAL FIX FOR DARK CLOUD 2) ===
            // If this candidate calls ANOTHER candidate, this is the Master Dispatcher!
            for (Function other : candidates) {
                if (other.equals(func)) continue;
                if (callees.contains(other)) {
                    score += 1000.0; // Massive boost to ensure MainLoop beats EditLoop
                    break;
                }
            }

            // Penalty: If no hardware interaction (GS/PAD) is found
            if (hits.size() < 1) score *= 0.05;
            else if (hits.size() >= 2) score *= 1.5;

            topologyScores.put(func.getEntryPoint(), score);
            anchorMap.put(func.getEntryPoint(), hits);
        }

        List<MainLoopCandidate> results = new ArrayList<>();
        for (Address addr : topologyScores.keySet()) {
            Function f = funcManager.getFunctionAt(addr);
            MainLoopCandidate c = new MainLoopCandidate(addr, f.getName(), anchorMap.get(addr));
            c.score = topologyScores.get(addr).intValue();
            results.add(c);
        }

        results.sort((a, b) -> Integer.compare(b.score, a.score));
        return results;
    }

    // =========================================================
    // FIREWALLS
    // =========================================================
    private boolean isStaticLibraryFunction(Function func) {
        Address key = func.getEntryPoint();
        Boolean cached = staticFwCache.get(key);
        if (cached != null) return cached;

        String name = func.getName();
        // Exception: sceVu0 is allowed (game physics)
        if (name.startsWith("sceVu0")) {
            staticFwCache.put(key, false);
            return false;
        }
        // Block all other sce* and libc functions
        for (String prefix : STATIC_FIREWALL_PREFIXES) {
            if (name.startsWith(prefix)) {
                staticFwCache.put(key, true);
                return true;
            }
        }
        staticFwCache.put(key, false);
        return false;
    }

    private boolean referencesIopModule(Function func) {
        Address key = func.getEntryPoint();
        Boolean cached = iopFwCache.get(key);
        if (cached != null) return cached;

        // Scan ALL instructions in the function body (not just entry point)
        // MIPS loads string pointers mid-function via lui/addiu pairs
        InstructionIterator bodyIter = currentProgram.getListing()
            .getInstructions(func.getBody(), true);
        while (bodyIter.hasNext()) {
            Instruction inst = bodyIter.next();
            for (Reference ref : inst.getReferencesFrom()) {
                Address toAddr = ref.getToAddress();
                Data data = getDataAt(toAddr);
                if (data != null && data.hasStringValue()) {
                    String str = data.getDefaultValueRepresentation();
                    for (String iopStr : IOP_MODULE_STRINGS) {
                        if (str.contains(iopStr)) {
                            iopFwCache.put(key, true);
                            return true;
                        }
                    }
                }
            }
        }
        iopFwCache.put(key, false);
        return false;
    }
    // =========================================================
    // DEPENDENCY BOUNCER (Universal Crash Preventer)
    // =========================================================
    private boolean isReturnValueUsed(Function parentFunc, Address jalAddr) {
        Address parentEntry = parentFunc.getEntryPoint();

        // LAYER 1: P-Code check — if decompiler resolved a return value with descendants
        HighFunction highFunc = highFuncCache.get(parentEntry);
        if (highFunc == null) {
            DecompileResults res = decomp.decompileFunction(parentFunc, 15, monitor);
            highFunc = res.getHighFunction();
            if (highFunc != null) highFuncCache.put(parentEntry, highFunc);
        }
        if (highFunc != null) {
            Iterator<PcodeOpAST> ops = highFunc.getPcodeOps(jalAddr);
            while (ops.hasNext()) {
                PcodeOpAST op = ops.next();
                if (op.getOpcode() == PcodeOp.CALL) {
                    Varnode out = op.getOutput();
                    if (out != null && out.getDescendants().hasNext()) return true;
                }
            }
        }

        // LAYER 2: Smart Assembly Fallback (Read vs Write tracking)
        // Scans 5 instructions after the delay slot.
        try {
            Address scanStart = jalAddr.add(8);
            Instruction cur = getInstructionAt(scanStart);
            if (cur == null) cur = getInstructionAfter(scanStart);
            int checked = 0;
            
            boolean v0Overwritten = false;
            boolean v1Overwritten = false;
            boolean f0Overwritten = false;

            while (cur != null && checked < 5) {
                // First: Check if the register is READ (Input). 
                // If it's read before being overwritten -> Return value is used!
                Object[] inputObjs = cur.getInputObjects();
                for (Object obj : inputObjs) {
                    if (obj instanceof ghidra.program.model.lang.Register) {
                        String rname = ((ghidra.program.model.lang.Register) obj).getName().toLowerCase();
                        if (rname.equals("v0") && !v0Overwritten) return true;
                        if (rname.equals("v1") && !v1Overwritten) return true;
                        if (rname.equals("f0") && !f0Overwritten) return true;
                    }
                }

                // Second: Check if the register is WRITTEN to (Result).
                // If it's overwritten, we no longer care about it in subsequent instructions.
                Object[] resultObjs = cur.getResultObjects();
                for (Object obj : resultObjs) {
                    if (obj instanceof ghidra.program.model.lang.Register) {
                        String rname = ((ghidra.program.model.lang.Register) obj).getName().toLowerCase();
                        if (rname.equals("v0")) v0Overwritten = true;
                        if (rname.equals("v1")) v1Overwritten = true;
                        if (rname.equals("f0")) f0Overwritten = true;
                    }
                }

                cur = getInstructionAfter(cur.getAddress());
                checked++;
            }
        } catch (Exception ignored) {}

        return false;
    }
    // =========================================================
    // SCORING (V16 - Original V11 + Logic Engine + Target FPU)
    // =========================================================
    private ScoreBreakdown calculateScore(FuncTraits parent, FuncTraits target,
                                          Address parentAddr, Address jalAddr,
                                          int dangerDepth) {
        ScoreBreakdown bd = new ScoreBreakdown();

        // === LAYER 1: DNA (Extended Categories with Hardware fallback) ===
        
        // Priority 1: VU0 coprocessor / COP2 hardware
        if (target.isVu0 || target.usesCop2) {
            if (parent.hasFrameCounterPattern) {
                bd.category = "TIMERS"; bd.dnaScore = DNA_TIMER_PATTERN;
                bd.reasons.add("Timer Pattern (" + DNA_TIMER_PATTERN + ")");
            } else {
                bd.category = "VECTORS"; bd.dnaScore = DNA_VU0;
                bd.reasons.add("Vu0 Co-processor / COP2 (" + DNA_VU0 + ")");
            }
        }
        // Priority 2: Target is Heavy FPU Math OR uses COP1 hardware directly (Fixes mgSetProjection)
        else if (target.floatOps >= 6 || target.usesCop1) {
            bd.category = "VECTORS"; bd.dnaScore = DNA_HEAVY_FPU;
            bd.reasons.add("Target uses FPU/COP1 (" + DNA_HEAVY_FPU + ")");
        }
        // Priority 3: Target is Massive Script/Logic Engine
        else if (target.branchOps >= 8 && target.byteSize > 120 && target.floatOps == 0 && !target.usesCop1) {
            bd.category = "STATE_MACHINES"; bd.dnaScore = DNA_STATE_MACHINE;
            bd.reasons.add("Target is Logic Engine (" + DNA_STATE_MACHINE + ")");
        }
        // Priority 4: Massive Dispatcher Parent -> Small Worker (Fixes resume__10CRunScriptFv)
        else if (parent.byteSize >= 800 && parent.branchOps >= 20 && target.byteSize <= 150) {
            bd.category = "MACRO_SCRIPTS"; bd.dnaScore = DNA_MACRO_SCRIPT;
            bd.reasons.add("Massive Dispatcher -> Worker (" + DNA_MACRO_SCRIPT + ")");
        }
        // Priority 5: Timer pattern
        else if (parent.hasFrameCounterPattern ||
                 ((parent.hasTickIncrement || target.hasTickIncrement) &&
                  (parent.hasTimerCompare  || target.hasTimerCompare))) {
            bd.category = "TIMERS"; bd.dnaScore = DNA_TIMER_PATTERN;
            bd.reasons.add("Timer Pattern (" + DNA_TIMER_PATTERN + ")");
        }
        // Priority 6: Heavy FPU -> Pure Worker
        else if (parent.floatOps >= FPU_THRESHOLD && target.floatOps == 0 && target.byteSize <= 100) {
            bd.category = "VECTORS"; bd.dnaScore = DNA_HEAVY_FPU;
            bd.reasons.add("Heavy FPU -> Pure Worker (" + DNA_HEAVY_FPU + ")");
        }
        // Priority 7: Standard State Machine
        else if (parent.byteSize <= 350 && parent.branchOps >= 3 && parent.calledCount <= 15 &&
                 parent.floatOps == 0 && target.floatOps == 0 && target.byteSize <= 100) {
            bd.category = "STATE_MACHINES"; bd.dnaScore = DNA_STATE_MACHINE;
            bd.reasons.add("Entity State Machine (" + DNA_STATE_MACHINE + ")");
        }

        // === LAYER 2: DYNAMIC KILL-ZONE ===
        int killZoneLimit = 0;
        if      (bd.category.equals("TIMERS"))         killZoneLimit = 0;
        else if (bd.category.equals("MACRO_SCRIPTS"))  killZoneLimit = 1;
        else if (bd.category.equals("VECTORS"))        killZoneLimit = 2;
        else if (bd.category.equals("STATE_MACHINES")) killZoneLimit = 3;
        else if (bd.category.equals("UNKNOWN"))        killZoneLimit = 3; 

        // Parent buffer modifier
        if (parent.byteSize < 64)                             killZoneLimit = Math.max(0, killZoneLimit - 1);
        if (parent.byteSize > 2000 && parent.branchOps > 30) killZoneLimit += 1;

        // NEW: Protect orphans (depth -1) UNLESS they are UNKNOWN
        if (dangerDepth != -1 && dangerDepth <= killZoneLimit) {
            bd.isKilled   = true;
            bd.killReason = String.format("depth %d <= killZone %d (cat=%s)", dangerDepth, killZoneLimit, bd.category);
            return bd;
        }

        // === LAYER 3: ADDRESS BONUS ===
        long offset = jalAddr.getOffset() - PS2_BASE;
        if (offset < 0x040000L) {
            bd.isKilled   = true;
            bd.killReason = "AddrDanger: offset 0x" + Long.toHexString(offset) + " < 0x040000";
            return bd;
        } else if (offset < 0x080000L) {
            if (bd.category.equals("VECTORS") && offset >= 0x050000L) {
                bd.addressBonus = ADDR_VECTORS_MID;
                bd.reasons.add("AddrVectorsMid (+" + ADDR_VECTORS_MID + ")");
            } else {
                bd.addressBonus = ADDR_SUBSYSTEM;
            }
        } else if (offset < 0x100000L) {
            bd.addressBonus = ADDR_MID;
            bd.reasons.add("AddrMid (+" + ADDR_MID + ")");
        } else {
            bd.addressBonus = ADDR_SAFE;
            bd.reasons.add("AddrSafe (+" + ADDR_SAFE + ")");
        }

        // === LAYER 4: DEPTH/SAFETY BONUS ===
        if (dangerDepth == -1) {
            bd.depthBonus = 20;
            bd.reasons.add("SafeOrphan (+20)");
        } else if (dangerDepth >= killZoneLimit + 4) {
            bd.depthBonus = 15;
            bd.reasons.add("DeepTree d=" + dangerDepth + " (+15)");
        } else if (dangerDepth >= killZoneLimit + 3) {
            bd.depthBonus = 10;
            bd.reasons.add("Tree d=" + dangerDepth + " (+10)");
        } else if (dangerDepth >= killZoneLimit + 2) {
            bd.depthBonus = 5;
            bd.reasons.add("Tree d=" + dangerDepth + " (+5)");
        } else {
            bd.depthBonus = 0;
        }

        // === LAYER 5: NEXUS BONUS ===
        if (!frameRateNexus.isEmpty() &&
            frameRateNexus.containsKey(parentAddr) &&
            (bd.category.equals("VECTORS") || bd.category.equals("TIMERS"))) {
            bd.nexusBonus = NEXUS_BONUS;
            bd.reasons.add("Nexus (+" + NEXUS_BONUS + ")");
        }

        return bd;
    }

    // =========================================================
    // TRAITS EXTRACTION (with cache)
    // =========================================================
    private FuncTraits getTraits(Function func) {
        Address key = func.getEntryPoint();
        if (cache.containsKey(key)) return cache.get(key);

        FuncTraits traits = new FuncTraits();
        traits.byteSize    = func.getBody().getNumAddresses();
        traits.calledCount = func.getCalledFunctions(monitor).size();
        traits.isThunk     = isThunkFunction(func);
        // FIX: Hardware-level assembly scan to bypass Ghidra P-Code blindness
        if (func.getName().toLowerCase().contains("vu0") || 
            hasCop2Mnemonic(func, "scale") || 
            hasCop2Mnemonic(func, "add")) {
            traits.isVu0 = true;
        }
        if (traits.isThunk) {
            cache.put(key, traits);
            return traits;
        }

        // #1: Reuse HighFunction from cache (may already be decompiled by isReturnValueUsed)
        HighFunction highFunc = highFuncCache.get(key);
        if (highFunc == null) {
            DecompileResults res = decomp.decompileFunction(func, 15, monitor);
            highFunc = res.getHighFunction();
            if (highFunc != null) highFuncCache.put(key, highFunc);
        }
        if (highFunc == null) {
            cache.put(key, traits);
            return traits;
        }

        Map<Long, Integer> varIncrements      = new HashMap<>();
        Map<Long, Boolean> varHasFrameCompare = new HashMap<>();

        Iterator<PcodeOpAST> pcodeOps = highFunc.getPcodeOps();
        while (pcodeOps.hasNext()) {
            PcodeOp op     = pcodeOps.next();
            int     opcode = op.getOpcode();

            if (opcode == PcodeOp.FLOAT_MULT || opcode == PcodeOp.FLOAT_ADD ||
                opcode == PcodeOp.FLOAT_SUB  || opcode == PcodeOp.FLOAT_DIV) traits.floatOps++;
            if (opcode == PcodeOp.INT_ADD  || opcode == PcodeOp.INT_SUB ||
                opcode == PcodeOp.INT_MULT || opcode == PcodeOp.INT_DIV)  traits.mathOps++;
            if (opcode == PcodeOp.CBRANCH  || opcode == PcodeOp.BRANCHIND) traits.branchOps++;

            // CALLOTHER Hunter: Ghidra issue #113 — inlined VU0 intrinsics appear as CALLOTHER.
            // If the decompiler inlined _vmul/_vadd/_sqc2/_lqc2, mark this function as VU0.
            if (opcode == PcodeOp.CALLOTHER && !traits.isVu0) {
                Varnode nameVn = op.getInput(0);
                if (nameVn != null) {
                    // Ghidra stores the intrinsic name as the string representation of input 0
                    String intrinsicName = highFunc.getPcodeOps().hasNext()
                        ? nameVn.toString().toLowerCase() : "";
                    // More reliable: check via UserDefinedOp name lookup
                    try {
                        ghidra.app.plugin.processors.sleigh.SleighLanguage lang =
                            (ghidra.app.plugin.processors.sleigh.SleighLanguage)
                            currentProgram.getLanguage();
                        String opName = lang.getUserDefinedOpName((int) nameVn.getOffset()).toLowerCase();
                        if (opName.contains("vmul") || opName.contains("vadd") ||
                            opName.contains("vsub") || opName.contains("sqc2") ||
                            opName.contains("lqc2") || opName.contains("vscl") ||
                            opName.contains("vmadd")) {
                            traits.isVu0 = true;
                        }
                    } catch (Exception ignored) {}
                }
            }

            // Collect constants
            for (int i = 0; i < op.getNumInputs(); i++) {
                Varnode in = op.getInput(i);
                if (in != null && in.isConstant()) traits.constants.add(in.getOffset());
            }

            // Tick increment
            if (opcode == PcodeOp.INT_ADD) {
                Varnode output = op.getOutput();
                Varnode in1    = op.getInput(1);
                if (in1 != null && in1.isConstant() &&
                    (in1.getOffset() == 1L || in1.getOffset() == 0xFFFFFFFFL)) {
                    traits.hasTickIncrement = true;
                    if (output != null)
                        varIncrements.put(output.getOffset(),
                            varIncrements.getOrDefault(output.getOffset(), 0) + 1);
                }
            }

            // Frame compare
            if (opcode == PcodeOp.INT_LESS    || opcode == PcodeOp.INT_LESSEQUAL ||
                opcode == PcodeOp.INT_SLESS   || opcode == PcodeOp.INT_SLESSEQUAL) {
                Varnode in0 = op.getInput(0);
                Varnode in1 = op.getInput(1);
                if (in1 != null && in1.isConstant() && isFrameConst(in1.getOffset())) {
                    traits.hasTimerCompare = true;
                    if (in0 != null && !in0.isConstant())
                        varHasFrameCompare.put(in0.getOffset(), true);
                } else if (in0 != null && in0.isConstant() && isFrameConst(in0.getOffset())) {
                    traits.hasTimerCompare = true;
                    if (in1 != null && !in1.isConstant())
                        varHasFrameCompare.put(in1.getOffset(), true);
                }
            }
        }

        // Cross-reference
        for (Long varId : varIncrements.keySet()) {
            if (varHasFrameCompare.getOrDefault(varId, false)) {
                traits.hasFrameCounterPattern = true;
                break;
            }
        }

        // Detect global writes via raw assembly scan.
        // A store instruction (sw/swc1/sqc2/sh/sb) that has a Write reference to an
        // absolute address ≥ GLOBAL_ADDR_MIN means this function mutates global state.
        InstructionIterator asmIter = currentProgram.getListing().getInstructions(func.getBody(), true);
        outer:
        while (asmIter.hasNext()) {
            Instruction inst = asmIter.next();
            String mnem = inst.getMnemonicString().toLowerCase();
            
            // NEW: Hardware-level coprocessor detection (Bypasses Decompiler blindness)
            if (mnem.contains("c1") || mnem.endsWith(".s")) traits.usesCop1 = true;
            if (mnem.contains("c2") || mnem.startsWith("vadd") || mnem.startsWith("vmul") || 
                mnem.startsWith("vsub") || mnem.startsWith("vscl") || mnem.startsWith("sqc2") || 
                mnem.startsWith("lqc2")) traits.usesCop2 = true;

            if (!mnem.equals("sw") && !mnem.equals("swc1") && !mnem.equals("sqc2") &&
                !mnem.equals("sh") && !mnem.equals("sb")) continue;
            for (Reference ref : inst.getReferencesFrom()) {
                if (ref.getReferenceType().isWrite() &&
                    ref.getToAddress().getOffset() >= GLOBAL_ADDR_MIN) {
                    traits.writesToGlobal = true;
                    break outer;
                }
            }
        }
        cache.put(key, traits);
        return traits;
    }

    // =========================================================
    // HELPERS
    // =========================================================
    private boolean isThunkFunction(Function func) {
        if (func.isThunk()) return true;
        if (func.getBody().getNumAddresses() <= 8 &&
            func.getCalledFunctions(monitor).size() > 0) return true;
        return false;
    }

    // =========================================================
    // THUNK RESOLVER (Ghidra Issue #113 workaround)
    // If a function's body is a bare `j <addr>` (tail call), Ghidra may not
    // model it as a proper call graph edge. We follow the jump manually and
    // return the real destination for trait analysis.
    // The original JAL address is kept for the PNACH patch line.
    // =========================================================
    private Function resolveThunkTarget(Function func) {
        // Scan first 10 instructions for an unconditional `j` with no prior jal/jalr
        InstructionIterator iter = currentProgram.getListing()
            .getInstructions(func.getBody(), true);
        int checked = 0;
        while (iter.hasNext() && checked < 10) {
            Instruction inst = iter.next();
            checked++;
            String mnem = inst.getMnemonicString();
            // If we see a call before a bare jump, this isn't a simple thunk
            if (mnem.equals("jal") || mnem.equals("jalr")) return func;
            if (mnem.equals("j")) {
                Reference[] refs = inst.getReferencesFrom();
                if (refs.length == 0) return func;
                Address dest = refs[0].getToAddress();
                Function resolved = funcManager.getFunctionAt(dest);
                return (resolved != null && !resolved.equals(func)) ? resolved : func;
            }
        }
        return func;
    }

    private boolean isFrameConst(long val) {
        return val == 15 || val == 30 || val == 60 || val == 120 || val == 240;
    }

    private int calcDangerDepth(int d1, int d2) {
        if (d1 != -1 && d2 != -1) return Math.min(d1, d2);
        if (d1 != -1) return d1;
        if (d2 != -1) return d2;
        return -1;
    }

    private void buildCallTree(Function root, int maxDepth, Map<Address, Integer> tree) {
        if (root == null) return;
        Queue<Address> q = new LinkedList<>();
        q.add(root.getEntryPoint());
        tree.put(root.getEntryPoint(), 0);
        while (!q.isEmpty()) {
            Address curr  = q.poll();
            int     depth = tree.get(curr);
            if (depth >= maxDepth) continue;
            Function f = funcManager.getFunctionAt(curr);
            if (f == null) continue;
            for (Function callee : f.getCalledFunctions(monitor)) {
                Address calledAddr = callee.getEntryPoint();
                if (!tree.containsKey(calledAddr)) {
                    tree.put(calledAddr, depth + 1);
                    q.add(calledAddr);
                }
            }
        }
    }

    private void buildFrameRateNexus(Address varAddr) {
        ReferenceIterator varRefs = refManager.getReferencesTo(varAddr);
        Set<Function> seeds = new HashSet<>();
        while (varRefs.hasNext()) {
            Function f = funcManager.getFunctionContaining(varRefs.next().getFromAddress());
            if (f != null) seeds.add(f);
        }
        for (Function root : seeds) {
            Queue<Address>        q          = new LinkedList<>();
            Map<Address, Integer> localDepth = new HashMap<>();
            q.add(root.getEntryPoint());
            localDepth.put(root.getEntryPoint(), 0);
            frameRateNexus.put(root.getEntryPoint(), root.getName() + " (Direct)");
            while (!q.isEmpty()) {
                Address curr  = q.poll();
                int     depth = localDepth.get(curr);
                if (depth >= 10) continue;
                Function f = funcManager.getFunctionAt(curr);
                if (f == null) continue;
                for (Function callee : f.getCalledFunctions(monitor)) {
                    Address calledAddr = callee.getEntryPoint();
                    if (!localDepth.containsKey(calledAddr)) {
                        localDepth.put(calledAddr, depth + 1);
                        q.add(calledAddr);
                        frameRateNexus.putIfAbsent(calledAddr,
                            root.getName() + " (Depth: " + (depth + 1) + ")");
                    }
                }
            }
        }
    }

    private Address askAddressOptional(String title, String message) {
        try {
            return askAddress(title, message);
        } catch (Exception e) {
            return null; // User cancelled
        }
    }

    // =========================================================
    // V12 SNIPER - MODULE E: ANIMATION HUNTER
    // Detects: float param data flow + no COP2 in target + FPU in parent
    // Semantic keywords used as fast path when symbols exist.
    // =========================================================
    private boolean detectAnimationModifier(Function parentFunc, Function targetFunc, Address jalAddr) {
        Boolean cached = animDetectCache.get(jalAddr);
        if (cached != null) return cached;

        // 1. Parent must have float operations (animation blending/interpolation)
        FuncTraits parentTraits = cache.get(parentFunc.getEntryPoint());
        if (parentTraits == null || parentTraits.floatOps == 0) {
            animDetectCache.put(jalAddr, false);
            return false;
        }

        // 2. Target must NOT use COP2 computation — animation runs on main EE CPU
        if (hasCop2Mnemonic(targetFunc, "scale") || hasCop2Mnemonic(targetFunc, "add")) {
            animDetectCache.put(jalAddr, false);
            return false;
        }

        // 3a. Semantic fast path: check target name for animation keywords (non-stripped)
        String targetName = targetFunc.getName().toLowerCase();
        boolean semanticMatch = false;
        for (String kw : ANIM_KEYWORDS) {
            if (targetName.contains(kw)) { semanticMatch = true; break; }
        }

        // 3b. Universal: check if a Float argument is passed to this specific CALL
        boolean floatParamMatch = isFloatParamPassedToCall(parentFunc, jalAddr);

        boolean result = semanticMatch || floatParamMatch;
        animDetectCache.put(jalAddr, result);
        return result;
    }

    // Checks if the Target function reads from physical register f12 before writing to it.
    // f12 is the MIPS ABI register for the first float argument (fa0 in EE ABI).
    // If the target reads f12 as its first instruction, it was defined to accept a float param.
    // We look for any FLOAT op in the first ~8 pcode ops whose input is a register varnode
    // with offset matching f12 (Ghidra represents MIPS float regs in the register space).
    private boolean isFloatParamPassedToCall(Function parentFunc, Address jalAddr) {
        // Step 1: verify the parent's CALL at jalAddr produces a float-origin argument.
        // Reuse cached HighFunction from parent — no extra decompilation.
        HighFunction parentHF = highFuncCache.get(parentFunc.getEntryPoint());
        if (parentHF == null) return false;

        boolean parentSendsFloat = false;
        Iterator<PcodeOpAST> parentOps = parentHF.getPcodeOps(jalAddr);
        outer:
        while (parentOps.hasNext()) {
            PcodeOpAST op = parentOps.next();
            if (op.getOpcode() != PcodeOp.CALL) continue;
            for (int i = 1; i < op.getNumInputs(); i++) {
                Varnode in = op.getInput(i);
                if (in == null) continue;
                // Follow def chain one level — check if it came from a float operation
                PcodeOp def = in.getDef();
                if (def != null) {
                    int opc = def.getOpcode();
                    if (opc == PcodeOp.FLOAT_ADD  || opc == PcodeOp.FLOAT_MULT ||
                        opc == PcodeOp.FLOAT_SUB  || opc == PcodeOp.FLOAT_DIV  ||
                        opc == PcodeOp.FLOAT_INT2FLOAT || opc == PcodeOp.FLOAT_FLOAT2FLOAT ||
                        opc == PcodeOp.FLOAT_ABS  || opc == PcodeOp.FLOAT_SQRT) {
                        parentSendsFloat = true;
                        break outer;
                    }
                }
                // Also accept if Ghidra resolved the type as float/double
                HighVariable hv = in.getHigh();
                if (hv != null && hv.getDataType() != null) {
                    String tn = hv.getDataType().getName().toLowerCase();
                    if (tn.equals("float") || tn.equals("double")) {
                        parentSendsFloat = true;
                        break outer;
                    }
                }
            }
        }
        if (!parentSendsFloat) return false;

        // Step 2: verify the Target reads f12 before writing it (i.e., it expects a float param).
        // Scan the first ~12 P-Code ops of the target for a use of a register varnode
        // whose offset matches the f12 register in Ghidra's MIPS register space.
        ghidra.program.model.lang.Register f12Reg =
            currentProgram.getLanguage().getRegister("f12");
        if (f12Reg == null) {
            // Fallback if Ghidra doesn't name it f12: accept parent evidence alone
            return true;
        }
        long f12Offset = f12Reg.getOffset();

        // Decompile target if not already cached (targets are usually small)
        Address targetEntry = null;
        // We only reach here for the specific target passed to detectAnimationModifier,
        // so decompile it directly (result cached by highFuncCache).
        // Look up target function from jalAddr reference
        Reference[] refs = getInstructionAt(jalAddr) != null
            ? getInstructionAt(jalAddr).getReferencesFrom() : new Reference[0];
        if (refs.length == 0) return true; // can't verify, trust parent evidence
        Function targetFunc = funcManager.getFunctionAt(refs[0].getToAddress());
        if (targetFunc == null) return true;

        targetEntry = targetFunc.getEntryPoint();
        HighFunction targetHF = highFuncCache.get(targetEntry);
        if (targetHF == null) {
            DecompileResults res = decomp.decompileFunction(targetFunc, 10, monitor);
            targetHF = res.getHighFunction();
            if (targetHF != null) highFuncCache.put(targetEntry, targetHF);
        }
        if (targetHF == null) return true; // trust parent evidence

        int checkedOps = 0;
        Iterator<PcodeOpAST> targetOps = targetHF.getPcodeOps();
        while (targetOps.hasNext() && checkedOps < 12) {
            PcodeOpAST op = targetOps.next();
            checkedOps++;
            for (int i = 0; i < op.getNumInputs(); i++) {
                Varnode in = op.getInput(i);
                if (in != null && in.isRegister() && in.getOffset() == f12Offset) return true;
            }
        }
        return false;
    }

    // =========================================================
    // MODULE F: GLOBAL STATE WRITER DETECTOR (#2)
    // Scans Parent assembly for store instructions (sw/swc1/sqc2) that target
    // an absolute memory address (global variable), not a register-relative offset.
    // These are guaranteed State mutators — safe and valuable to NOP.
    // =========================================================
    private boolean parentWritesToGlobal(Function parentFunc, Address jalAddr) {
        Address key = jalAddr; // per-JAL cache
        Boolean cached = globalWriteCache.get(key);
        if (cached != null) return cached;

        // Scan a window of ±20 instructions around the JAL site
        boolean result = false;
        InstructionIterator iter = currentProgram.getListing()
            .getInstructions(parentFunc.getBody(), true);
        Address jalOffset = jalAddr;
        List<Instruction> window = new ArrayList<>();

        // Collect all instructions, then find the JAL and check ±20
        List<Instruction> all = new ArrayList<>();
        while (iter.hasNext()) all.add(iter.next());

        int jalIdx = -1;
        for (int i = 0; i < all.size(); i++) {
            if (all.get(i).getAddress().equals(jalOffset)) { jalIdx = i; break; }
        }
        if (jalIdx >= 0) {
            int from = Math.max(0, jalIdx - 20);
            int to   = Math.min(all.size() - 1, jalIdx + 5);
            for (int i = from; i <= to && !result; i++) {
                Instruction inst = all.get(i);
                String mnem = inst.getMnemonicString().toLowerCase();
                if (!mnem.equals("sw") && !mnem.equals("swc1") &&
                    !mnem.equals("sqc2") && !mnem.equals("sh") && !mnem.equals("sb")) continue;
                // A global store has a direct memory reference (not register-relative)
                for (Reference ref : inst.getReferencesFrom()) {
                    if (ref.getReferenceType().isWrite()) {
                        long addr = ref.getToAddress().getOffset();
                        if (addr >= GLOBAL_ADDR_MIN) { result = true; break; }
                    }
                }
            }
        }

        globalWriteCache.put(key, result);
        return result;
    }

    // =========================================================
    // MODULE G: ENTITY STRUCT WRITER DETECTOR (#3)
    // Scans Parent assembly near the JAL for swc1/sqc2 to low struct offsets
    // (0x00 – STRUCT_OFFSET_MAX) from pointer registers (a0/a1/s0/s1/s2).
    // This is the clearest signature of a kinematic/position update.
    // =========================================================
    private boolean parentWritesToEntityStruct(Function parentFunc, Address jalAddr) {
        Boolean cached = structWriteCache.get(jalAddr);
        if (cached != null) return cached;

        boolean result = false;
        List<Instruction> all = new ArrayList<>();
        InstructionIterator iter = currentProgram.getListing()
            .getInstructions(parentFunc.getBody(), true);
        while (iter.hasNext()) all.add(iter.next());

        int jalIdx = -1;
        for (int i = 0; i < all.size(); i++) {
            if (all.get(i).getAddress().equals(jalAddr)) { jalIdx = i; break; }
        }

        if (jalIdx >= 0) {
            // Look in a window of 15 instructions before and 3 after the JAL
            int from = Math.max(0, jalIdx - 15);
            int to   = Math.min(all.size() - 1, jalIdx + 3);
            for (int i = from; i <= to && !result; i++) {
                Instruction inst = all.get(i);
                String mnem = inst.getMnemonicString().toLowerCase();
                if (!mnem.equals("swc1") && !mnem.equals("sqc2")) continue;
                // Check operands: looking for pattern like "swc1 fX, 0x10(s0)"
                for (int op = 0; op < inst.getNumOperands(); op++) {
                    Object[] objs = inst.getOpObjects(op);
                    for (Object obj : objs) {
                        // Ghidra represents the displacement as a Scalar
                        if (obj instanceof ghidra.program.model.scalar.Scalar) {
                            long disp = ((ghidra.program.model.scalar.Scalar) obj).getValue();
                            if (disp >= 0 && disp <= STRUCT_OFFSET_MAX) {
                                result = true;
                                break;
                            }
                        }
                    }
                    if (result) break;
                }
            }
        }

        structWriteCache.put(jalAddr, result);
        return result;
    }

    private void writeCategory(PrintWriter writer, String title, List<ScoredJAL> list) {
        if (list.isEmpty()) return;
        writer.println("// =========================================================");
        writer.println("// " + title);
        writer.println("// Count: " + list.size());
        writer.println("// =========================================================");
        for (ScoredJAL j : list) writer.println(j.pnachLine);
        writer.println();
    }

    // =========================================================
    // V12 SNIPER - MODULE A: EULER HUNTER (Instruction-Level Resolution)
    // Asks: "Is THIS specific JAL the AddVector that follows a ScaleVector?"
    // Only the AddVector JAL gets the bonus — not every JAL in the parent.
    // =========================================================
    private boolean detectEulerPattern(Function parentFunc, Function targetFunc, Address jalAddr) {
        // Fast exit: if this JAL's target is not an Add function, no bonus possible.
        if (!isCop2AddFunction(targetFunc)) return false;

        // Cache by specific JAL address (not parent), since each JAL needs its own answer.
        Boolean cached = eulerPatternCache.get(jalAddr);
        if (cached != null) return cached;

        // Get (or build) the ordered list of JALs for this parent.
        // Each entry is a long[2]: [jalOffset, targetEntryOffset] for fast lookup.
        Address parentEntry = parentFunc.getEntryPoint();
        List<long[]> jalList = parentJalListCache.get(parentEntry);
        if (jalList == null) {
            jalList = new ArrayList<>();
            InstructionIterator iter = currentProgram.getListing()
                .getInstructions(parentFunc.getBody(), true);
            while (iter.hasNext()) {
                Instruction i = iter.next();
                if (!i.getMnemonicString().equals("jal")) continue;
                Reference[] refs = i.getReferencesFrom();
                if (refs.length == 0) continue;
                Function t = funcManager.getFunctionAt(refs[0].getToAddress());
                long targetOffset = (t != null) ? t.getEntryPoint().getOffset() : -1L;
                jalList.add(new long[]{ i.getAddress().getOffset(), targetOffset });
            }
            parentJalListCache.put(parentEntry, jalList);
        }

        // Find this JAL's index in the list, then look backward for a Scale within EULER_WINDOW.
        long thisOffset = jalAddr.getOffset();
        int thisIdx = -1;
        for (int i = 0; i < jalList.size(); i++) {
            if (jalList.get(i)[0] == thisOffset) { thisIdx = i; break; }
        }

        boolean result = false;
        if (thisIdx > 0) {
            int lookbackStart = Math.max(0, thisIdx - EULER_WINDOW);
            for (int i = lookbackStart; i < thisIdx && !result; i++) {
                long tOff = jalList.get(i)[1];
                if (tOff == -1L) continue;
                Address tAddr = currentProgram.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(tOff);
                Function prev = funcManager.getFunctionAt(tAddr);
                if (prev != null && isCop2ScaleFunction(prev)) result = true;
            }
        }

        eulerPatternCache.put(jalAddr, result);
        return result;
    }

    // Scale: vmul/vscl/vmadd mnemonics OR COP2 opcode (stripped)
    private boolean isCop2ScaleFunction(Function func) {
        String name = func.getName();
        if (name.contains("ScaleVector") || name.contains("ApplyMatrix") ||
            name.contains("ApplyRotMatrix")) return true;
        return hasCop2Mnemonic(func, "scale");
    }

    // Add: vadd/vsub mnemonics OR COP2 opcode (stripped)
    private boolean isCop2AddFunction(Function func) {
        if (func.getName().contains("AddVector")) return true;
        return hasCop2Mnemonic(func, "add");
    }

    // Scan function body for VU0 macro instructions
    private boolean hasCop2Mnemonic(Function func, String type) {
        InstructionIterator iter = currentProgram.getListing()
            .getInstructions(func.getBody(), true);
        while (iter.hasNext()) {
            Instruction inst = iter.next();
            String mnem = inst.getMnemonicString().toLowerCase();
            if (type.equals("scale") &&
                (mnem.startsWith("vmul") || mnem.startsWith("vscl") || mnem.startsWith("vmadd")))
                return true;
            if (type.equals("add") &&
                mnem.startsWith("vadd") && !mnem.startsWith("vmul"))
                return true;
            // Raw byte fallback for stripped binaries:
            // COP2 primary opcode = bits 31-26 must be 0x12.
            // Bit 25 = 1 means VU0 macro computation (vadd/vmul/vscl...).
            // Bit 25 = 0 means move/control (MFC2/MTC2/CFC2/CTC2) — reject these.
            try {
                byte[] b = inst.getBytes();
                if (b.length == 4) {
                    int word = ((b[3] & 0xFF) << 24) | ((b[2] & 0xFF) << 16) |
                               ((b[1] & 0xFF) <<  8) |  (b[0] & 0xFF);
                    boolean isCop2        = ((word >>> 26) & 0x3F) == 0x12;
                    boolean isComputation = ((word >>> 25) & 0x01) == 1;
                    if (isCop2 && isComputation) return true;
                }
            } catch (Exception ignored) {}
        }
        return false;
    }

    // =========================================================
    // V12 SNIPER - MODULE B: KINEMATIC HUNTER (sinf/cosf data flow -> CopyVector)
    // Traces P-Code def-use chain backwards from CALL inputs to find sinf/cosf origin.
    // =========================================================
    private boolean detectKinematicPattern(Function parentFunc, Function targetFunc,
                                           Address jalAddr) {
        // Target must be a vector copy (by name, or small COP2 function)
        boolean targetIsCopy = targetFunc.getName().contains("CopyVector")
            || (targetFunc.getBody().getNumAddresses() <= 64 && hasCop2Mnemonic(targetFunc, "add"));
        if (!targetIsCopy) return false;

        Address key = parentFunc.getEntryPoint();
        Boolean cached = kinematicCache.get(key);
        if (cached != null) return cached;

        // Get (or reuse) HighFunction
        HighFunction highFunc = highFuncCache.get(key);
        if (highFunc == null) {
            DecompileResults res = decomp.decompileFunction(parentFunc, 15, monitor);
            highFunc = res.getHighFunction();
            if (highFunc == null) { kinematicCache.put(key, false); return false; }
            highFuncCache.put(key, highFunc);
        }

        // Find the CALL pcode op at jalAddr
        boolean result = false;
        Iterator<PcodeOpAST> ops = highFunc.getPcodeOps(jalAddr);
        outer:
        while (ops.hasNext()) {
            PcodeOpAST op = ops.next();
            if (op.getOpcode() != PcodeOp.CALL) continue;
            // Trace each input argument (skip i=0 = callee address)
            for (int i = 1; i < op.getNumInputs(); i++) {
                if (tracesToTrigFunction(op.getInput(i))) { result = true; break outer; }
            }
        }

        kinematicCache.put(key, result);
        return result;
    }

    // BFS backwards through P-Code def chain looking for a sinf/cosf CALL
    private boolean tracesToTrigFunction(Varnode start) {
        if (start == null) return false;
        Set<Varnode> visited = new HashSet<>();
        Queue<Varnode>  queue = new LinkedList<>();
        queue.add(start);
        while (!queue.isEmpty()) {
            Varnode curr = queue.poll();
            if (curr == null || !visited.add(curr)) continue;
            PcodeOp def = curr.getDef();
            if (def == null) continue;
            int opc = def.getOpcode();
            if (opc == PcodeOp.CALL || opc == PcodeOp.CALLIND) {
                Varnode callTarget = def.getInput(0);
                if (callTarget != null && callTarget.isAddress()) {
                    Function callee = funcManager.getFunctionAt(callTarget.getAddress());
                    if (callee != null) {
                        String n = callee.getName();
                        if (n.equals("sinf") || n.equals("cosf") ||
                            n.equals("sin")  || n.equals("cos"))  return true;
                    }
                }
            }
            // Continue tracing through non-address, non-constant inputs
            for (int i = 0; i < def.getNumInputs(); i++) {
                Varnode in = def.getInput(i);
                if (in != null && !in.isConstant() && !in.isAddress()) queue.add(in);
            }
        }
        return false;
    }

    // =========================================================
    // V12 SNIPER - MODULE C: HIERARCHY MATRIX (loop detection in grandparents)
    // BATCH = any caller contains a backward branch that encloses the JAL to parentFunc.
    // SINGLETON = no caller has such a loop.
    // =========================================================
    private String calcHierarchyType(Function parentFunc) {
        Address key = parentFunc.getEntryPoint();
        String cached = hierarchyCache.get(key);
        if (cached != null) return cached;

        Set<Function> callers = parentFunc.getCallingFunctions(monitor);
        if (callers.isEmpty()) {
            hierarchyCache.put(key, "SINGLETON");
            return "SINGLETON";
        }

        for (Function caller : callers) {
            if (callerContainsLoopAroundCall(caller, key)) {
                hierarchyCache.put(key, "BATCH");
                return "BATCH";
            }
        }

        hierarchyCache.put(key, "SINGLETON");
        return "SINGLETON";
    }

    // Returns true if `caller` contains a backward branch that brackets a JAL to `calleeEntry`
    private boolean callerContainsLoopAroundCall(Function caller, Address calleeEntry) {
        // Step 1: find the JAL site inside caller
        Address jalSite = null;
        InstructionIterator it = currentProgram.getListing()
            .getInstructions(caller.getBody(), true);
        while (it.hasNext()) {
            Instruction inst = it.next();
            if (!inst.getMnemonicString().equals("jal")) continue;
            Reference[] refs = inst.getReferencesFrom();
            if (refs.length > 0 && refs[0].getToAddress().equals(calleeEntry)) {
                jalSite = inst.getAddress();
                break;
            }
        }
        if (jalSite == null) return false;

        // Step 2: look for a backward branch (loop-end) that brackets jalSite.
        // A backward branch at address B with flow-target T satisfies:
        //   T < B  (backward)  AND  T <= jalSite <= B  (jalSite is inside the loop body)
        InstructionIterator it2 = currentProgram.getListing()
            .getInstructions(caller.getBody(), true);
        while (it2.hasNext()) {
            Instruction inst = it2.next();
            String mnem = inst.getMnemonicString();
            // MIPS conditional branches and unconditional jumps used as loop closers
            if (!mnem.startsWith("b") && !mnem.equals("j") && !mnem.equals("jr")) continue;
            for (Reference ref : inst.getReferencesFrom()) {
                if (!ref.getReferenceType().isFlow()) continue;
                Address target = ref.getToAddress();
                Address branchAt = inst.getAddress();
                if (target.compareTo(branchAt)  < 0 &&   // backward
                    target.compareTo(jalSite)   <= 0 &&   // loop start is before (or at) jal
                    branchAt.compareTo(jalSite) >= 0) {   // loop end is after (or at) jal
                    return true;
                }
            }
        }
        return false;
    }

    // =========================================================
    // V12 SNIPER - MODULE D: TRACER BULLETS (write N-sized chunks)
    // =========================================================
    private void writeTracerBullets(File baseFile, List<ScoredJAL> allResults,
                                     int chunkSize) throws IOException {
        if (allResults.isEmpty()) return;
        String basePath = baseFile.getParent();
        String baseName = baseFile.getName().replaceFirst("\\..*$", "");
        int chunkIndex  = 1;
        int total       = allResults.size();

        for (int i = 0; i < total; i += chunkSize) {
            List<ScoredJAL> chunk = allResults.subList(i, Math.min(i + chunkSize, total));
            String fileName = String.format("%s_chunk_%02d_of_%02d.txt",
                baseName, chunkIndex, (int) Math.ceil((double) total / chunkSize));
            PrintWriter w = new PrintWriter(new FileWriter(new File(basePath, fileName)));
            w.println("// V12 Tracer Bullet - Chunk " + chunkIndex +
                      " (" + (i+1) + "-" + Math.min(i+chunkSize, total) + " of " + total + ")");
            w.println("// Load this chunk in PCSX2 and test. Binary search: if broken, try chunk/2.");
            w.println();
            for (ScoredJAL j : chunk) w.println(j.pnachLine);
            w.close();
            println("[TRACER] Wrote: " + fileName + " (" + chunk.size() + " patches)");
            chunkIndex++;
        }
    }
}
