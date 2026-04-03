// PS2 Scoring Radar V13 Final - The Definitive Edition
// EE Hardware-Aware + Full Binary Profiling + All Pattern Modules + 60FPS Hunter
// Architecture: V11 Safety Core + V12 Binary Profiling + V13 EE Specifics + V13 Final Fixes
// @author Gemini + Claude + Puggsy
// @category PlayStation2

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.block.*;
import java.util.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PS2_Scoring_Radar extends GhidraScript {

    // =========================================================
    // PS2 ARCHITECTURE CONSTANTS
    // =========================================================
    private static final long PS2_BASE        = 0x00100000L;
    private static final long MMIO_START      = 0x10000000L;
    private static final long MMIO_END        = 0x1000FFFFL;
    private static final long GS_PRIV_START   = 0x12000000L;
    private static final long GS_PRIV_END     = 0x12001FFFL;
    private static final long KSEG1_START     = 0x20000000L;
    private static final long SPR_START       = 0x70000000L;
    private static final long SPR_END         = 0x70003FFFL;
    private static final long GLOBAL_ADDR_MIN = 0x00100000L;
    private static final long STRUCT_OFFSET_MAX = 0x60L;

    // =========================================================
    // SCORING CONSTANTS
    // =========================================================
    private static final int DNA_VU0            = 45;
    private static final int DNA_TIMER_PATTERN  = 45;
    private static final int DNA_STATE_MACHINE  = 35;
    private static final int DNA_HEAVY_FPU      = 35;
    private static final int DNA_MACRO_SCRIPT   = 30;
    private static final int DNA_ANIMATION      = 40;
    private static final int DNA_ANIM_TICKER    = 40;

    private static final int ADDR_SAFE          = 25;
    private static final int ADDR_VECTORS_MID   = 20;
    private static final int ADDR_MID           = 10;

    private static final int NEXUS_BONUS            = 10;
    private static final int ANIM_NEXUS_BONUS        = 40;
    private static final int ANIM_HEURISTIC_BONUS    = 25;
    private static final int ANIM_FPU_THRESHOLD      =  8;
    private static final int ANIM_BRANCH_THRESHOLD   =  5;
    private static final int EULER_BONUS             = 25;
    private static final int KINEMATIC_BONUS         = 20;
    private static final int SINGLETON_BONUS         = 15;
    private static final int BATCH_PENALTY           = -10;
    private static final int GLOBAL_WRITE_BONUS      = 20;
    private static final int STRUCT_WRITE_BONUS      = 15;
    private static final int SPR_BONUS               = 15;
    private static final int QVU_BONUS               = 10;
    private static final int VTABLE_BONUS            = 20;
    private static final int CONTEXT_BONUS           = 10;
    private static final int CLUSTER_BONUS           = 12;
    private static final int DEPTH_BONUS_MACRO       = 15; // MACRO_SCRIPT at depth 1-2
    private static final int DEPTH_PENALTY_ANIM_SHALLOW = -20; // ANIM_TICKER at depth 1

    private static final int SCORE_THRESHOLD    = 50;
    private static final int FPU_THRESHOLD      = 12;
    private static final int EULER_WINDOW       =  5;
    private static final int ACC_OPS_THRESHOLD  =  4;

    // V13 Final: per-category caller ceilings and penalties
    private static final int MAX_CALLERS_MACRO   =  5;
    private static final int MAX_CALLERS_TIMERS  =  8;
    private static final int MAX_CALLERS_STATE   = 10;
    private static final int MAX_CALLERS_VECTORS = 12;
    private static final int MAX_CALLERS_ANIM    = 15;
    private static final int MAX_CALLERS_DEFAULT = 15;
    private static final int PENALTY_MACRO   = 8;
    private static final int PENALTY_TIMERS  = 6;
    private static final int PENALTY_STATE   = 5;
    private static final int PENALTY_VECTORS = 4;
    private static final int PENALTY_ANIM    = 3;
    private static final int PENALTY_DEFAULT = 5;

    // 60FPS float delta targets (IEEE 754 approximations)
    private static final float DELTA_30FPS = 0.03333333f; // 1/30
    private static final float DELTA_60FPS = 0.01666666f; // 1/60
    private static final float DELTA_EPSILON = 0.002f;

    // =========================================================
    // FIREWALLS
    // =========================================================
    private static final String[] STATIC_FIREWALL_PREFIXES = {
        "sceCd","sceMc","scePad","sceSif","sceVif","sceDma",
        "sceIpu","sceGs","sceVu1",
        "malloc","free","realloc","calloc","memcpy","memset","memmove",
        "printf","sprintf","vsprintf","strcpy","strlen","strcmp","strcat",
        "sin","cos","tan","atan","atan2","sqrt","pow","exp","log","fabs","floor","ceil",
        "__builtin_new","__builtin_vec_new","__builtin_delete",
        "__sti","__std","_GLOBAL_","__gnu_","__cxa_",
        "sceOpen","sceClose","sceRead","sceWrite","sceLseek",
        "sceSifCallRpc","sceSifBindRpc"
    };
    private static final String[] BIOS_FIREWALL_PREFIXES = {
        "CreateThread","StartThread","ExitThread","SleepThread",
        "WakeupThread","iWakeupThread","RotateThreadReadyQueue",
        "CreateSema","WaitSema","SignalSema","DeleteSema",
        "iWaitSema","iSignalSema","PollSema","iPollSema",
        "AddIntcHandler","RemoveIntcHandler","EnableIntc","DisableIntc",
        "AddDmacHandler","RemoveDmacHandler","EnableDmac","DisableDmac",
        "SetVSyncFlag","SetSyscall","SetVBlankHandler","SetHBlankHandler",
        "FlushCache","AllocSysMemory","FreeSysMemory"
    };
    private static final String[] DANGEROUS_KEYWORDS = {
        "save","load","mcwrite","mcread","mcformat","checkpoint","autosave","typeinfo","vtable"
    };
    private static final String[] IOP_MODULE_STRINGS = {
        "loadcore","iopmac","iopheap","threadman","sysclib","sifman","sifcmd",
        "cdvdman","cdvdfsv","mcman","xmcman","mcserv","atad","hdd","pfs",
        "sio2man","padman","xpadman","mtapman","libsd","sdrdrv","audsrv","modmidi",
        "usbd","dev9","smap","ps2smap","ps2ip",".IRX",".irx",".BIN",".bin",".DAT",".dat"
    };
    private static final String[] ANIM_KEYWORDS = {
        "motion","anim","pose","skeleton","blend","setframe","settime",
        "changemotion","setmotion","updatebone","interp","particle","effect","spawn"
    };
    private static final String[] MAINLOOP_ANCHORS = {
        "sceGsSyncV","sceGsSwapDB","scePadRead","scePadGetState","FlushCache"
    };

    // =========================================================
    // INNER CLASSES
    // =========================================================
    class FuncTraits {
        int  floatOps=0, branchOps=0, mathOps=0, loadOps=0, returnPaths=0;
        long byteSize=0;
        int  calledCount=0;
        boolean isVu0=false, isThunk=false;
        boolean hasTickIncrement=false, hasTimerCompare=false, hasFrameCounterPattern=false;
        boolean writesToGlobal=false, usesCop1=false, usesCop2=false;
        boolean usesSPR=false, hasStackFrame=false, hasMutatingInstructions=false;
        int quadwordVU=0, quadwordGeneral=0, accOps=0;
        int callOps=0; // assembly-level call counter (catches jalr that calledCount misses)
        Set<Long> constants = new TreeSet<>();
    }

    class ParentContext {
        Function parent; Address jalAddr; FuncTraits parentTraits;
        int depthInTree; boolean inNexus;
        int baseScore=0; String baseCategory="UNKNOWN";
        int v12Bonus=0; List<String> v12Tags=new ArrayList<>();
        String hierarchy="UNKNOWN"; boolean wasResolved=false; Function resolvedTarget;
    }

    class TargetProfile {
        Function targetFunc; FuncTraits targetTraits;
        List<ParentContext> callers=new ArrayList<>();
        int totalCallers=0, maxScore=0, finalScore=0;
        double avgParentSize=0, avgParentFPU=0;
        int deepestDepth=-1, shallowestDepth=Integer.MAX_VALUE;
        boolean anyInNexus=false, isVtableHook=false;
        boolean hasReturnDependency=false, contextBonusApplied=false;
        String assignedCategory="UNKNOWN"; String sprTag="";
        List<String> bestTags=new ArrayList<>();
    }

    class ScoreBreakdown {
        int dnaScore=0, depthBonus=0, nexusBonus=0, addressBonus=0;
        boolean isKilled=false; String killReason=""; String category="UNKNOWN";
        List<String> reasons=new ArrayList<>();
        int total() { return isKilled?0:dnaScore+depthBonus+nexusBonus+addressBonus; }
    }

    class MainLoopCandidate {
        Address addr; String name; Set<String> anchorsHit; int score;
        MainLoopCandidate(Address a,String n,Set<String> h){addr=a;name=n;anchorsHit=h;score=h.size();}
    }

    class StrideCandidate {
        Address addr; String funcName; String description;
        StrideCandidate(Address a,String f,String d){addr=a;funcName=f;description=d;}
    }

    // =========================================================
    // STATE
    // =========================================================
    private FunctionManager  funcManager;
    private ReferenceManager refManager;
    private SymbolTable      symbolTable;
    private Memory           memory;
    private DecompInterface  decomp;

    private Map<Address,Integer>      mainLoop1Tree      = new HashMap<>();
    private Map<Address,Integer>      mainLoop2Tree      = new HashMap<>();
    private Map<Address,String>       frameRateNexus     = new HashMap<>();
    private Map<Address,FuncTraits>   cache              = new HashMap<>();
    private Map<Address,HighFunction> highFuncCache      = new HashMap<>();
    private Map<Address,Boolean>      staticFwCache      = new HashMap<>();
    private Map<Address,Boolean>      iopFwCache         = new HashMap<>();
    private Map<Address,Boolean>      behavFwCache       = new HashMap<>();
    private Map<Address,Boolean>      eulerCache         = new HashMap<>();
    private Map<Address,List<long[]>> parentJalListCache = new HashMap<>();
    private Map<Address,Boolean>      animDetectCache    = new HashMap<>();
    private Map<Address,Boolean>      globalWriteCache   = new HashMap<>();
    private Map<Address,Boolean>      structWriteCache   = new HashMap<>();
    private Map<Address,Boolean>      kinematicCache     = new HashMap<>();
    private Map<Address,String>       hierarchyCache     = new HashMap<>();
    private Map<Address,TargetProfile> targetProfiles    = new HashMap<>();
    private Map<Long,String>          globalHooks        = new TreeMap<>();

    // V13: suppress storing HighFunction in cache during Pass 2 (OOM prevention)
    private boolean suppressHFCache = false;

    private int staticFirewallBlocked=0, iopFirewallBlocked=0, behavFirewallBlocked=0;
    private int dependencyBlocked=0, killedByZone=0, thunksSkipped=0;
    private int pureMathKilled=0, utilityDropped=0, vtableFound=0;

    // =========================================================
    // ENTRY POINT
    // =========================================================
    @Override
    public void run() throws Exception {
        funcManager = currentProgram.getFunctionManager();
        refManager  = currentProgram.getReferenceManager();
        symbolTable = currentProgram.getSymbolTable();
        memory      = currentProgram.getMemory();
        decomp      = new DecompInterface();
        decomp.openProgram(currentProgram);

        println("=========================================================");
        println("PS2 SCORING RADAR V13 FINAL - THE DEFINITIVE EDITION");
        println("EE Hardware-Aware + All Modules + 60FPS Hunter + Memory-Safe");
        println("=========================================================\n");

        boolean doTracerBullets = false;
        try {
            doTracerBullets = askYesNo("Tracer Bullets",
                "Generate a Tracer Bullets file for binary search?\n(Single .txt file beside main output)");
        } catch(Exception ignored){}

        // --- MainLoop Detection ---
        Address mainLoop1Addr=null, mainLoop2Addr=null;
        boolean autoDetect=false;
        try { autoDetect=askYesNo("MainLoop Detection",
            "Auto-detect MainLoop via topology analysis?\n(No = manual input for stripped binaries)");
        } catch(Exception ignored){}

        List<MainLoopCandidate> loopCandidates = new ArrayList<>();
        if (autoDetect) {
            loopCandidates = findMainLoopCandidates();
            if (!loopCandidates.isEmpty()) {
                println("[AUTO-DETECT] Found " + loopCandidates.size() + " candidate(s):");
                for (int i=0;i<Math.min(5,loopCandidates.size());i++) {
                    MainLoopCandidate c=loopCandidates.get(i);
                    println("  ["+(i+1)+"] "+c.name+" @ "+c.addr+" (topo:"+c.score+")");
                }
                mainLoop1Addr=loopCandidates.get(0).addr;
                if(loopCandidates.size()>=2) mainLoop2Addr=loopCandidates.get(1).addr;
                println();
            } else {
                println("[AUTO-DETECT] No candidates. Falling back to manual.\n");
                autoDetect=false;
            }
        }
        if (!autoDetect) {
            mainLoop1Addr=askAddressOptional("Main Loop 1 (Gameplay)","Address of Gameplay MainLoop (Cancel=skip)");
            mainLoop2Addr=askAddressOptional("Main Loop 2 (Menu)","Address of Menu MainLoop (Cancel=skip)");
        }

        // V13 Final: Hybrid Nexus — accepts code address OR data address
        Address nexusInput = askAddressOptional("Nexus Seed",
            "FrameRate variable OR VSync instruction address (Cancel=skip)");
        File outputFile = askFile("Save PNACH output","Save as...");

        if (mainLoop1Addr!=null){buildCallTree(funcManager.getFunctionAt(mainLoop1Addr),15,mainLoop1Tree);println("[*] Gameplay Tree: "+mainLoop1Tree.size()+" functions.");}
        if (mainLoop2Addr!=null){buildCallTree(funcManager.getFunctionAt(mainLoop2Addr),15,mainLoop2Tree);println("[*] Menu Tree: "+mainLoop2Tree.size()+" functions.");}
        if (nexusInput!=null){buildFrameRateNexus(nexusInput);println("[*] Nexus: "+frameRateNexus.size()+" functions.");}
        println();

        // =========================================================
        // PASS 1: JAL SCAN
        // =========================================================
        println("[PASS 1] Pre-counting JAL instructions...");
        int totalJals=0;
        { InstructionIterator pre=currentProgram.getListing().getInstructions(true);
          while(pre.hasNext()&&!monitor.isCancelled()) if("jal".equals(pre.next().getMnemonicString())) totalJals++; }
        println("[PASS 1] "+totalJals+" JAL instructions. Starting scan...\n");

        long scanStart=System.currentTimeMillis();
        int jalsSeen=0, processed=0, lastPct=-1;

        InstructionIterator instIter=currentProgram.getListing().getInstructions(true);
        while(instIter.hasNext()&&!monitor.isCancelled()) {
            Instruction inst=instIter.next();
            String mnem=inst.getMnemonicString();
            if(mnem==null||!mnem.equals("jal")) continue;
            jalsSeen++;

            if(totalJals>0){
                int pct=(jalsSeen*100)/totalJals;
                if(pct!=lastPct&&pct%10==0){
                    lastPct=pct;
                    long el=System.currentTimeMillis()-scanStart;
                    String eta="...";
                    if(pct>0){long r=((el*100L)/pct)-el;long s=r/1000;eta=s>=60?String.format("%dm%02ds",s/60,s%60):s+"s";}
                    int f=pct/5;
                    println(String.format("[SCAN] [%s%s] %3d%% | JAL:%d/%d | ETA:%s","#".repeat(f),".".repeat(20-f),pct,jalsSeen,totalJals,eta));
                }
            }

            Reference[] refs=inst.getReferencesFrom();
            if(refs.length==0) continue;
            Function parentFunc=funcManager.getFunctionContaining(inst.getAddress());
            Function targetFunc=funcManager.getFunctionAt(refs[0].getToAddress());
            if(parentFunc==null||targetFunc==null) continue;
            if(parentFunc.equals(targetFunc)) continue;

            // V13 Final: Deep thunk resolution (loop depth 3, visited guard)
            Function resolvedTarget=resolveThunkTarget(targetFunc);
            boolean wasResolved=!resolvedTarget.equals(targetFunc);

            if(isStaticLibraryFunction(parentFunc)||isStaticLibraryFunction(targetFunc)||(wasResolved&&isStaticLibraryFunction(resolvedTarget))){staticFirewallBlocked++;continue;}
            if(referencesIopModule(parentFunc)||referencesIopModule(targetFunc)||(wasResolved&&referencesIopModule(resolvedTarget))){iopFirewallBlocked++;continue;}
            if(isBehaviorallyDangerous(parentFunc)||isBehaviorallyDangerous(resolvedTarget)){behavFirewallBlocked++;continue;}
            if(isThunkFunction(parentFunc)){thunksSkipped++;continue;}

            FuncTraits target=getTraits(resolvedTarget);
            if(target.byteSize<8||(target.calledCount>15&&!target.usesCop1&&!target.usesCop2)) continue;
            FuncTraits parent=getTraits(parentFunc);

            Address parentEntry=parentFunc.getEntryPoint();
            int depth1=mainLoop1Tree.getOrDefault(parentEntry,-1);
            int depth2=mainLoop2Tree.getOrDefault(parentEntry,-1);
            int dangerDepth=calcDangerDepth(depth1,depth2);
            boolean inNexus=frameRateNexus.containsKey(parentEntry);

            ScoreBreakdown bd=calculateScore(parent,target,parentEntry,resolvedTarget.getEntryPoint(),dangerDepth);
            if(bd.isKilled){killedByZone++;continue;}

            boolean isPureMath=false;
            if((bd.category.equals("VECTORS")&&(target.isVu0||target.usesCop2)&&!target.writesToGlobal)||
               (target.accOps>=ACC_OPS_THRESHOLD&&!target.writesToGlobal)){
                bd.category="PURE_MATH_HOOKS"; isPureMath=true; pureMathKilled++;
            }

            // V13 Final: Dependency Bouncer — mark profile as risky, don't silently skip
            // Profile is created first so we can set the flag even if this is the only caller
            final String   finalCategory       = bd.category;
            final Function finalResolvedTarget  = resolvedTarget;
            final Function finalOriginalTarget  = targetFunc;
            final FuncTraits finalTarget        = target;

            Address originalTargetEntry = finalOriginalTarget.getEntryPoint();
            TargetProfile profile = targetProfiles.computeIfAbsent(originalTargetEntry, k -> {
                TargetProfile p=new TargetProfile();
                p.targetFunc=finalOriginalTarget; // Thunk address for surgical patching
                p.targetTraits=finalTarget;       // Real function's DNA
                if(finalTarget.usesSPR) p.sprTag="[SPR]";
                return p;
            });

            if(isReturnValueUsed(parentFunc,inst.getAddress())){
                dependencyBlocked++;
                profile.hasReturnDependency=true;
                continue; // Don't count this caller toward score
            }

            // Global Hook Points (central address for ASM hooks)
            long targetOffset=finalResolvedTarget.getEntryPoint().getOffset();
            if((targetOffset-PS2_BASE)>=0x040000L&&
               !isStaticLibraryFunction(finalResolvedTarget)&&
               !referencesIopModule(finalResolvedTarget)&&
               !finalCategory.equals("PURE_MATH_HOOKS")){
                globalHooks.computeIfAbsent(targetOffset, k->
                    finalResolvedTarget.getName()+" | "+finalCategory);
            }

            String effectiveCategory=finalCategory;
            int v12Bonus=0; List<String> v12Tags=new ArrayList<>();

            if(!isPureMath){
                if(detectEulerPattern(parentFunc,resolvedTarget,inst.getAddress())){
                    v12Bonus+=EULER_BONUS; v12Tags.add("Euler(+"+EULER_BONUS+")");
                    if(!bd.category.equals("VECTORS")&&!bd.category.equals("TIMERS")) effectiveCategory="VECTORS";
                } else if(detectKinematicPattern(parentFunc,resolvedTarget,inst.getAddress())){
                    v12Bonus+=KINEMATIC_BONUS; v12Tags.add("Kinematic(+"+KINEMATIC_BONUS+")");
                    effectiveCategory="VECTORS";
                }
                boolean isAnim=detectAnimationModifier(parentFunc,resolvedTarget,inst.getAddress());
                if(isAnim){
                    if(effectiveCategory.equals("UNKNOWN")||effectiveCategory.equals("VECTORS")){
                        bd.dnaScore=DNA_ANIMATION; effectiveCategory="ANIMATION_MODIFIERS";
                    }
                    boolean nexusAvail=!frameRateNexus.isEmpty();
                    if(nexusAvail&&inNexus){ v12Bonus+=ANIM_NEXUS_BONUS; v12Tags.add("AnimNexus(+"+ANIM_NEXUS_BONUS+")");}
                    else if(!nexusAvail){
                        if(parent.floatOps>ANIM_FPU_THRESHOLD&&parent.branchOps>ANIM_BRANCH_THRESHOLD){
                            v12Bonus+=ANIM_HEURISTIC_BONUS; v12Tags.add("AnimHeuristic(+"+ANIM_HEURISTIC_BONUS+")");}
                        else{isAnim=false;if(effectiveCategory.equals("ANIMATION_MODIFIERS")) effectiveCategory="UNKNOWN";}
                    } else { v12Bonus-=10; v12Tags.add("AnimOutsideNexus(-10)");}
                }
                if(parentWritesToGlobal(parentFunc,inst.getAddress())){
                    v12Bonus+=GLOBAL_WRITE_BONUS; v12Tags.add("GlobalWriter(+"+GLOBAL_WRITE_BONUS+")");
                    if(effectiveCategory.equals("UNKNOWN")){bd.dnaScore=DNA_STATE_MACHINE;effectiveCategory="STATE_MACHINES";}
                }
                if(parentWritesToEntityStruct(parentFunc,inst.getAddress())){
                    v12Bonus+=STRUCT_WRITE_BONUS; v12Tags.add("StructWriter(+"+STRUCT_WRITE_BONUS+")");
                    if(!effectiveCategory.equals("VECTORS")&&!effectiveCategory.equals("TIMERS")) effectiveCategory="VECTORS";
                }
                // Side-Effect Gate: STATE_MACHINES/ANIM_TICKERS without mutations are suspect
                if((effectiveCategory.equals("STATE_MACHINES")||effectiveCategory.equals("ANIM_TICKERS"))
                   &&!target.hasMutatingInstructions){
                    v12Tags.add("RISK:NoMutation");
                    v12Bonus-=10;
                }
                // Stack Frame check
                if(!target.hasStackFrame&&(effectiveCategory.equals("STATE_MACHINES")||effectiveCategory.equals("ANIM_TICKERS"))){
                    v12Tags.add("RISK:NoStackFrame");
                    v12Bonus-=5;
                }
            }

            String hierarchy=calcHierarchyType(parentFunc);
            if(hierarchy.equals("SINGLETON")){v12Bonus+=SINGLETON_BONUS;v12Tags.add("Singleton(+"+SINGLETON_BONUS+")");}
            else if(hierarchy.equals("BATCH")){v12Bonus+=BATCH_PENALTY;v12Tags.add("Batch("+BATCH_PENALTY+")");}

            if(target.usesSPR){v12Bonus+=SPR_BONUS;v12Tags.add("SPR(+"+SPR_BONUS+")");}
            if(target.quadwordVU>=2){v12Bonus+=QVU_BONUS;v12Tags.add("QuadVU(+"+QVU_BONUS+")");
                if(!isPureMath&&effectiveCategory.equals("UNKNOWN")) effectiveCategory="VECTORS";}

            // V13 Final: Reverse Depth BonusZone (per-category depth expectation)
            if(effectiveCategory.equals("MACRO_SCRIPTS")&&dangerDepth!=-1&&dangerDepth<=2){
                v12Bonus+=DEPTH_BONUS_MACRO; v12Tags.add("MacroDepthBonus(+"+DEPTH_BONUS_MACRO+")");}
            if(effectiveCategory.equals("ANIM_TICKERS")&&dangerDepth!=-1&&dangerDepth<=1){
                v12Bonus+=DEPTH_PENALTY_ANIM_SHALLOW; v12Tags.add("AnimTooShallow("+DEPTH_PENALTY_ANIM_SHALLOW+")");}

            // Multiple Return Path Risk
            if(target.returnPaths>=3) v12Tags.add("RISK:MultiReturn("+target.returnPaths+")");

            // Orphan Kill: still UNKNOWN after all modules
            if(dangerDepth==-1&&effectiveCategory.equals("UNKNOWN")){killedByZone++;continue;}

            int finalPerJal=bd.total()+v12Bonus;
            if(finalPerJal<SCORE_THRESHOLD&&!isPureMath) continue;

            if(wasResolved&&!isPureMath){
                v12Tags.add("ProxyFor:"+effectiveCategory);
                effectiveCategory="THUNKS";
            }

            processed++;

            ParentContext ctx=new ParentContext();
            ctx.parent=parentFunc; ctx.jalAddr=inst.getAddress();
            ctx.parentTraits=parent; ctx.depthInTree=dangerDepth; ctx.inNexus=inNexus;
            ctx.baseScore=bd.total(); ctx.baseCategory=effectiveCategory;
            ctx.v12Bonus=v12Bonus; ctx.v12Tags=v12Tags;
            ctx.hierarchy=hierarchy; ctx.wasResolved=wasResolved; ctx.resolvedTarget=resolvedTarget;
            // Fix: Deduplicate callers by parent entry address.
            // Loop-unrolled code can emit 10-15 JALs to the same target from the same parent,
            // inflating totalCallers and triggering CALLER_PENALTY on legitimate targets.
            // Keep only the JAL with the highest tactical score per unique parent function.
            boolean parentExists=false;
            for(ParentContext existing:profile.callers){
                if(existing.parent.getEntryPoint().equals(ctx.parent.getEntryPoint())){
                    parentExists=true;
                    if(ctx.baseScore+ctx.v12Bonus>existing.baseScore+existing.v12Bonus){
                        existing.jalAddr=ctx.jalAddr; existing.depthInTree=ctx.depthInTree;
                        existing.inNexus=ctx.inNexus; existing.baseScore=ctx.baseScore;
                        existing.baseCategory=ctx.baseCategory; existing.v12Bonus=ctx.v12Bonus;
                        existing.v12Tags=ctx.v12Tags; existing.hierarchy=ctx.hierarchy;
                    }
                    break;
                }
            }
            if(!parentExists) profile.callers.add(ctx);
        }

        long scanSec=(System.currentTimeMillis()-scanStart)/1000;
        println(String.format("\n[PASS 1] Done. %d JALs in %dm%02ds → %d unique targets.",
            jalsSeen,scanSec/60,scanSec%60,targetProfiles.size()));

        // V13 Final: Clear HighFunction cache to reclaim memory before Pass 2
        int hfCacheSize=highFuncCache.size();
        highFuncCache.clear();
        println("[MEMORY] Cleared highFuncCache ("+hfCacheSize+" entries freed).");

        // =========================================================
        // PASS 2: FULL BINARY SCAN (vtable / jalr candidates)
        // V13 Final: suppressHFCache=true to prevent OOM during full-binary scan
        // =========================================================
        println("[PASS 2] Scanning all functions for vtable candidates (no HF cache)...");
        suppressHFCache=true;
        FunctionIterator allFuncs=funcManager.getFunctions(true);
        while(allFuncs.hasNext()&&!monitor.isCancelled()){
            Function func=allFuncs.next();
            Address addr=func.getEntryPoint();
            if(targetProfiles.containsKey(addr)) continue;
            if(isStaticLibraryFunction(func)||isBehaviorallyDangerous(func)||
               referencesIopModule(func)||isThunkFunction(func)) continue;
            FuncTraits traits=getTraits(func);
            if(traits.byteSize<8) continue;
            int standalone=computeStandaloneScore(traits,addr);
            String cat=assignCategoryFromTraits(traits);
            if(standalone<=0||cat.equals("UNKNOWN")) continue;
            TargetProfile p=new TargetProfile();
            p.targetFunc=func; p.targetTraits=traits; p.isVtableHook=true;
            p.assignedCategory=cat; p.finalScore=standalone;
            if(traits.usesSPR) p.sprTag="[SPR]";
            String ln=func.getName().toLowerCase();
            for(String kw:ANIM_KEYWORDS) if(ln.contains(kw)){p.finalScore+=10;break;}
            if(p.finalScore>=SCORE_THRESHOLD){targetProfiles.put(addr,p);vtableFound++;}
        }
        suppressHFCache=false;
        println("[PASS 2] Complete. "+vtableFound+" vtable candidates.\n");

        // Vtable Cluster Synergy: adjacent vtable candidates of same category get a bonus
        applyVtableClusterSynergy();

        // V13.2: VTABLE SAFETY SCORING
        // Applies Blast Radius / Callee analysis ONLY to isVtableHook=true targets (PASS 2).
        // PASS 1 targets use Local NOPs (surgical per-JAL), which are inherently safe —
        // safety penalties would wrongly discard heavyweight animation managers we want.
        applyVtableSafetyScoring();

        // =========================================================
        // ANALYSIS: Aggregate, score, filter
        // =========================================================
        println("Analyzing and scoring target profiles...");
        List<TargetProfile> worthyTargets=new ArrayList<>();

        for(TargetProfile profile:targetProfiles.values()){
            if(monitor.isCancelled()) break;
            if(profile.isVtableHook){if(profile.finalScore>=SCORE_THRESHOLD) worthyTargets.add(profile);continue;}
            if(profile.callers.isEmpty()) continue; // no valid callers (all were dependency-blocked)

            String assignedCat=profile.callers.get(0).baseCategory;
            // Per-category caller ceiling
            int maxCallers=getMaxCallers(assignedCat);
            if(profile.callers.size()>maxCallers){utilityDropped++;continue;}

            profile.totalCallers=profile.callers.size();
            double sumSize=0,sumFPU=0; int bestTotal=0; ParentContext bestCtx=null;
            for(ParentContext ctx:profile.callers){
                sumSize+=ctx.parentTraits.byteSize; sumFPU+=ctx.parentTraits.floatOps;
                if(ctx.depthInTree>profile.deepestDepth) profile.deepestDepth=ctx.depthInTree;
                if(ctx.depthInTree!=-1&&ctx.depthInTree<profile.shallowestDepth) profile.shallowestDepth=ctx.depthInTree;
                if(ctx.inNexus) profile.anyInNexus=true;
                int t=ctx.baseScore+ctx.v12Bonus;
                if(t>bestTotal){bestTotal=t;bestCtx=ctx;}
            }
            profile.avgParentSize=sumSize/profile.totalCallers;
            profile.avgParentFPU=sumFPU/profile.totalCallers;
            profile.maxScore=bestTotal;
            if(bestCtx!=null){profile.assignedCategory=bestCtx.baseCategory;profile.bestTags=bestCtx.v12Tags;}

            // Per-category caller penalty
            int penalty=getCallerPenalty(profile.assignedCategory);
            profile.finalScore=profile.maxScore-(profile.totalCallers*penalty);

            // ANIM_TICKERS fallback
            if(profile.assignedCategory.equals("UNKNOWN")&&hasAnimTickerDNA(profile.targetTraits)){
                profile.assignedCategory="ANIM_TICKERS"; profile.finalScore+=DNA_ANIM_TICKER;}

            if(profile.finalScore>=SCORE_THRESHOLD&&
               !profile.assignedCategory.equals("UNKNOWN")&&
               !profile.assignedCategory.equals("PURE_MATH_HOOKS"))
                worthyTargets.add(profile);
        }

        // V13 Final: Cross-Category Parent Context Bonus (post-analysis, uses known categories)
        applyContextBonuses(worthyTargets);

        println("Found "+worthyTargets.size()+" hook-worthy targets.\n");

        // Thunk dedup: remove thunks whose resolved target is already in worthyTargets
        Set<Address> realCaptured=new HashSet<>();
        for(TargetProfile p:worthyTargets)
            if(!p.assignedCategory.equals("THUNKS")) realCaptured.add(p.targetFunc.getEntryPoint());
        List<TargetProfile> thunkTargets=new ArrayList<>();
        worthyTargets.removeIf(p->{
            if(!p.assignedCategory.equals("THUNKS")) return false;
            for(ParentContext ctx:p.callers)
                if(ctx.wasResolved&&realCaptured.contains(ctx.resolvedTarget.getEntryPoint())) return true;
            thunkTargets.add(p); return true;
        });

        Comparator<TargetProfile> profileSort=(a,b)->{
            if(a.totalCallers!=b.totalCallers) return Integer.compare(a.totalCallers,b.totalCallers);
            return Integer.compare(b.finalScore,a.finalScore);
        };
        worthyTargets.sort(profileSort);
        thunkTargets.sort(profileSort);

        // 60FPS Stride Hunter (passive scan)
        List<StrideCandidate> strideCandidates=find60FpsStrideCandidates(loopCandidates,mainLoop1Addr,mainLoop2Addr);

        decomp.dispose();

        println("[*] Final Statistics:");
        println("    JALs scanned               : "+jalsSeen);
        println("    Unique targets (JAL)        : "+(targetProfiles.size()-vtableFound));
        println("    Vtable candidates           : "+vtableFound);
        println("    Static Firewall blocked     : "+staticFirewallBlocked);
        println("    IOP Firewall blocked        : "+iopFirewallBlocked);
        println("    Behavioral Firewall blocked : "+behavFirewallBlocked);
        println("    Dependency Bouncer blocked  : "+dependencyBlocked);
        println("    KillZone eliminated         : "+killedByZone);
        println("    Pure Math Guard killed      : "+pureMathKilled);
        println("    Utility dropped             : "+utilityDropped);
        println("    Thunks skipped (parent)     : "+thunksSkipped);
        println("    Hook-worthy (main)          : "+worthyTargets.size());
        println("    Thunk hooks (separate)      : "+thunkTargets.size());
        println("    Global Hook Points          : "+globalHooks.size());
        println("    60FPS Stride candidates     : "+strideCandidates.size());

        if(!strideCandidates.isEmpty()){
            println("\n[60FPS HUNTER] Candidates:");
            for(StrideCandidate sc:strideCandidates)
                println("  "+String.format("%08X",sc.addr.getOffset())+" // "+sc.funcName+" | "+sc.description);
        }

        String basePath=outputFile.getParent();
        String baseName=outputFile.getName().replaceFirst("\\..*$","");
        File hooksFile=new File(basePath,baseName+"_global_hooks.txt");
        File thunksFile=new File(basePath,baseName+"_thunks.txt");

        writePnach(outputFile,worthyTargets,mainLoop1Addr,mainLoop2Addr,nexusInput,strideCandidates);
        writeGlobalHooks(hooksFile);
        writeThunksFile(thunksFile,thunkTargets);
        if(doTracerBullets) writeTracerBullets(outputFile,worthyTargets);
        println("\n[SUCCESS] Main    : "+outputFile.getAbsolutePath());
        println("[SUCCESS] Hooks   : "+hooksFile.getAbsolutePath());
        println("[SUCCESS] Thunks  : "+thunksFile.getAbsolutePath());
    }

    // =========================================================
    // 60FPS STRIDE HUNTER (Passive Scanner)
    // Scans MainLoop candidate functions for integer stride (1 or 2)
    // and float delta (1/30, 1/60) instructions without generating hooks.
    // =========================================================
    private List<StrideCandidate> find60FpsStrideCandidates(
            List<MainLoopCandidate> topo, Address loop1, Address loop2) {
        List<StrideCandidate> results=new ArrayList<>();
        Set<Address> scanTargets=new HashSet<>();
        // Scan top topology candidates + known mainloops
        for(int i=0;i<Math.min(5,topo.size());i++) scanTargets.add(topo.get(i).addr);
        if(loop1!=null) scanTargets.add(loop1);
        if(loop2!=null) scanTargets.add(loop2);

        for(Address root:scanTargets){
            Function func=funcManager.getFunctionAt(root);
            if(func==null) continue;
            InstructionIterator it=currentProgram.getListing().getInstructions(func.getBody(),true);
            while(it.hasNext()&&!monitor.isCancelled()){
                Instruction inst=it.next();
                String mnem=inst.getMnemonicString();
                if(mnem==null) continue;
                String ml=mnem.toLowerCase();

                // Integer stride — FIX: require zero-register base to avoid false positives
                // from loop counters (addiu v0,v0,1). A real VSync stride is loaded as an
                // absolute constant: addiu a1,zero,2 or the pseudo-op 'li a1,2'.
                // Also supports negative countdown timers (-1, -2).
                if(ml.equals("li")||ml.equals("addiu")||ml.equals("ori")){
                    boolean hasZeroBase=ml.equals("li"); // li is inherently based on zero
                    if(!hasZeroBase){
                        for(Object op:inst.getInputObjects())
                            if(op instanceof ghidra.program.model.lang.Register&&
                               ((ghidra.program.model.lang.Register)op).getName().equalsIgnoreCase("zero")){
                                hasZeroBase=true; break;}
                    }
                    if(hasZeroBase){
                        for(Object op:inst.getInputObjects()){
                            if(op instanceof ghidra.program.model.scalar.Scalar){
                                long val=((ghidra.program.model.scalar.Scalar)op).getValue();
                                if(val==1||val==2||val==0xFFFFFFFFL||val==0xFFFFFFFEL){
                                    String desc=Math.abs((int)val)==2?
                                        "30FPS stride, halve for 60FPS":"Already 60FPS stride";
                                    results.add(new StrideCandidate(inst.getAddress(),func.getName(),
                                        mnem+" val="+val+" ("+desc+")"));
                                }
                            }
                        }
                    }
                }

                // Float delta: lwc1 loading a float constant (1/30 or 1/60)
                if(ml.equals("lwc1")){
                    for(Reference ref:inst.getReferencesFrom()){
                        try{
                            Address dataAddr=ref.getToAddress();
                            byte[] bytes=new byte[4];
                            int read=memory.getBytes(dataAddr,bytes);
                            if(read<4) continue;
                            int bits=ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getInt();
                            float val=Float.intBitsToFloat(bits);
                            if(Math.abs(val-DELTA_30FPS)<DELTA_EPSILON)
                                results.add(new StrideCandidate(inst.getAddress(),func.getName(),
                                    String.format("lwc1 float=%.5f (≈1/30 delta, change to 0.01666f for 60FPS)",val)));
                            else if(Math.abs(val-DELTA_60FPS)<DELTA_EPSILON)
                                results.add(new StrideCandidate(inst.getAddress(),func.getName(),
                                    String.format("lwc1 float=%.5f (≈1/60 delta, already 60FPS speed)",val)));
                        } catch(Exception ignored){}
                    }
                }
            }
        }
        return results;
    }

    // =========================================================
    // V16: TOPOLOGY-BASED MAINLOOP DETECTION
    // =========================================================
    private List<MainLoopCandidate> findMainLoopCandidates() throws Exception {
        Map<Address,Double> topoScores=new HashMap<>();
        Map<Address,Set<String>> anchorMap=new HashMap<>();
        BasicBlockModel blockModel=new BasicBlockModel(currentProgram);
        Map<Address,String> anchorAddrs=new HashMap<>();
        for(String name:MAINLOOP_ANCHORS){SymbolIterator syms=symbolTable.getSymbols(name);while(syms.hasNext()) anchorAddrs.put(syms.next().getAddress(),name);}
        List<Function> candidates=new ArrayList<>();
        for(Function func:funcManager.getFunctions(true)){
            if(monitor.isCancelled()) break;
            if(func.isThunk()||func.getBody().getNumAddresses()<50) continue;
            candidates.add(func);
        }
        for(Function func:candidates){
            if(monitor.isCancelled()) break;
            long instCount=0;
            InstructionIterator it=currentProgram.getListing().getInstructions(func.getBody(),true);
            while(it.hasNext()){it.next();instCount++;}
            if(instCount<100) continue;
            Set<Function> callees=func.getCalledFunctions(monitor);
            int callCount=callees.size();
            int backEdges=0;
            CodeBlockIterator blocks=blockModel.getCodeBlocksContaining(func.getBody(),monitor);
            while(blocks.hasNext()){
                CodeBlock block=blocks.next();
                CodeBlockReferenceIterator dests=block.getDestinations(monitor);
                while(dests.hasNext()){
                    CodeBlockReference ref=dests.next();
                    if(ref.getDestinationAddress().compareTo(block.getFirstStartAddress())<=0&&
                       func.getBody().contains(ref.getDestinationAddress())) backEdges++;
                }
            }
            if(backEdges==0) continue;
            Set<String> hits=new HashSet<>();
            boolean hasBegin=false,hasEnd=false;
            for(Function callee:callees){
                String cn=callee.getName().toLowerCase();
                if(cn.contains("beginframe")||cn.contains("gssetsync")) hasBegin=true;
                if(cn.contains("endframe")||cn.contains("gssyncv")) hasEnd=true;
                if(anchorAddrs.containsKey(callee.getEntryPoint())) hits.add(anchorAddrs.get(callee.getEntryPoint()));
                for(Function gc:callee.getCalledFunctions(monitor))
                    if(anchorAddrs.containsKey(gc.getEntryPoint())) hits.add(anchorAddrs.get(gc.getEntryPoint()));
            }
            double score=(instCount*0.1)+(callCount*2.5)+(backEdges*10.0);
            if(hasBegin&&hasEnd){score*=2.0;hits.add("HEARTBEAT");}
            for(Function other:candidates) if(!other.equals(func)&&callees.contains(other)){score+=1000.0;break;}
            if(hits.isEmpty()) score*=0.05; else if(hits.size()>=2) score*=1.5;
            topoScores.put(func.getEntryPoint(),score);
            anchorMap.put(func.getEntryPoint(),hits);
        }
        List<MainLoopCandidate> results=new ArrayList<>();
        for(Address addr:topoScores.keySet()){
            Function f=funcManager.getFunctionAt(addr);
            MainLoopCandidate c=new MainLoopCandidate(addr,f!=null?f.getName():"?",anchorMap.get(addr));
            c.score=topoScores.get(addr).intValue(); results.add(c);
        }
        results.sort((a,b)->Integer.compare(b.score,a.score));
        return results;
    }

    // =========================================================
    // V13.2: VTABLE SAFETY SCORING
    // Evaluates the "Blast Radius" of placing jr ra on each PASS 2 vtable candidate.
    // Uses PASS 1 targetProfiles for O(1) callee lookups instead of O(n²) graph traversal.
    // Rules:
    //   Danger penalties: byteSize (in addresses), branchOps, static lib callees, utility callees
    //   Safety bonuses:   high leaf ratio, callees in safe categories (ANIM_TICKERS/VECTORS)
    //   Caps: dangerPenalty ≤ 70, safetyBonus ≤ 35  (prevent outlier distortion)
    // =========================================================
    private void applyVtableSafetyScoring() {
        for(TargetProfile profile : targetProfiles.values()) {
            if(!profile.isVtableHook) continue;
            FuncTraits t = profile.targetTraits;

            int dangerPenalty = 0;
            int safetyBonus   = 0;
            List<String> safetyTags = new ArrayList<>();

            // --- Blast Radius (byteSize in Addresses; MIPS: 1 addr = 4 bytes) ---
            // 375 addrs ≈ 1500 bytes, 200 addrs ≈ 800 bytes, 100 addrs ≈ 400 bytes
            if(t.byteSize > 375)      { dangerPenalty += 40; safetyTags.add("Danger:Huge"); }
            else if(t.byteSize > 200) { dangerPenalty += 20; safetyTags.add("Danger:Large"); }
            else if(t.byteSize > 100) { dangerPenalty += 10; safetyTags.add("Danger:Medium"); }

            // --- Complexity (branch ops) ---
            if(t.branchOps > 15)     { dangerPenalty += 15; safetyTags.add("Danger:HighBranch"); }
            else if(t.branchOps > 8) { dangerPenalty +=  5; }

            // --- Callee analysis using cache (O(1)) and targetProfiles (PASS 1 data) ---
            Set<Function> rawCallees = profile.targetFunc.getCalledFunctions(monitor);
            int totalCallees = rawCallees.size();
            int leafCallees  = 0;

            for(Function rawCallee : rawCallees) {
                if(monitor.isCancelled()) break;

                // Resolve thunks so we evaluate the real destination
                Function callee    = resolveThunkTarget(rawCallee);
                Address calleeAddr = callee.getEntryPoint();

                // Static Library / IOP Penalty — calling malloc/sceCd = system manager
                if(isStaticLibraryFunction(callee) || referencesIopModule(callee)) {
                    dangerPenalty += 30;
                    safetyTags.add("Danger:SysLib");
                    continue; // no further analysis needed for this callee
                }

                // Leaf node check via cache (avoids extra getCalledFunctions calls)
                FuncTraits calleeTrait = cache.get(calleeAddr);
                if(calleeTrait != null && calleeTrait.calledCount == 0) leafCallees++;

                // PASS 1 context lookup
                TargetProfile calleeProfile = targetProfiles.get(calleeAddr);
                if(calleeProfile != null) {
                    // Gish 1: Utility callee — high fan-in = risky dependency
                    if(calleeProfile.totalCallers > 8) {
                        dangerPenalty += 20;
                        safetyTags.add("Danger:UtilityCallee");
                    }
                    // Gish 2: Safe domain propagation
                    String cCat = calleeProfile.assignedCategory;
                    if(cCat.equals("VECTORS") || cCat.equals("ANIM_TICKERS")) {
                        safetyBonus += 15;
                        safetyTags.add("Safe:GoodDomain");
                    }
                }
            }

            // Weighted Leaf Ratio (gish 4) — more leaf callees = safer to stub
            if(totalCallees > 0) {
                float ratio = (float) leafCallees / totalCallees;
                // min(leafCallees,10) rewards absolute volume of safe work, not just ratio
                safetyBonus += (int)(ratio * 15) + Math.min(leafCallees, 10);
                if(ratio >= 0.8f) safetyTags.add("Safe:LeafHeavy");
            }

            // Apply caps to prevent outlier distortion
            dangerPenalty = Math.min(dangerPenalty, 70);
            safetyBonus   = Math.min(safetyBonus,   35);

            // Adjust finalScore and tag for visibility in output
            int net = safetyBonus - dangerPenalty;
            profile.finalScore += net;
            if(net > 0)       profile.bestTags.add("VtableSafe(+"  + net + ")");
            else if(net < 0)  profile.bestTags.add("VtableDanger(" + net + ")");
        }
    }

    // =========================================================
    // VTABLE CLUSTER SYNERGY
    // =========================================================
    private void applyVtableClusterSynergy() {
        List<TargetProfile> vtables=new ArrayList<>();
        for(TargetProfile p:targetProfiles.values()) if(p.isVtableHook) vtables.add(p);
        vtables.sort((a,b)->Long.compare(a.targetFunc.getEntryPoint().getOffset(),
                                         b.targetFunc.getEntryPoint().getOffset()));
        for(int i=0;i<vtables.size()-1;i++){
            TargetProfile a=vtables.get(i), b=vtables.get(i+1);
            long gap=b.targetFunc.getEntryPoint().getOffset()-a.targetFunc.getEntryPoint().getOffset();
            if(gap<0x1000&&a.assignedCategory.equals(b.assignedCategory)){
                a.finalScore+=CLUSTER_BONUS; b.finalScore+=CLUSTER_BONUS;
                if(!a.bestTags.contains("Cluster")) a.bestTags.add("Cluster(+"+CLUSTER_BONUS+")");
                if(!b.bestTags.contains("Cluster")) b.bestTags.add("Cluster(+"+CLUSTER_BONUS+")");
            }
        }
    }

    // =========================================================
    // CROSS-CATEGORY CONTEXT BONUS
    // =========================================================
    private void applyContextBonuses(List<TargetProfile> targets) {
        Set<Address> strongTargets=new HashSet<>();
        for(TargetProfile p:targets)
            if(isStrongCategory(p.assignedCategory)) strongTargets.add(p.targetFunc.getEntryPoint());

        for(TargetProfile profile:targets){
            if(profile.contextBonusApplied) continue;
            outer:
            for(ParentContext ctx:profile.callers){
                List<long[]> jalList=parentJalListCache.get(ctx.parent.getEntryPoint());
                if(jalList==null) continue;
                long jalOff=ctx.jalAddr.getOffset();
                int myIdx=-1;
                for(int i=0;i<jalList.size();i++) if(jalList.get(i)[0]==jalOff){myIdx=i;break;}
                if(myIdx<0) continue;
                int lo=Math.max(0,myIdx-5),hi=Math.min(jalList.size(),myIdx+6);
                for(int i=lo;i<hi;i++){
                    if(i==myIdx) continue;
                    Address neighborAddr=toAddr(jalList.get(i)[1]);
                    if(strongTargets.contains(neighborAddr)){
                        profile.finalScore+=CONTEXT_BONUS;
                        profile.bestTags.add("ContextBonus(+"+CONTEXT_BONUS+")");
                        profile.contextBonusApplied=true;
                        break outer;
                    }
                }
            }
        }
    }

    private boolean isStrongCategory(String cat){
        return cat.equals("TIMERS")||cat.equals("VECTORS")||
               cat.equals("STATE_MACHINES")||cat.equals("ANIM_TICKERS");
    }

    // =========================================================
    // FIREWALLS
    // =========================================================
    private boolean isStaticLibraryFunction(Function func){
        Address key=func.getEntryPoint();
        Boolean cached=staticFwCache.get(key); if(cached!=null) return cached;
        String name=func.getName(), lowerName=name.toLowerCase();
        if(name.startsWith("sceVu0")){staticFwCache.put(key,false);return false;}
        for(String p:STATIC_FIREWALL_PREFIXES) if(name.startsWith(p)){staticFwCache.put(key,true);return true;}
        for(String p:BIOS_FIREWALL_PREFIXES)   if(name.startsWith(p)){staticFwCache.put(key,true);return true;}
        for(String kw:DANGEROUS_KEYWORDS)       if(lowerName.contains(kw)){staticFwCache.put(key,true);return true;}
        staticFwCache.put(key,false); return false;
    }

    private boolean referencesIopModule(Function func){
        Address key=func.getEntryPoint();
        Boolean cached=iopFwCache.get(key); if(cached!=null) return cached;
        InstructionIterator it=currentProgram.getListing().getInstructions(func.getBody(),true);
        while(it.hasNext()){
            for(Reference ref:it.next().getReferencesFrom()){
                Data data=getDataAt(ref.getToAddress());
                if(data!=null&&data.hasStringValue()){
                    String str=data.getDefaultValueRepresentation();
                    for(String s:IOP_MODULE_STRINGS) if(str.contains(s)){iopFwCache.put(key,true);return true;}
                }
            }
        }
        iopFwCache.put(key,false); return false;
    }

    private boolean isBehaviorallyDangerous(Function func){
        Address key=func.getEntryPoint();
        Boolean cached=behavFwCache.get(key); if(cached!=null) return cached;
        boolean d=containsSyscall(func)||accessesHardware(func)||containsCOP0(func)||hasSystemStrings(func);
        behavFwCache.put(key,d); return d;
    }

    private boolean containsSyscall(Function func){
        InstructionIterator it=currentProgram.getListing().getInstructions(func.getBody(),true);
        while(it.hasNext()){String m=it.next().getMnemonicString();if(m!=null&&m.equalsIgnoreCase("syscall")) return true;}
        return false;
    }

    private boolean accessesHardware(Function func){
        for(Address addr:func.getBody().getAddresses(true)){
            for(Reference ref:refManager.getReferencesFrom(addr)){
                long off=ref.getToAddress().getOffset();
                if((off>=MMIO_START&&off<=MMIO_END)||(off>=GS_PRIV_START&&off<=GS_PRIV_END)||off>=KSEG1_START) return true;
            }
        }
        return false;
    }

    private boolean containsCOP0(Function func){
        InstructionIterator it=currentProgram.getListing().getInstructions(func.getBody(),true);
        while(it.hasNext()){
            String m=it.next().getMnemonicString();
            if(m==null) continue; m=m.toLowerCase();
            if(m.equals("di")||m.equals("ei")||m.equals("mfc0")||m.equals("mtc0")||
               m.equals("eret")||m.startsWith("c0")) return true;
        }
        return false;
    }

    private boolean hasSystemStrings(Function func){
        for(Address addr:func.getBody().getAddresses(true)){
            for(Reference ref:refManager.getReferencesFrom(addr)){
                Data data=getDataAt(ref.getToAddress());
                if(data!=null&&data.hasStringValue()){
                    String str=data.getDefaultValueRepresentation().toLowerCase();
                    if(str.contains("error")||str.contains("assert")||str.contains("debug")||
                       str.contains("panic")||str.contains("bios")||
                       str.contains("kernel")) return true;
                    // SCE SDK match: "sce" followed by uppercase (sceGs, scePad, etc.)
                    // Avoids false positives on "scene", "ascend", "crescent", etc.
                    if(str.matches("(?i).*\\bsce[A-Z].*")) return true;
                }
            }
        }
        return false;
    }

    // =========================================================
    // DEPENDENCY BOUNCER
    // =========================================================
    private boolean isReturnValueUsed(Function parentFunc, Address jalAddr){
        Address parentEntry=parentFunc.getEntryPoint();
        HighFunction highFunc=highFuncCache.get(parentEntry);
        if(highFunc==null){
            DecompileResults res=decomp.decompileFunction(parentFunc,15,monitor);
            highFunc=res.getHighFunction();
            if(highFunc!=null&&!suppressHFCache) highFuncCache.put(parentEntry,highFunc);
        }
        if(highFunc!=null){
            Iterator<PcodeOpAST> ops=highFunc.getPcodeOps(jalAddr);
            while(ops.hasNext()){
                PcodeOpAST op=ops.next();
                if(op.getOpcode()==PcodeOp.CALL){Varnode out=op.getOutput();if(out!=null&&out.getDescendants().hasNext()) return true;}
            }
        }
        try{
            Address scanFrom=jalAddr.add(8);
            Instruction cur=getInstructionAt(scanFrom);
            if(cur==null) cur=getInstructionAfter(scanFrom);
            boolean v0w=false,v1w=false,f0w=false; int checked=0;
            while(cur!=null&&checked<5){
                if(!parentFunc.getBody().contains(cur.getAddress())) break;

                // ABI Clobber Guard — jal/jalr/bal all clobber $ra and invoke a subroutine
                String curMnem=cur.getMnemonicString();
                if(curMnem!=null&&(curMnem.equals("jal")||curMnem.equals("jalr")||
                   curMnem.equals("bal")||curMnem.startsWith("bgezal"))) break;

                // Branch Delay Slot Guard: branches in MIPS always execute the next instruction
                // (the delay slot) before taking the jump. If v0 is read inside that delay slot
                // we must catch it even if it's the 6th instruction in our window.
                boolean isBranch=(curMnem!=null&&(curMnem.startsWith("b")||curMnem.equals("j")));

                // Double delay slot guard: if this instruction IS inside another branch's
                // delay slot (aggressive O3 optimization), control flow is too complex to
                // track linearly — bail out conservatively.
                if(checked>0&&isBranch){
                    Instruction prev=getInstructionBefore(cur.getAddress());
                    if(prev!=null){
                        String pm=prev.getMnemonicString();
                        if(pm!=null&&(pm.startsWith("b")||pm.equals("j")||pm.equals("jal")||pm.equals("jalr")))
                            break; // nested branch in delay slot — abort scan
                    }
                }

                for(Object obj:cur.getInputObjects()){
                    if(!(obj instanceof ghidra.program.model.lang.Register)) continue;
                    String rn=((ghidra.program.model.lang.Register)obj).getName().toLowerCase();
                    if(rn.equals("v0")&&!v0w) return true;
                    if(rn.equals("v1")&&!v1w) return true;
                    if(rn.equals("f0")&&!f0w) return true;
                }
                for(Object obj:cur.getResultObjects()){
                    if(!(obj instanceof ghidra.program.model.lang.Register)) continue;
                    String rn=((ghidra.program.model.lang.Register)obj).getName().toLowerCase();
                    if(rn.equals("v0")) v0w=true;
                    if(rn.equals("v1")) v1w=true;
                    if(rn.equals("f0")) f0w=true;
                }

                if(isBranch){
                    // Force-check the delay slot (always executes before the branch takes effect)
                    Instruction ds=getInstructionAfter(cur.getAddress());
                    if(ds!=null&&parentFunc.getBody().contains(ds.getAddress())){
                        for(Object obj:ds.getInputObjects()){
                            if(!(obj instanceof ghidra.program.model.lang.Register)) continue;
                            String rn=((ghidra.program.model.lang.Register)obj).getName().toLowerCase();
                            if(rn.equals("v0")&&!v0w) return true;
                            if(rn.equals("v1")&&!v1w) return true;
                            if(rn.equals("f0")&&!f0w) return true;
                        }
                    }
                    // After branch+delay slot, control flow diverges — too complex to track statically
                    break;
                }

                cur=getInstructionAfter(cur.getAddress()); checked++;
            }
        } catch(Exception ignored){}
        return false;
    }

    // =========================================================
    // THUNK RESOLVER — V13 Final: loop with depth 3 + visited guard
    // Handles single AND double thunks (virtual inheritance patterns)
    // =========================================================
    private Function resolveThunkTarget(Function func){
        Set<Address> visited=new HashSet<>();
        Function current=func;
        for(int depth=0;depth<3;depth++){
            Address entry=current.getEntryPoint();
            if(!visited.add(entry)) break;
            InstructionIterator iter=currentProgram.getListing().getInstructions(current.getBody(),true);
            int checked=0; boolean found=false;
            while(iter.hasNext()&&checked<10){
                Instruction inst=iter.next(); checked++;
                String mnem=inst.getMnemonicString();
                if(mnem==null) continue;
                if(mnem.equals("jal")||mnem.equals("jalr")) break; // real function, stop
                if(mnem.equals("j")){
                    Reference[] refs=inst.getReferencesFrom();
                    if(refs.length==0) break;
                    Function resolved=funcManager.getFunctionAt(refs[0].getToAddress());
                    if(resolved!=null&&!resolved.equals(current)){current=resolved;found=true;break;}
                }
            }
            if(!found) break;
        }
        return current;
    }

    // =========================================================
    // SCORING
    // =========================================================
    private ScoreBreakdown calculateScore(FuncTraits parent, FuncTraits target,
                                          Address parentAddr, Address targetAddr, int dangerDepth){
        ScoreBreakdown bd=new ScoreBreakdown();
        // V13.2: A function with heavy FPU/VU0 that ALSO calls other functions is an
        // animation/physics manager, not pure math. Pure math never calls; it only computes.
        boolean targetCallsOthers = (target.calledCount > 0 || target.callOps > 0);

        if(target.isVu0||target.usesCop2){
            if(targetCallsOthers){
                bd.category="ANIM_TICKERS";bd.dnaScore=DNA_ANIM_TICKER;bd.reasons.add("VU0/COP2+Calls");
            } else if(parent.hasFrameCounterPattern){
                bd.category="TIMERS";bd.dnaScore=DNA_TIMER_PATTERN;bd.reasons.add("TimerPattern");
            } else {
                bd.category="VECTORS";bd.dnaScore=DNA_VU0;bd.reasons.add("VU0/COP2");
            }
        } else if(target.floatOps>=6||target.usesCop1){
            if(targetCallsOthers){
                bd.category="ANIM_TICKERS";bd.dnaScore=DNA_ANIM_TICKER;bd.reasons.add("HeavyFPU+Calls");
            } else {
                bd.category="VECTORS";bd.dnaScore=DNA_HEAVY_FPU;bd.reasons.add("HeavyFPU/COP1");
            }
        } else if(parent.hasFrameCounterPattern){
            bd.category="TIMERS";bd.dnaScore=DNA_TIMER_PATTERN;bd.reasons.add("FrameCounter");
        } else if(parent.floatOps>=FPU_THRESHOLD&&target.branchOps<=1&&target.byteSize<=100){
            bd.category="VECTORS";bd.dnaScore=DNA_HEAVY_FPU;bd.reasons.add("FPUParent+VecTarget");
        } else if(target.branchOps>=8&&target.byteSize>120&&target.floatOps==0){
            bd.category="STATE_MACHINES";bd.dnaScore=DNA_STATE_MACHINE;bd.reasons.add("LogicEngine");
        } else if(parent.byteSize<350&&parent.branchOps>=3&&parent.calledCount<5&&
                  target.byteSize<50&&target.branchOps<=2&&target.calledCount<=1){
            bd.category="STATE_MACHINES";bd.dnaScore=DNA_STATE_MACHINE;bd.reasons.add("Dispatcher+Worker");
        } else if((parent.byteSize>400||parent.calledCount>10)&&parent.floatOps==0&&
                  target.byteSize<=100&&target.branchOps<=2&&target.mathOps<=4){
            bd.category="MACRO_SCRIPTS";bd.dnaScore=DNA_MACRO_SCRIPT;bd.reasons.add("MacroScript");
        }
        if(bd.category.equals("UNKNOWN")){bd.isKilled=true;bd.killReason="NoDNAMatch";return bd;}

        int kzl;
        switch(bd.category){
            case "TIMERS":         kzl=0; break;
            case "MACRO_SCRIPTS":  kzl=1; break;
            case "VECTORS":        kzl=2; break;
            case "STATE_MACHINES": kzl=3; break;
            case "ANIM_TICKERS":   kzl=4; break; // Deep in call tree by design
            default:               kzl=2; break;
        }
        if(parent.byteSize<64)                             kzl=Math.max(0,kzl-1);
        if(parent.byteSize>2000&&parent.branchOps>30)      kzl++;
        if(dangerDepth!=-1&&dangerDepth<=kzl){bd.isKilled=true;bd.killReason="KillZone(d="+dangerDepth+")";return bd;}

        long offset=targetAddr.getOffset()-PS2_BASE;
        if(offset<0x040000L){bd.isKilled=true;bd.killReason="HardwareZone";return bd;}
        else if(offset<0x080000L){if(bd.category.equals("VECTORS")&&offset>=0x050000L) bd.addressBonus=ADDR_VECTORS_MID;}
        else if(offset<0x100000L) bd.addressBonus=ADDR_MID;
        else bd.addressBonus=ADDR_SAFE;

        // V13.2: Orphan bonus reduced from 20→10 to prevent score inflation.
        // Functions not in any call tree were getting an unwarranted +20 that pushed
        // unrelated vtable candidates above real gameplay functions.
        if(dangerDepth==-1) bd.depthBonus=10;
        else if(dangerDepth>=kzl+4) bd.depthBonus=15;
        else if(dangerDepth>=kzl+3) bd.depthBonus=10;
        else if(dangerDepth>=kzl+2) bd.depthBonus=5;

        // V13.2: Expanded nexus bonus to ANIM_TICKERS (animation managers are frame-rate-sensitive)
        if(frameRateNexus.containsKey(parentAddr)&&
           (bd.category.equals("VECTORS")||bd.category.equals("TIMERS")||bd.category.equals("ANIM_TICKERS")))
            bd.nexusBonus=NEXUS_BONUS;
        return bd;
    }

    private int getMaxCallers(String cat){
        switch(cat){
            case "MACRO_SCRIPTS":     return MAX_CALLERS_MACRO;
            case "TIMERS":            return MAX_CALLERS_TIMERS;
            case "STATE_MACHINES":    return MAX_CALLERS_STATE;
            case "VECTORS":           return MAX_CALLERS_VECTORS;
            case "ANIM_TICKERS":
            case "ANIMATION_MODIFIERS": return MAX_CALLERS_ANIM;
            default:                  return MAX_CALLERS_DEFAULT;
        }
    }

    private int getCallerPenalty(String cat){
        switch(cat){
            case "MACRO_SCRIPTS":   return PENALTY_MACRO;
            case "TIMERS":          return PENALTY_TIMERS;
            case "STATE_MACHINES":  return PENALTY_STATE;
            case "VECTORS":         return PENALTY_VECTORS;
            case "ANIM_TICKERS":
            case "ANIMATION_MODIFIERS": return PENALTY_ANIM;
            default:                return PENALTY_DEFAULT;
        }
    }

    // =========================================================
    // STANDALONE SCORING (Pass 2 vtable candidates)
    // V13.2: Getter Killer, VTABLE sub-split via callOps, removed Orphan Bonus inflation
    // =========================================================
    private int computeStandaloneScore(FuncTraits t, Address addr){
        String cat=assignCategoryFromTraits(t);
        // Passive Getter Killer and unknown — return 0 so PASS 2 discards them silently
        if(cat.equals("VTABLE_GETTER")||cat.equals("UNKNOWN")) return 0;

        int score=0;
        if(cat.equals("ANIM_TICKERS"))       score=DNA_ANIM_TICKER;
        else if(cat.equals("STATE_MACHINES")) score=DNA_STATE_MACHINE;
        else if(cat.equals("VECTORS"))        score=DNA_HEAVY_FPU;

        long off=addr.getOffset()-PS2_BASE;
        if(off<0x040000L) return 0;
        else if(off<0x100000L) score+=ADDR_MID; else score+=ADDR_SAFE;

        if(t.usesSPR) score+=SPR_BONUS;
        if(t.quadwordVU>=2) score+=QVU_BONUS;

        // V13.2: Removed automatic VTABLE_BONUS (+20/25) that caused 100+ score inflation.
        // Flat +10 keeps standalone vtable functions in the 55-85 range, proportional to
        // JAL-discovered functions that earn their score through parent context.
        return score+10;
    }

    private String assignCategoryFromTraits(FuncTraits t){
        // V13.2: Passive Getter Killer.
        // A vtable function that calls nothing, writes nothing, and is tiny is a Getter/Checker.
        // Hooking it would at best do nothing; at worst cause a null-dereference in the caller.
        boolean callsOthers=(t.calledCount>0||t.callOps>0);
        if(!callsOthers&&t.byteSize<150&&!t.writesToGlobal) return "VTABLE_GETTER";

        // V13.2: VTABLE sub-split — maps to existing output categories (no new category names).
        // FPU/VU0 + calls = Animation/Physics Manager (not pure math)
        if(callsOthers&&(t.floatOps>=4||t.usesCop2||t.isVu0)) return "ANIM_TICKERS";
        // Many branches + calls = AI/State Manager
        if(callsOthers&&t.branchOps>=5) return "STATE_MACHINES";

        // Standard fallbacks for non-vtable-split functions
        if(t.isVu0||t.usesCop2||t.usesCop1||t.floatOps>=6) return "VECTORS";
        if(hasAnimTickerDNA(t)) return "ANIM_TICKERS";
        if(hasStateMachineDNA(t)) return "STATE_MACHINES";
        return "UNKNOWN";
    }

    private boolean hasAnimTickerDNA(FuncTraits t){
        return !t.isThunk&&t.byteSize>=8&&t.byteSize<300&&
               t.loadOps>0&&t.mathOps>0&&t.branchOps>=1&&t.floatOps==0;
    }
    private boolean hasStateMachineDNA(FuncTraits t){
        return !t.isThunk&&t.byteSize>=8&&t.byteSize<350&&
               t.branchOps>=3&&t.mathOps<=10&&t.floatOps==0;
    }

    // =========================================================
    // TRAITS — Full P-Code + Assembly Scanner
    // V13 Final: null guards on all getMnemonicString() calls
    //            suppressHFCache support for Pass 2 OOM prevention
    // =========================================================
    private FuncTraits getTraits(Function func){
        Address key=func.getEntryPoint();
        if(cache.containsKey(key)) return cache.get(key);
        FuncTraits traits=new FuncTraits();
        traits.byteSize=func.getBody().getNumAddresses();
        traits.calledCount=func.getCalledFunctions(monitor).size();
        traits.isThunk=isThunkFunction(func);
        if(func.getName().toLowerCase().contains("vu0")) traits.isVu0=true;
        if(traits.isThunk){cache.put(key,traits);return traits;}

        // P-Code analysis — FIX: skip entirely during Pass 2.
        // Pass 2 iterates all 20,000+ functions; decompiling each costs ~15s worst-case.
        // The assembly scanner below provides sufficient signal (COP1/COP2/SPR/quadword)
        // to classify vtable candidates without P-Code. Pass 1 already collected P-Code
        // for all JAL-reachable functions with full cache, so nothing is lost.
        if(!suppressHFCache){
            HighFunction highFunc=highFuncCache.get(key);
            if(highFunc==null){
                DecompileResults res=decomp.decompileFunction(func,15,monitor);
                highFunc=res.getHighFunction();
                if(highFunc!=null) highFuncCache.put(key,highFunc);
            }
            if(highFunc!=null){
                Map<Long,Integer> varIncrements=new HashMap<>();
                Map<Long,Boolean> varHasFrameCompare=new HashMap<>();
                Iterator<PcodeOpAST> pcodeOps=highFunc.getPcodeOps();
                while(pcodeOps.hasNext()){
                    PcodeOp op=pcodeOps.next(); int opc=op.getOpcode();
                    if(opc==PcodeOp.FLOAT_MULT||opc==PcodeOp.FLOAT_ADD||opc==PcodeOp.FLOAT_SUB||opc==PcodeOp.FLOAT_DIV) traits.floatOps++;
                    if(opc==PcodeOp.INT_ADD||opc==PcodeOp.INT_SUB||opc==PcodeOp.INT_MULT||opc==PcodeOp.INT_DIV) traits.mathOps++;
                    if(opc==PcodeOp.CBRANCH||opc==PcodeOp.BRANCHIND) traits.branchOps++;
                    if(opc==PcodeOp.LOAD) traits.loadOps++;
                    for(int i=0;i<op.getNumInputs();i++){Varnode in=op.getInput(i);if(in!=null&&in.isConstant()) traits.constants.add(in.getOffset());}
                    if(opc==PcodeOp.INT_ADD){
                        Varnode out=op.getOutput(),in1=op.getInput(1);
                        if(in1!=null&&in1.isConstant()&&(in1.getOffset()==1L||in1.getOffset()==0xFFFFFFFFL)){
                            traits.hasTickIncrement=true;
                            if(out!=null) varIncrements.put(out.getOffset(),varIncrements.getOrDefault(out.getOffset(),0)+1);
                        }
                    }
                    if(opc==PcodeOp.INT_LESS||opc==PcodeOp.INT_LESSEQUAL||opc==PcodeOp.INT_SLESS||opc==PcodeOp.INT_SLESSEQUAL){
                        Varnode in0=op.getInput(0),in1=op.getInput(1);
                        if(in1!=null&&in1.isConstant()&&isFrameConst(in1.getOffset())){
                            traits.hasTimerCompare=true;if(in0!=null&&!in0.isConstant()) varHasFrameCompare.put(in0.getOffset(),true);
                        } else if(in0!=null&&in0.isConstant()&&isFrameConst(in0.getOffset())){
                            traits.hasTimerCompare=true;if(in1!=null&&!in1.isConstant()) varHasFrameCompare.put(in1.getOffset(),true);
                        }
                    }
                }
                for(Long varId:varIncrements.keySet())
                    if(varHasFrameCompare.getOrDefault(varId,false)){traits.hasFrameCounterPattern=true;break;}
            }
        } // end !suppressHFCache (P-Code block)

        // Assembly scanner — null guard on every getMnemonicString()
        InstructionIterator asmIter=currentProgram.getListing().getInstructions(func.getBody(),true);
        int instrIdx=0;
        while(asmIter.hasNext()){
            Instruction inst=asmIter.next();
            String mnem=inst.getMnemonicString();
            if(mnem==null){instrIdx++;continue;}
            String ml=mnem.toLowerCase();

            // V13 Final: Stack Frame detection — first 8 instructions
            // FIX: added daddiu for EE 64-bit stack allocation support
            if(instrIdx<8&&(ml.equals("addiu")||ml.equals("daddiu")))
                for(Object op:inst.getInputObjects())
                    if(op instanceof ghidra.program.model.lang.Register&&
                       ((ghidra.program.model.lang.Register)op).getName().equals("sp"))
                        traits.hasStackFrame=true;

            // COP1 / COP2 detection
            if(ml.contains("c1")||ml.endsWith(".s")||ml.endsWith(".d")) traits.usesCop1=true;
            if(ml.startsWith("vadd")||ml.startsWith("vmul")||ml.startsWith("vsub")||
               ml.startsWith("vscl")||ml.startsWith("vdiv")||ml.startsWith("vmfir")||
               ml.startsWith("vmtir")||ml.startsWith("vabs")||ml.startsWith("vsqrt")||
               ml.startsWith("vrsqrt")||ml.startsWith("vwaitq")||ml.startsWith("vopmula")||
               ml.startsWith("vitof")||ml.startsWith("vftoi")||
               ml.contains("c2")) traits.usesCop2=true;
            if(ml.equals("lqc2")||ml.equals("sqc2")){traits.usesCop2=true;traits.quadwordVU++;}
            if(ml.equals("lq")||ml.equals("sq")) traits.quadwordGeneral++;
            if(ml.startsWith("madda")||ml.startsWith("vmadd")||ml.startsWith("vmsub")||ml.startsWith("madd")||
               ml.startsWith("vmula")||ml.startsWith("vadda")||ml.startsWith("vsuba")||ml.startsWith("vopmula")) traits.accOps++;

            // Return path count — FIX: ONLY 'jr' is a return in MIPS.
            // 'jalr' is a virtual call (C++ vtable dispatch), NOT a return.
            // Counting jalr as return wrongly penalizes C++ virtual methods.
            if(ml.equals("jr"))
                for(Object op:inst.getInputObjects())
                    if(op instanceof ghidra.program.model.lang.Register&&
                       ((ghidra.program.model.lang.Register)op).getName().equalsIgnoreCase("ra"))
                        traits.returnPaths++;

            // Global write detection — FIX: isMemorySpace() prevents stack/register
            // space offsets from being misidentified as global RAM writes.
            if(ml.equals("sw")||ml.equals("swc1")||ml.equals("sqc2")||ml.equals("sh")||ml.equals("sb")){
                traits.hasMutatingInstructions=true;
                for(Reference ref:inst.getReferencesFrom())
                    if(ref.getReferenceType().isWrite()&&
                       ref.getToAddress().getAddressSpace().isMemorySpace()&&
                       ref.getToAddress().getOffset()>=GLOBAL_ADDR_MIN)
                        traits.writesToGlobal=true;
            }
            // FIX: jal AND jalr both indicate mutation (jalr = C++ virtual call)
            if(ml.equals("jal")||ml.equals("jalr")) traits.hasMutatingInstructions=true;

            // SPR detection
            for(Reference ref:inst.getReferencesFrom()){
                long off=ref.getToAddress().getOffset();
                if(off>=SPR_START&&off<=SPR_END) traits.usesSPR=true;
            }

            // Fix 1: Assembly-level fallback counters for Pass 2.
            // When suppressHFCache=true the P-Code block is skipped entirely, leaving
            // branchOps/loadOps/mathOps at 0. hasStateMachineDNA and hasAnimTickerDNA
            // depend on these values, so without this fallback Pass 2 would never find
            // AI or animation vtable targets. The heuristics are intentionally coarse
            // (branch mnemonic prefix, load prefix, arithmetic prefix) — sufficient for
            // DNA classification without requiring a full decompile.
            if(suppressHFCache){
                if(ml.startsWith("b")&&!ml.equals("break")) traits.branchOps++;
                else if(ml.startsWith("l")&&!ml.equals("lui")&&!ml.equals("lq")&&!ml.equals("lqc2")) traits.loadOps++;
                else if(ml.startsWith("add")||ml.startsWith("dadd")||ml.startsWith("sub")||
                        ml.startsWith("mul")||ml.startsWith("div")) traits.mathOps++;
                // V13.2: Count standard COP1 float ops in Pass 2 (decompiler skipped)
                // Catches add.s/sub.s/mul.s which don't have a vadd/vscl prefix
                if(ml.endsWith(".s")||ml.endsWith(".d")||ml.startsWith("cvt.")||ml.startsWith("c."))
                    traits.floatOps++;
                // Count calls at instruction level — catches jalr (C++ virtuals) that
                // Ghidra's getFunctionCalledFunctions() sometimes misses in stripped binaries
                if(ml.equals("jal")||ml.equals("jalr")||ml.equals("bal")||ml.startsWith("bgezal")) traits.callOps++;
            }

            instrIdx++;
        }
        cache.put(key,traits); return traits;
    }

    // =========================================================
    // MODULE A: EULER HUNTER
    // =========================================================
    private boolean detectEulerPattern(Function parentFunc, Function targetFunc, Address jalAddr){
        String tn=targetFunc.getName().toLowerCase();
        boolean targetIsAdd=tn.contains("addvec")||tn.contains("addvector")||tn.contains("vecadd")||hasCop2Mnemonic(targetFunc,"vadd");
        if(!targetIsAdd) return false;
        Boolean cached=eulerCache.get(jalAddr); if(cached!=null) return cached;
        Address parentEntry=parentFunc.getEntryPoint();
        List<long[]> jalList=parentJalListCache.get(parentEntry);
        if(jalList==null){
            jalList=new ArrayList<>();
            InstructionIterator it=currentProgram.getListing().getInstructions(parentFunc.getBody(),true);
            while(it.hasNext()){
                Instruction inst=it.next();
                String m=inst.getMnemonicString();
                if(m==null||!m.equals("jal")) continue;
                Reference[] refs=inst.getReferencesFrom();
                if(refs.length==0) continue;
                jalList.add(new long[]{inst.getAddress().getOffset(),refs[0].getToAddress().getOffset()});
            }
            parentJalListCache.put(parentEntry,jalList);
        }
        int myIdx=-1; long jalOff=jalAddr.getOffset();
        for(int i=0;i<jalList.size();i++) if(jalList.get(i)[0]==jalOff){myIdx=i;break;}
        if(myIdx<0){eulerCache.put(jalAddr,false);return false;}
        int lookBack=Math.max(0,myIdx-EULER_WINDOW);
        for(int i=lookBack;i<myIdx;i++){
            Function prev=funcManager.getFunctionAt(toAddr(jalList.get(i)[1]));
            if(prev==null) continue;
            String pn=prev.getName().toLowerCase();
            if(pn.contains("scalevec")||pn.contains("vecscale")||pn.contains("scale")||hasCop2Mnemonic(prev,"vscl")){
                eulerCache.put(jalAddr,true); return true;
            }
        }
        eulerCache.put(jalAddr,false); return false;
    }

    // =========================================================
    // MODULE B: KINEMATIC HUNTER
    // =========================================================
    private boolean detectKinematicPattern(Function parentFunc, Function targetFunc, Address jalAddr){
        String tn=targetFunc.getName().toLowerCase();
        boolean isCopy=tn.contains("copyvec")||tn.contains("vecopy")||tn.contains("copyvector")||
                       (targetFunc.getBody().getNumAddresses()<=64&&hasCop2Mnemonic(targetFunc,"vadd"));
        if(!isCopy) return false;
        Address parentEntry=parentFunc.getEntryPoint();
        Boolean cached=kinematicCache.get(parentEntry); if(cached!=null) return cached;
        HighFunction highFunc=highFuncCache.get(parentEntry); if(highFunc==null){kinematicCache.put(parentEntry,false);return false;}
        boolean result=false;
        Iterator<PcodeOpAST> ops=highFunc.getPcodeOps(jalAddr);
        outer: while(ops.hasNext()){
            PcodeOpAST op=ops.next();
            if(op.getOpcode()!=PcodeOp.CALL) continue;
            for(int i=1;i<op.getNumInputs();i++) if(tracesToTrigFunction(op.getInput(i))){result=true;break outer;}
        }
        kinematicCache.put(parentEntry,result); return result;
    }

    private boolean tracesToTrigFunction(Varnode start){
        if(start==null) return false;
        Set<Varnode> visited=new HashSet<>(); Queue<Varnode> queue=new LinkedList<>(); queue.add(start);
        while(!queue.isEmpty()){
            Varnode curr=queue.poll(); if(curr==null||!visited.add(curr)) continue;
            PcodeOp def=curr.getDef(); if(def==null) continue;
            int opc=def.getOpcode();
            if(opc==PcodeOp.CALL||opc==PcodeOp.CALLIND){
                Varnode ct=def.getInput(0);
                if(ct!=null&&ct.isAddress()){
                    Function callee=funcManager.getFunctionAt(ct.getAddress());
                    if(callee!=null){String cn=callee.getName();if(cn.equals("sinf")||cn.equals("cosf")||cn.equals("sin")||cn.equals("cos")) return true;}
                }
            }
            for(int i=0;i<def.getNumInputs();i++){Varnode in=def.getInput(i);if(in!=null&&!in.isConstant()&&!in.isAddress()) queue.add(in);}
        }
        return false;
    }

    // =========================================================
    // MODULE C: HIERARCHY MATRIX
    // =========================================================
    private String calcHierarchyType(Function parentFunc){
        Address key=parentFunc.getEntryPoint();
        String cached=hierarchyCache.get(key); if(cached!=null) return cached;
        Set<Function> callers=parentFunc.getCallingFunctions(monitor);
        if(callers.isEmpty()){hierarchyCache.put(key,"SINGLETON");return "SINGLETON";}
        for(Function caller:callers) if(callerContainsLoopAroundCall(caller,key)){hierarchyCache.put(key,"BATCH");return "BATCH";}
        hierarchyCache.put(key,"SINGLETON"); return "SINGLETON";
    }

    private boolean callerContainsLoopAroundCall(Function caller, Address calleeEntry){
        Address jalSite=null;
        InstructionIterator it=currentProgram.getListing().getInstructions(caller.getBody(),true);
        while(it.hasNext()){
            Instruction inst=it.next(); String m=inst.getMnemonicString();
            if(m==null||!m.equals("jal")) continue;
            Reference[] refs=inst.getReferencesFrom();
            if(refs.length>0&&refs[0].getToAddress().equals(calleeEntry)){jalSite=inst.getAddress();break;}
        }
        if(jalSite==null) return false;
        InstructionIterator it2=currentProgram.getListing().getInstructions(caller.getBody(),true);
        while(it2.hasNext()){
            Instruction inst=it2.next(); String mnem=inst.getMnemonicString();
            if(mnem==null||(!mnem.startsWith("b")&&!mnem.equals("j")&&!mnem.equals("jr"))) continue;
            for(Reference ref:inst.getReferencesFrom()){
                if(!ref.getReferenceType().isFlow()) continue;
                Address target=ref.getToAddress(),branchAt=inst.getAddress();
                if(target.compareTo(branchAt)<0&&target.compareTo(jalSite)<=0&&branchAt.compareTo(jalSite)>=0) return true;
            }
        }
        return false;
    }

    // =========================================================
    // MODULE E: ANIMATION HUNTER
    // =========================================================
    private boolean detectAnimationModifier(Function parentFunc, Function targetFunc, Address jalAddr){
        Boolean cached=animDetectCache.get(jalAddr); if(cached!=null) return cached;
        FuncTraits parentTraits=cache.get(parentFunc.getEntryPoint());
        if(parentTraits==null||parentTraits.floatOps==0){animDetectCache.put(jalAddr,false);return false;}
        if(hasCop2Mnemonic(targetFunc,"vadd")||hasCop2Mnemonic(targetFunc,"vscl")){animDetectCache.put(jalAddr,false);return false;}
        String targetName=targetFunc.getName().toLowerCase();
        for(String kw:ANIM_KEYWORDS) if(targetName.contains(kw)){animDetectCache.put(jalAddr,true);return true;}
        boolean result=isFloatParamPassedToCall(parentFunc,targetFunc,jalAddr);
        animDetectCache.put(jalAddr,result); return result;
    }

    private boolean isFloatParamPassedToCall(Function parentFunc, Function targetFunc, Address jalAddr){
        HighFunction parentHF=highFuncCache.get(parentFunc.getEntryPoint()); if(parentHF==null) return false;
        boolean parentSendsFloat=false;
        Iterator<PcodeOpAST> parentOps=parentHF.getPcodeOps(jalAddr);
        outer: while(parentOps.hasNext()){
            PcodeOpAST op=parentOps.next(); if(op.getOpcode()!=PcodeOp.CALL) continue;
            for(int i=1;i<op.getNumInputs();i++){
                Varnode in=op.getInput(i); if(in==null) continue;
                PcodeOp def=in.getDef();
                if(def!=null){int opc=def.getOpcode();
                    if(opc==PcodeOp.FLOAT_ADD||opc==PcodeOp.FLOAT_MULT||opc==PcodeOp.FLOAT_SUB||opc==PcodeOp.FLOAT_DIV||
                       opc==PcodeOp.FLOAT_ABS||opc==PcodeOp.FLOAT_SQRT||opc==PcodeOp.FLOAT_INT2FLOAT||opc==PcodeOp.FLOAT_FLOAT2FLOAT)
                        {parentSendsFloat=true;break outer;}
                }
                HighVariable hv=in.getHigh();
                if(hv!=null&&hv.getDataType()!=null){String tn=hv.getDataType().getName().toLowerCase();
                    if(tn.equals("float")||tn.equals("double")){parentSendsFloat=true;break outer;}}
            }
        }
        if(!parentSendsFloat) return false;
        ghidra.program.model.lang.Register f12Reg=currentProgram.getLanguage().getRegister("f12");
        if(f12Reg==null) return true;
        long f12Off=f12Reg.getOffset();
        Address targetEntry=targetFunc.getEntryPoint();
        HighFunction targetHF=highFuncCache.get(targetEntry);
        if(targetHF==null){
            DecompileResults res=decomp.decompileFunction(targetFunc,10,monitor);
            targetHF=res.getHighFunction();
            if(targetHF!=null&&!suppressHFCache) highFuncCache.put(targetEntry,targetHF);
        }
        if(targetHF==null) return true;
        int checked=0; Iterator<PcodeOpAST> targetOps=targetHF.getPcodeOps();
        while(targetOps.hasNext()&&checked<12){
            PcodeOpAST op=targetOps.next(); checked++;
            for(int i=0;i<op.getNumInputs();i++){Varnode in=op.getInput(i);if(in!=null&&in.isRegister()&&in.getOffset()==f12Off) return true;}
        }
        return false;
    }

    // =========================================================
    // MODULE F: GLOBAL STATE WRITER
    // =========================================================
    private boolean parentWritesToGlobal(Function parentFunc, Address jalAddr){
        Boolean cached=globalWriteCache.get(jalAddr); if(cached!=null) return cached;
        List<Instruction> all=new ArrayList<>();
        InstructionIterator iter=currentProgram.getListing().getInstructions(parentFunc.getBody(),true);
        while(iter.hasNext()) all.add(iter.next());
        int jalIdx=-1; long jalOff=jalAddr.getOffset();
        for(int i=0;i<all.size();i++) if(all.get(i).getAddress().getOffset()==jalOff){jalIdx=i;break;}
        if(jalIdx<0){globalWriteCache.put(jalAddr,false);return false;}
        int lo=Math.max(0,jalIdx-20),hi=Math.min(all.size(),jalIdx+21);
        for(int i=lo;i<hi;i++){
            Instruction inst=all.get(i); String mnem=inst.getMnemonicString();
            if(mnem==null) continue; String ml=mnem.toLowerCase();
            if(!ml.equals("sw")&&!ml.equals("swc1")&&!ml.equals("sqc2")&&!ml.equals("sh")&&!ml.equals("sb")) continue;
            for(Reference ref:inst.getReferencesFrom())
                if(ref.getReferenceType().isWrite()&&
                   ref.getToAddress().getAddressSpace().isMemorySpace()&&
                   ref.getToAddress().getOffset()>=GLOBAL_ADDR_MIN){
                    globalWriteCache.put(jalAddr,true); return true;}
        }
        globalWriteCache.put(jalAddr,false); return false;
    }

    // =========================================================
    // MODULE G: ENTITY STRUCT WRITER (V13: fixed Scalar type)
    // =========================================================
    private boolean parentWritesToEntityStruct(Function parentFunc, Address jalAddr){
        Boolean cached=structWriteCache.get(jalAddr); if(cached!=null) return cached;
        List<Instruction> all=new ArrayList<>();
        InstructionIterator iter=currentProgram.getListing().getInstructions(parentFunc.getBody(),true);
        while(iter.hasNext()) all.add(iter.next());
        int jalIdx=-1; long jalOff=jalAddr.getOffset();
        for(int i=0;i<all.size();i++) if(all.get(i).getAddress().getOffset()==jalOff){jalIdx=i;break;}
        if(jalIdx<0){structWriteCache.put(jalAddr,false);return false;}
        int lo=Math.max(0,jalIdx-20),hi=Math.min(all.size(),jalIdx+21);
        for(int i=lo;i<hi;i++){
            Instruction inst=all.get(i); String mnem=inst.getMnemonicString();
            if(mnem==null) continue; String ml=mnem.toLowerCase();
            if(!ml.equals("swc1")&&!ml.equals("sqc2")) continue;
            // V13 Bug 1 Fix: Ghidra operands are Scalar, never Integer/Long
            for(Object op:inst.getInputObjects())
                if(op instanceof ghidra.program.model.scalar.Scalar){
                    long offset=((ghidra.program.model.scalar.Scalar)op).getValue();
                    if(offset>=0&&offset<=STRUCT_OFFSET_MAX){structWriteCache.put(jalAddr,true);return true;}
                }
        }
        structWriteCache.put(jalAddr,false); return false;
    }

    // =========================================================
    // HELPER: COP2 mnemonic check (null guard)
    // =========================================================
    private boolean hasCop2Mnemonic(Function func, String contains){
        InstructionIterator it=currentProgram.getListing().getInstructions(func.getBody(),true);
        while(it.hasNext()){String m=it.next().getMnemonicString();if(m!=null&&m.toLowerCase().contains(contains)) return true;}
        return false;
    }

    // =========================================================
    // WRITE PNACH — minimalist 2-line format
    // V13: Smart delay slot + hasReturnDependency [RISK] tag
    //      Smart Return Fallback comment for STATE_MACHINES
    // =========================================================
    private void writePnach(File outputFile, List<TargetProfile> targets,
                            Address loop1, Address loop2, Address nexus,
                            List<StrideCandidate> strides) throws Exception {
        PrintWriter w=new PrintWriter(new FileWriter(outputFile));
        w.println("// PS2 SCORING RADAR V13 FINAL - THE DEFINITIVE EDITION");
        w.println("// Gameplay Loop : "+(loop1!=null?loop1:"N/A"));
        w.println("// Menu Loop     : "+(loop2!=null?loop2:"N/A"));
        w.println("// Nexus Seed    : "+(nexus!=null?nexus:"N/A"));
        w.println("// Total targets : "+targets.size());
        w.println();

        if(!strides.isEmpty()){
            w.println("// =========================================================");
            w.println("// 60FPS STRIDE CANDIDATES ("+strides.size()+") — Manual inspection required");
            w.println("// =========================================================");
            for(StrideCandidate sc:strides)
                w.println(String.format("// %08X  %s  |  %s",sc.addr.getOffset(),sc.funcName,sc.description));
            w.println();
        }

        // Split targets: regular categories vs STATE_MACHINES (softlock-prone)
        List<TargetProfile> mainTargets = new ArrayList<>();
        List<TargetProfile> softlockTargets = new ArrayList<>();
        for(TargetProfile p : targets) {
            if(p.assignedCategory.equals("STATE_MACHINES")) softlockTargets.add(p);
            else mainTargets.add(p);
        }

        writePnachSection(w, mainTargets, false);

        if(!softlockTargets.isEmpty()){
            w.println("// =========================================================");
            w.println("// STATE_MACHINES — SOFTLOCK RISK ("+softlockTargets.size()+")");
            w.println("// If game freezes after patching, change delay slot word from");
            w.println("// 00001021 (move v0,zero) → 24020001 (li v0,1) to return TRUE.");
            w.println("// =========================================================");
            w.println();
            writePnachSection(w, softlockTargets, true);
        }

        String[] cats={"TIMERS","VECTORS","ANIMATION_MODIFIERS","ANIM_TICKERS","STATE_MACHINES","MACRO_SCRIPTS"};
        w.println("// =========================================================");
        w.println("// STATISTICS");
        w.println("// =========================================================");
        int total=0;
        for(String cat:cats){long count=targets.stream().filter(p->p.assignedCategory.equals(cat)).count();w.println("// "+cat+" : "+count);total+=(int)count;}
        long vtCount=targets.stream().filter(p->p.isVtableHook).count();
        w.println("// VTABLE HOOKS    : "+vtCount);
        w.println("// TOTAL           : "+total);
        w.println("// (Thunks → see _thunks.txt  |  Global hooks → see _global_hooks.txt)");
        w.close();
    }

    private void writePnachSection(PrintWriter w, List<TargetProfile> targets, boolean isSoftlockSection){
        int prevGroup=-1;
        for(TargetProfile p:targets){
            if(p.totalCallers!=prevGroup){
                prevGroup=p.totalCallers;
                if(p.isVtableHook) w.println("// === VTABLE / JALR (0 direct JAL callers) ===");
                else w.println("// === Callers: "+p.totalCallers+" ===");
            }
            Address addr=p.targetFunc.getEntryPoint();
            String addrHex=String.format("%08X",addr.getOffset());
            String addrHex4=String.format("%08X",addr.getOffset()+4);
            String funcName=p.targetFunc.getName();
            String delaySlot=buildDelaySlot(p.assignedCategory,p.targetTraits);
            String tagStr=p.bestTags.isEmpty()?"":" | "+String.join(", ",p.bestTags);
            String vtag=p.isVtableHook?" [VTABLE]":"";
            String spr=p.sprTag.isEmpty()?"":" "+p.sprTag;
            if(p.hasReturnDependency){
                w.println("// [FALLBACK] Global Hook suppressed — Local NOPs on safe callers only.");
                w.println("// Reason: at least one other caller depends on the return value.");
                for(ParentContext ctx:p.callers){
                    String la=String.format("%08X",ctx.jalAddr.getOffset());
                    String la4=String.format("%08X",ctx.jalAddr.getOffset()+4);
                    w.println("patch=1,EE,"+la+",word,00000000 // NOP jal → "+funcName+" ("+p.assignedCategory+")");
                    w.println("patch=1,EE,"+la4+",word,00000000 // NOP delay slot");
                }
            } else {
                // For STATE_MACHINES: inline SOFTLOCK ALT into the delay slot comment line
                String delayComment = isSoftlockSection
                    ? "//SOFTLOCK ALT: if game freezes, change delay slot to 24020001 (li v0,1) Callers:"+p.totalCallers+" | Type:"+p.assignedCategory+tagStr
                    : "// Callers:"+p.totalCallers+" | Type:"+p.assignedCategory+tagStr;
                w.println("patch=1,EE,"+addrHex+",word,03E00008 // jr ra "+funcName+
                          " @ "+addrHex.toLowerCase()+" [Score:"+p.finalScore+"]"+vtag+spr);
                w.println("patch=1,EE,"+addrHex4+",word,"+delaySlot+" "+delayComment);
            }
            w.println();
        }
    }

    // V13: Smart delay slot
    private String buildDelaySlot(String cat, FuncTraits t){
        if(cat.equals("VECTORS")) return "00000000";       // NOP — don't corrupt HW registers
        if(t.usesCop1||t.floatOps>5) return "44800000";   // mtc1 zero,$f0 — safe float return
        return "00001021";                                  // move v0,zero (addu) — null pointer return
    }

    // =========================================================
    // WRITE GLOBAL HOOKS FILE
    // =========================================================
    private void writeGlobalHooks(File outputFile) throws IOException {
        PrintWriter w=new PrintWriter(new FileWriter(outputFile));
        w.println("// PS2 RADAR V13 FINAL - GLOBAL HOOK POINTS");
        w.println("// Address → central entry point for planting custom ASM redirections.");
        w.println("// Usage: patch=1,EE,XXXXXXXX,word,<j_instruction_encoding>");
        w.println("// Count: "+globalHooks.size()); w.println();
        for(Map.Entry<Long,String> e:globalHooks.entrySet())
            w.println(String.format("%08X // [GLOBAL HOOK] %s",e.getKey(),e.getValue()));
        w.close();
    }

    // =========================================================
    // WRITE THUNKS FILE
    // =========================================================
    private void writeThunksFile(File outputFile, List<TargetProfile> thunks) throws IOException {
        PrintWriter w=new PrintWriter(new FileWriter(outputFile));
        w.println("// PS2 RADAR V13 FINAL - THUNK HOOKS (Surgical Vtable Entries)");
        w.println("// Only thunks whose real target was NOT caught by the main scanner.");
        w.println("// Patching a thunk affects only callers via this specific vtable slot.");
        w.println("// Count: "+thunks.size()); w.println();
        for(TargetProfile p:thunks){
            Address addr=p.targetFunc.getEntryPoint();
            String addrHex=String.format("%08X",addr.getOffset());
            String addrHex4=String.format("%08X",addr.getOffset()+4);
            String delay=buildDelaySlot(p.assignedCategory,p.targetTraits);
            String realName=p.callers.isEmpty()?"?":(p.callers.get(0).wasResolved?p.callers.get(0).resolvedTarget.getName():"?");
            w.println("// Thunk → "+realName+" [Score:"+p.finalScore+"] Callers:"+p.totalCallers);
            w.println("patch=1,EE,"+addrHex+",word,03E00008 // jr ra "+p.targetFunc.getName());
            w.println("patch=1,EE,"+addrHex4+",word,"+delay+" // "+p.assignedCategory);
            w.println();
        }
        w.close();
    }

    // =========================================================
    // TRACER BULLETS — single file, all targets, for binary search in PCSX2
    // =========================================================
    private void writeTracerBullets(File baseFile, List<TargetProfile> all) throws IOException {
        if(all.isEmpty()) return;
        String basePath=baseFile.getParent(),baseName=baseFile.getName().replaceFirst("\\..*$","");
        File outFile=new File(basePath,baseName+"_tracer.txt");
        PrintWriter w=new PrintWriter(new FileWriter(outFile));
        w.println("// V13 Tracer Bullets — "+all.size()+" targets");
        w.println("// Binary search: disable half at a time in PCSX2 until crash disappears.");
        w.println();
        for(TargetProfile p:all){
            Address addr=p.targetFunc.getEntryPoint();
            String funcName=p.targetFunc.getName();
            if(p.hasReturnDependency){
                w.println("// [FALLBACK LOCAL NOPs] "+funcName+" — return value dependency");
                for(ParentContext ctx:p.callers){
                    String la=String.format("%08X",ctx.jalAddr.getOffset());
                    String la4=String.format("%08X",ctx.jalAddr.getOffset()+4);
                    w.println("patch=1,EE,"+la+",word,00000000 // NOP jal → "+funcName);
                    w.println("patch=1,EE,"+la4+",word,00000000 // NOP delay slot");
                }
            } else {
                String addrHex=String.format("%08X",addr.getOffset()),addrHex4=String.format("%08X",addr.getOffset()+4);
                String delay=buildDelaySlot(p.assignedCategory,p.targetTraits);
                boolean isSoftlock=p.assignedCategory.equals("STATE_MACHINES");
                String delayComment=isSoftlock
                    ? "//SOFTLOCK ALT: if game freezes, change delay slot to 24020001 (li v0,1) Type:"+p.assignedCategory
                    : "// "+p.assignedCategory;
                w.println("patch=1,EE,"+addrHex+",word,03E00008 // jr ra "+funcName+" [Score:"+p.finalScore+"]");
                w.println("patch=1,EE,"+addrHex4+",word,"+delay+" "+delayComment);
            }
            w.println();
        }
        w.close();
        println("[TRACER] Wrote: "+outFile.getName()+" ("+all.size()+" targets)");
    }

    // =========================================================
    // HELPERS
    // =========================================================
    // V13 Final: Hybrid Nexus — accepts code address (instruction) OR data address (variable)
    private void buildFrameRateNexus(Address inputAddr) {
        // Determine if input is inside a function (code) or standalone data
        Function containingFunc=funcManager.getFunctionContaining(inputAddr);
        Set<Function> seeds=new HashSet<>();
        if(containingFunc!=null){
            // Code address: the containing function IS the nexus root
            seeds.add(containingFunc);
            println("[NEXUS] Code address detected → using containing function: "+containingFunc.getName());
        } else {
            // Data address: find all functions that reference this global variable
            ReferenceIterator varRefs=refManager.getReferencesTo(inputAddr);
            while(varRefs.hasNext()){
                Function f=funcManager.getFunctionContaining(varRefs.next().getFromAddress());
                if(f!=null) seeds.add(f);
            }
            println("[NEXUS] Data address detected → "+seeds.size()+" seed function(s).");
        }
        for(Function root:seeds){
            Queue<Address> q=new LinkedList<>(); Map<Address,Integer> localDepth=new HashMap<>();
            q.add(root.getEntryPoint()); localDepth.put(root.getEntryPoint(),0);
            frameRateNexus.put(root.getEntryPoint(),root.getName()+"(Direct)");
            while(!q.isEmpty()){
                Address curr=q.poll(); int depth=localDepth.get(curr);
                if(depth>=10) continue;
                Function f=funcManager.getFunctionAt(curr); if(f==null) continue;
                for(Function callee:f.getCalledFunctions(monitor)){
                    Address ca=callee.getEntryPoint();
                    if(!localDepth.containsKey(ca)){
                        localDepth.put(ca,depth+1); q.add(ca);
                        frameRateNexus.putIfAbsent(ca,root.getName()+"(D:"+(depth+1)+")");
                    }
                }
            }
        }
    }

    private void buildCallTree(Function root, int maxDepth, Map<Address,Integer> tree){
        if(root==null) return;
        Queue<Address> q=new LinkedList<>(); q.add(root.getEntryPoint()); tree.put(root.getEntryPoint(),0);
        while(!q.isEmpty()){
            Address curr=q.poll(); int depth=tree.get(curr); if(depth>=maxDepth) continue;
            Function f=funcManager.getFunctionAt(curr); if(f==null) continue;
            for(Function callee:f.getCalledFunctions(monitor)){
                Address ca=callee.getEntryPoint();
                if(!tree.containsKey(ca)){tree.put(ca,depth+1);q.add(ca);}
            }
        }
    }

    private boolean isThunkFunction(Function func){
        return func.isThunk()||(func.getBody().getNumAddresses()<=8&&func.getCalledFunctions(monitor).size()>0);
    }
    private boolean isFrameConst(long val){return val==15||val==30||val==60||val==120||val==240;}
    private int calcDangerDepth(int d1,int d2){if(d1!=-1&&d2!=-1)return Math.min(d1,d2);if(d1!=-1)return d1;if(d2!=-1)return d2;return -1;}
    private Address askAddressOptional(String title,String msg){try{return askAddress(title,msg);}catch(Exception e){return null;}}
}
