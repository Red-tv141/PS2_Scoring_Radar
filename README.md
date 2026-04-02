# PS2 Scoring Radar V13 Final: Advanced Static Analysis for 60FPS Patching

## Overview

**PS2 Scoring Radar V13 Final** is an advanced, automated Ghidra script designed specifically to assist in creating 60FPS patches for PlayStation 2 games.

Finding the correct instructions to NOP in order to decouple game logic from the frame rate is a tedious manual process. This script automates that process by acting as a highly specialized static analysis engine. It scans the entire PS2 game binary in two passes, evaluates every `jal` instruction against a rigorous set of EE hardware-aware architectural rules, and outputs a ranked, ready-to-use `.pnach` file along with supplementary hook and thunk files.

By intelligently classifying functions and prioritizing safety, PS2 Scoring Radar significantly reduces the trial-and-error traditionally required in PS2 modding.

---

## Key Features

### Two-Pass Architecture
- **Pass 1 — JAL Scanner:** Evaluates every direct `jal` instruction with full P-Code decompilation, caching, and parent context analysis.
- **Pass 2 — Full Binary Scan:** Scans all functions for vtable/`jalr` candidates using lightweight assembly heuristics (P-Code skipped to prevent OOM on large binaries).

### Topology-Based Auto-Detection
Automatically identifies Main Loop and Menu Loop candidates even in stripped binaries by analyzing:
- Instruction count and call breadth
- Internal back-edges (loop detection)
- Frame heartbeats (`BeginFrame`/`EndFrame`, `sceGsSyncV`)
- Hierarchy tiering (whether one loop calls another)

### Hybrid Nexus Seeding
The FrameRate Nexus accepts **either** a code address (a VSync instruction) **or** a data address (a global frame counter variable). In data mode, all functions that reference the variable are automatically used as roots for the nexus propagation tree.

### Multi-Layered Safety Firewalls
- **Static Library Firewall:** Blocks Sony SDK (`sceCd`, `scePad`, `sceVif`, etc.) and standard libc functions.
- **IOP Module Firewall:** Filters out I/O Processor calls (`cdvdman`, `padman`, `.IRX` references, etc.).
- **Behavioral Firewall:** Blocks functions using `syscall`, COP0, MMIO/KSEG1 hardware access, or system strings (`assert`, `panic`, `bios`).
- **Dependency Bouncer:** Blocks any JAL if its return value (`v0`, `v1`, `f0`) is read by subsequent instructions, including across MIPS branch delay slots.

### Advanced DNA Classification
Sorts safe patches into actionable categories based on FPU usage, branch density, hardware signatures (COP1/COP2/VU0), and call topology:

| Category | Description |
|---|---|
| `TIMERS` | Frame counters and tick logic |
| `VECTORS` | VU0/COP1/COP2 math, physics |
| `ANIMATION_MODIFIERS` | Float-param animation speed functions |
| `ANIM_TICKERS` | Animation/physics managers that call other functions |
| `STATE_MACHINES` | AI dispatchers and logic engines |
| `MACRO_SCRIPTS` | Cutscene and major event managers |
| `THUNKS` | Resolved vtable wrapper entries |

### Per-Category Caller Ceilings & Penalties
Each category has a maximum caller count and a per-caller score penalty to prevent utility functions from being promoted above specialized gameplay functions.

### Pattern Hunter Modules
- **Euler Hunter:** Detects Vector Scale → Vector Add sequences.
- **Kinematic Hunter:** Traces trigonometric data flows (`sinf`/`cosf`) back through P-Code.
- **Animation Hunter:** Isolates functions accepting computed float parameters (time/speed deltas).
- **Global State Writer:** Boosts functions that write to global RAM addresses near the call site.
- **Entity Struct Writer:** Boosts functions that write to struct offsets (`swc1`/`sqc2` with offsets ≤ `0x60`).
- **Hierarchy Matrix:** Promotes Singleton callers; penalizes Batch/loop callers.

### Vtable Safety Scoring
For Pass 2 vtable candidates, a Blast Radius analysis evaluates:
- Function size and branch complexity (danger penalties)
- System library callees (`malloc`, `sceCd`, etc.)
- High-fan-in utility callees
- Leaf callee ratio and safe-domain propagation (safety bonuses)

### Vtable Cluster Synergy
Adjacent vtable candidates of the same category within `0x1000` bytes receive a cluster bonus, promoting coherent vtable blocks.

### Cross-Category Context Bonus
After scoring, functions that are called near other already-confirmed strong targets (within ±5 JALs in the same parent) receive a context bonus.

### 60FPS Stride Hunter (Passive)
Scans Main Loop candidates for:
- **Integer strides:** `addiu`/`li` with `zero` base and value `1`, `2`, `-1`, `-2`
- **Float deltas:** `lwc1` loading IEEE 754 constants near `1/30` (≈`0.03333f`) or `1/60` (≈`0.01666f`)

Results are reported in the output file and console but do **not** generate automatic patches — manual inspection is required.

### Smart Delay Slot Generation
The delay slot word after each `jr ra` patch is chosen per category:
- `VECTORS` → `00000000` (NOP — avoids corrupting hardware registers)
- COP1/heavy-FPU targets → `44800000` (`mtc1 zero,$f0` — safe float return)
- All others → `0000102D` (`move v0,zero` — null pointer return)

### Memory Safety
- HighFunction (P-Code) cache is cleared between Pass 1 and Pass 2.
- `suppressHFCache` mode prevents OOM during the full-binary Pass 2 scan.

---

## Output Files

| File | Contents |
|---|---|
| `<name>.txt` | Main ranked `.pnach` patch list, split by category and caller count |
| `<name>_global_hooks.txt` | Central entry points for custom ASM redirections |
| `<name>_thunks.txt` | Thunk hooks whose real target was not caught by Pass 1 |
| `<name>_tracer.txt` | *(Optional)* All targets in a single file for binary search in PCSX2 |

---

## Usage Instructions

1. Load the PS2 ELF in Ghidra with the Emotion Engine processor addon and run the script.
2. Choose auto-detect or manually enter the Gameplay and Menu Main Loop addresses.
3. Optionally provide a FrameRate Nexus address — either a VSync instruction (code) or a global frame counter variable (data). Press Cancel to skip.
4. Choose an output file path and whether to generate a Tracer Bullets file.
5. Wait for the two-pass scan to complete.
6. Open the generated `.txt` file. Take a batch of codes from one category/score group at a time.
7. Load them into PCSX2 alongside a Save State at the problematic moment.
8. Observe what breaks. Broken animations, disappearing objects, camera shake, or cutscene failures all indicate you've found a frame-rate-coupled function.
9. Use binary search (disable half the codes, retest, repeat) to isolate the exact function.
10. Navigate to the address in Ghidra and analyze or decompile the function to write a proper 60FPS fix. AI assistance with the decompiled output is recommended.

---

## STATE_MACHINES Warning

The output file separates `STATE_MACHINES` into a dedicated section with a warning. If the game softlocks after patching, change the delay slot word from `0000102D` (`move v0,zero`) to `24020001` (`li v0,1`) to return `TRUE` instead of `NULL`.

---

## Notes

1. **THUNKS** exist to handle Ghidra's occasional failure to resolve indirect vtable calls. They may be relevant to various issues but are less likely to contain the primary frame-rate coupling.
2. **Global Hook Points** (`_global_hooks.txt`) are entry points for writing custom ASM, **not** for bulk NOPing. Loading many of these as `jr ra` patches will likely crash the game. Use them only once you know exactly what a function does.
3. The script cannot guarantee zero crash-inducing patches, but in testing, crash-causing codes are rare (typically fewer than 2 per category group). It also cannot guarantee it will find every frame-coupled function — but in practice it narrows the search to roughly 25% of total JAL instructions in the binary.
4. The Tracer Bullets file (`_tracer.txt`) is designed for rapid binary search: disable half at a time in PCSX2 until the crash disappears.

---

*Developed for the PS2 Modding Community. Tested on PS2 MIPS EE binaries.*
*Architecture: V11 Safety Core + V12 Binary Profiling + V13 EE Specifics + V13 Final.*
*@author Gemini + Claude + Puggsy*
