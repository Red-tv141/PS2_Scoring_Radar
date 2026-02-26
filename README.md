# PS2 Scoring Radar: Advanced Static Analysis for 60FPS Patching

## Overview

**PS2 Scoring Radar** is an advanced, automated Ghidra script designed specifically to assist in creating 60FPS patches for PlayStation 2 games. 

Finding the correct instructions to NOP (zero out) in order to decouple game logic from the frame rate is a tedious manual process. This script automates that process by acting as a highly specialized static analysis engine. It scans the entire PS2 game binary, evaluates every `jal` (Jump and Link) instruction against a rigorous set of architectural rules, and outputs a ranked, ready-to-use `.pnach` file. 

By intelligently classifying functions and prioritizing safety, PS2 Scoring Radar significantly reduces the trial-and-error traditionally required in PS2 modding. 

## Key Features

* **Topology-Based Auto-Detection:** Automatically identifies Main Loop and Menu Loop candidates even in stripped binaries by analyzing instruction count, call breadth, internal loops (back-edges), frame heartbeats (BeginFrame/EndFrame), and hierarchy tiering. 


* **Multi-Layered Safety Firewalls:** Prevents crashes before they happen by blocking:
* *Static Libraries:* Ignores Sony SDK (e.g., `sceCd`, `scePad`) and standard libc functions. 
* *IOP Modules:* Filters out I/O Processor calls (e.g., `cdvdman`, `padman`). 
* *Dependency Bouncer:* The ultimate safeguard—blocks any JAL if its return value (like `v0` or `f0`) is read by subsequent instructions. 

* **Advanced DNA Classification:** Sorts safe patches into 7 actionable categories (e.g., Vectors & Physics, Timers, Animation Modifiers) based on FPU usage, branch density, and hardware signatures (COP1/COP2). 

* **Sniper Pattern Hunters:** Applies bonus scores based on specific coding patterns common in PS2 development:
* *Euler Hunter:* Detects Vector Scaling followed by Vector Addition. 
* *Kinematic Hunter:* Traces trigonometric data flows (`sinf`/`cosf`). 
* *Animation Hunter:* Isolates functions accepting float parameters (time/speed) that don't rely on VU0. 
* *Struct/Global Writers:* Prioritizes functions that mutate global state rather than local pointers. 
* **Global Hook Points Extraction:** Identifies "Pure Math" functions (like Matrix Multiply) that are unsafe to NOP individually. Instead of NOPing callers and causing invisible geometry, it provides the target entry points so you can patch them once globally. 
* **High Performance:** Extensively caches expensive Ghidra P-Code decompilations and trait extractions to process tens of thousands of JALs efficiently. 

## How It Works

The radar processes the binary through a strict pipeline:

1. **Firewalls:** Immediately discards system, IO, and dependency-critical calls. 
2. **Thunk Resolution:** Manually resolves bare `j` wrappers that Ghidra might misinterpret, ensuring accurate analysis of the true target. 
3. **Base Scoring:** Evaluates the JAL across 5 layers (DNA type, Kill Zone depth, Address safety, Tree depth, and FrameRate Nexus connection). 
4. **Pattern Hunting:** Modifies the score based on advanced heuristic modules (Euler, Kinematic, etc.). 
5. **Output:** Generates a ranked `.pnach` file formatted for immediate testing in PCSX2. 


## Usage Instructions

1. Load ps2 elf file in Ghidra with the Emotion Engine addon and run my script.
2. The game will ask if you want to automatically find the game's mainloop or manually add it. It will also ask for the address responsible for the frame rate (you can choose cancel and the script will keep working)
3. Wait for the script to finish and save the text file it outputs.
4. Grab a batch of codes based on category and score from the generated file.
5. Load them into PCSX2 along with a Save State right at the problematic moment in the game.
6. Observe what happens. Because you just NOP'd these functions, some changes will occur. If you can't test if there is a change in the thing you want to fix, just use a binary search method (turn off half the code, check again, and repeat) until you isolate the exact single function responsible for the issue.
7. Once you can test the game with the codes, look for changes. If you see things that were previously affected by the 60fps patch stop working like: animations might completely stop, an object might disappear the moment it's thrown, a specific cutscene might break, or the game camera might start shaking ect...
It means you've hit the right target! use binary search method again, this time for finding the code of the function we will need to fix for the 60fps.
8. Go to the address in Ghidra. From there, you can properly analyze the function and fix it for 60FPS (You can send the decomp and assembly to an AI for help)

## Output Categories

The generated `.pnach` organizes patches into the following sections:
* **1 — VECTORS & PHYSICS:** VU0 coprocessor calls and kinematic updates. 
* **2 — TIMERS & TICKERS:** Frame counters and tick logic. 
* **3 — ENTITY STATE MACHINES:** AI and general logic dispatchers. 
* **4 — GLOBAL MACRO SCRIPTS:** Cutscene and major event managers. 
* **5 — ANIMATION MODIFIERS:** Functions adjusting animation speed. 
* **6 — THUNKS:** Indirect calls resolved through wrappers. 
* **GLOBAL HOOK POINTS:** Target entry points for writing custom assembly hooks. 

---

Developed for the PS2 Modding Community. Tested on PS2 MIPS EE binaries. 

---
