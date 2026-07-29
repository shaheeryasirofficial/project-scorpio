# dll_hunter.py
 
Scans System32 for viable module stomping targets. Filters by .text section size, entropy, and whether the DLL is actually loaded by your decoy process. Skips anything that's on the known-monitored list or will crash the host on stomp.
 
## Usage
 
```
python3 dll_hunter.py
python3 dll_hunter.py --proc notepad.exe --min-size 150000
python3 dll_hunter.py --no-proc-filter --min-size 100000 --verbose
```
 
## Options
 
| Flag | Default | What it does |
|---|---|---|
| `--min-size` | 150000 | Minimum .text section size in bytes must exceed your shellcode size |
| `--proc` | notepad.exe | Filter to DLLs actually loaded by this process |
| `--system32` | C:\Windows\System32 | Path to scan |
| `--top` | 20 | How many results to show |
| `--verbose` | off | Show why each DLL was skipped |
| `--no-proc-filter` | off | Scan everything, ignore proc filter |
 
## Output
 
Prints a ranked table sorted by .text size. Flags high-entropy entries with `!` those are packed or encrypted and should be avoided. Bottom of output gives top 5 picks and a ready-to-paste `#define` for the loader.
 
## Notes
 
Lower `--min-size` if nothing comes back — typical Adaptix beacon is 100-150KB so 150000 is a safe floor. If the decoy process isn't running when you execute the script the proc filter silently falls back to scanning everything.
 
