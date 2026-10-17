import sys
import math
import struct
import argparse
import subprocess
from pathlib import Path
from collections import Counter

skip_list = {
    "amsi.dll", "wldp.dll", "clrjit.dll", "ntdll.dll",
    "kernelbase.dll", "kernel32.dll", "advapi32.dll", "user32.dll",
    "combase.dll", "sechost.dll", "msvcrt.dll", "efswrt.dll",
    "mfperfhelper.dll", "win32u.dll", "gdi32.dll", "gdi32full.dll",
    "imm32.dll",
}

def parse_pe(data):
    try:
        if data[:2] != b'MZ':
            return None
        e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
        if data[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
            return None

        machine      = struct.unpack_from('<H', data, e_lfanew + 4)[0]
        num_sections = struct.unpack_from('<H', data, e_lfanew + 6)[0]
        opt_hdr_size = struct.unpack_from('<H', data, e_lfanew + 20)[0]

        if machine != 0x8664:
            return None

        opt_offset = e_lfanew + 24
        image_size = struct.unpack_from('<I', data, opt_offset + 56)[0]
        sec_offset = e_lfanew + 24 + opt_hdr_size

        sections = []
        for i in range(num_sections):
            s = sec_offset + i * 40
            sections.append({
                'name':         data[s:s+8].rstrip(b'\x00').decode('ascii', errors='replace'),
                'virtual_size': struct.unpack_from('<I', data, s + 8)[0],
                'virtual_addr': struct.unpack_from('<I', data, s + 12)[0],
                'raw_size':     struct.unpack_from('<I', data, s + 16)[0],
                'raw_offset':   struct.unpack_from('<I', data, s + 20)[0],
            })

        return {'image_size': image_size, 'sections': sections}
    except Exception:
        return None


def calc_entropy(data, section):
    try:
        raw = data[section['raw_offset']:section['raw_offset'] + section['raw_size']]
        if not raw:
            return 0.0
        counts = Counter(raw)
        total = len(raw)
        return round(-sum((c/total) * math.log2(c/total) for c in counts.values()), 3)
    except Exception:
        return 0.0


def get_proc_dlls(proc_name):
    loaded = set()
    try:
        out = subprocess.run(
            ['tasklist', '/m', '/fi', f'imagename eq {proc_name}'],
            capture_output=True, text=True, timeout=10
        ).stdout
        for line in out.splitlines():
            for part in line.strip().split(','):
                part = part.strip().lower()
                if part.endswith('.dll'):
                    loaded.add(part)
    except Exception:
        pass
    return loaded


def hunt(system32, min_size, proc_name, verbose):
    proc_dlls = set()
    if proc_name:
        proc_dlls = get_proc_dlls(proc_name)
        if proc_dlls:
            print(f"[*] {len(proc_dlls)} DLLs found in {proc_name}")
        else:
            print(f"[!] {proc_name} not running or could not enumerate  proc filter skipped")

    dlls = list(system32.glob('*.dll'))
    print(f"[*] Scanning {len(dlls)} DLLs\n")

    results = []
    for dll_path in sorted(dlls):
        name = dll_path.name.lower()

        if name in skip_list:
            if verbose: print(f"  [-] blacklisted:   {name}")
            continue

        if proc_dlls and name not in proc_dlls:
            if verbose: print(f"  [-] not in proc:   {name}")
            continue

        try:
            data = dll_path.read_bytes()
        except Exception as e:
            if verbose: print(f"  [-] read error:    {name} ({e})")
            continue

        pe = parse_pe(data)
        if not pe:
            continue

        text = next((s for s in pe['sections'] if s['name'] == '.text'), None)
        if not text:
            if verbose: print(f"  [-] no .text:      {name}")
            continue

        if text['virtual_size'] < min_size:
            if verbose: print(f"  [-] too small:     {name} ({text['virtual_size']:,})")
            continue

        results.append({
            'name':      name,
            'text_size': text['virtual_size'],
            'img_size':  pe['image_size'],
            'sections':  len(pe['sections']),
            'entropy':   calc_entropy(data, text),
            'loaded':    name in proc_dlls if proc_dlls else None,
        })

    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--min-size',       type=int, default=150_000)
    ap.add_argument('--proc',           type=str, default='notepad.exe')
    ap.add_argument('--system32',       type=str, default=r'C:\Windows\System32')
    ap.add_argument('--top',            type=int, default=20)
    ap.add_argument('--verbose',        action='store_true')
    ap.add_argument('--no-proc-filter', action='store_true')
    args = ap.parse_args()

    s32 = Path(args.system32)
    if not s32.exists():
        print(f"[!] path not found: {s32}")
        sys.exit(1)

    proc = None if args.no_proc_filter else args.proc

    print(f"[*] min .text size: {args.min_size:,}")
    print(f"[*] proc filter:    {proc or 'off'}")
    print(f"[*] skip list:      {len(skip_list)} entries\n")

    results = hunt(s32, args.min_size, proc, args.verbose)

    if not results:
        print("[!] nothing found  try --no-proc-filter or lower --min-size")
        return

    results.sort(key=lambda x: x['text_size'], reverse=True)

    print(f"\n{'='*72}")
    print(f"{'dll':<32} {'text size':>10} {'entropy':>8} {'secs':>5} {'loaded':>7}")
    print(f"{'='*72}")

    for r in results[:args.top]:
        loaded_str   = 'yes' if r['loaded'] else ('no' if r['loaded'] is False else '?')
        entropy_flag = ' !' if r['entropy'] > 6.8 else '  '
        print(f"{r['name']:<32} {r['text_size']:>10,} {r['entropy']:>7.3f}{entropy_flag} {r['sections']:>5} {loaded_str:>7}")

    print(f"{'='*72}")
    print(f"\n[+] {len(results)} candidates")

    picks = [r for r in results if r['entropy'] < 6.5][:5]
    if picks:
        print("\n[*] recommendations:")
        for i, r in enumerate(picks, 1):
            note = " (in proc)" if r['loaded'] else ""
            print(f"  {i}. {r['name']:<32} .text={r['text_size']:,}  entropy={r['entropy']}{note}")
        print(f'\n  #define STOMP_DLL L"{picks[0]["name"]}"')


if __name__ == '__main__':
    main()
