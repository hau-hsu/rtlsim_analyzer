#!/usr/bin/env python3
"""
To test with doctest:
$ python3 -m doctest rtlsim_analyzer.py
"""

import sys
import re
import argparse
from subprocess import run, PIPE
from shlex import split
from collections import defaultdict
import logging
import json

HEX_CHAR = r'[0-9a-fA-f]'

class RangeDict(dict):
    """The key of the dict is a range. For example:
    >>> age = RangeDict()
    >>> age[(0, 12)] = 'child'
    >>> age[(12, 18)] = 'teenager'
    >>> age[(18, 200)] = 'adult'
    >>> age[10]
    'child'
    """
    def __getitem__(self, item):
        if not (isinstance(item, tuple) and len(item) == 2):
            for key in self:
                if key[0] <= item <= key[1] :
                    return self[key]
            raise KeyError(item)

        return super().__getitem__(item)


def process_elf(objdump, elf_file):
    "Get function address ranges form ELF."
    disasm_cmd = split(f"{objdump} -d {elf_file}")
    asm = run(disasm_cmd, check=True, stdout=PIPE,
              universal_newlines=True).stdout
    asm = asm.split('\n')
    return parse_funcs(asm)


def parse_funcs(asm):
    """Parse functions from disassembled strings.
    Example:
    >>> asm = []
    >>> asm += ['00000000000100b0 <register_fini>:'         ]
    >>> asm += ['100b0:	00000793       	li	    a5,0'       ]
    >>> asm += ['100b4:	c791        	beqz	a5,100c0'   ]
    >>> asm += ['100b6:	00000517       	auipc	a0,0x0'     ]
    >>> asm = iter(asm)
    >>> parse_funcs(asm)
    {(65712, 65718): 'register_fini'}
    """

    asm = iter(asm)
    addr2func = RangeDict()
    re_func_begin = re.compile(fr'^{HEX_CHAR}+ <(?P<func>.+)>:')
    for line in asm:
        line = line.strip()
        match = re_func_begin.match(line)
        if match:
            func = match.group('func')
            range_ = parse_addr_range(asm)
            addr2func[range_] = func

    return addr2func


def parse_addr_range(asm):
    """Parse functions from disassembled strings.

    Example:
    >>> asm = []
    >>> asm += ["125c8:	0005b383          	ld	t2,0(a1)"]
    >>> asm += ["125cc:	0085b283          	ld	t0,8(a1)"]
    >>> asm = iter(asm)
    >>> parse_addr_range(asm)
    (75208, 75212)
    """
    re_inst = re.compile(fr'\s*(?P<addr>{HEX_CHAR}+):.+')
    cur = next(asm).strip()
    match = re_inst.match(cur)
    if not match:
        print(f"Cannot parse the first line of function: {cur}")
        sys.exit(1)
    low_addr = int(match.group('addr'), 16)

    prev = cur
    for cur in asm:
        cur = cur.strip()
        if cur == '' or cur == '...':  # end of function
            break
        prev = cur

    match = re_inst.match(prev)
    high_addr = int(match.group('addr'), 16)
    return (low_addr, high_addr)


def analysis_rtlsim(logfile, addr2func):
    func_statistic = defaultdict(int)
    re_one_cycle = re.compile(fr'^C.+pc=\[(?P<pc>{HEX_CHAR}+?)\].+')
    with open(logfile) as log:
        for line in log:
            match = re_one_cycle.match(line)
            if match:
                pc = int(match.group('pc'), 16)
                try:
                    func = addr2func[pc]
                    func_statistic[func] += 1

                except KeyError:
                    logging.warning("Cannot decode address: %d", pc)

    return func_statistic



def main():
    """Main"""
    argparser = argparse.ArgumentParser()
    argparser.add_argument("elf_file", help="ELF file that runs rtlsim.")
    argparser.add_argument("rtlsim_log", help="Output log of rtlsim.")
    argparser.add_argument("--objdump", type=str,
            default='riscv64-unknown-elf-objdump',
            help="Path of `objdump` program.")

    args = argparser.parse_args()


    addr2func = process_elf(args.objdump, args.elf_file)
    #print(addr2func)
    func_cnt = analysis_rtlsim(args.rtlsim_log, addr2func)
    print(json.dumps(func_cnt, indent=4))



if __name__ == "__main__":
    main()
