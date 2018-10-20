# AddSym

An ida python script that reads symbols from ida and adds them into an elf
binary. This similar to sym2elf. Unlike sym2elf, it uses objcopy
as backend instead of fiddling with elf library api.

# Requirements

`objcopy` is needed.

# Usage

Run the script in IDA pro.
