import subprocess
import os

try:
    import idc, idaapi, idautils
    is_ida = True
except ImportError:
    is_ida = False

class AddSym:

    def __init__(self, 
                 inp_name,
                 out_name=None,
                 sections=['.text', '.rodata', '.data', '.bss']):
        self.symbols = {}
        self.inp_name = inp_name
        self.out_name = out_name
        self.sections = sections

    def objcopy(self):
        cmd = ['objcopy', self.inp_name]
        if self.out_name is not None:
            cmd.append(self.out_name)
        for symbol, (section, offset, type) in self.symbols.items():
            cmd.append('--add-symbol')
            cmd.append('{}={}:{},{},global'.format(symbol,
                                                    section,
                                                    offset,
                                                    type))
        p = subprocess.Popen(cmd, stderr=subprocess.PIPE)
        err_msg = p.communicate()[1].strip()
        err = p.wait()
        return err, err_msg

    def load_symbols_from_ida(self):
        for ea, name in idautils.Names():
            flag = idc.GetFlags(ea)
            if not idc.hasUserName(flag):
                continue
            seg_ea = idc.SegStart(ea)
            seg_name = idc.SegName(ea)
            if seg_name not in self.sections:
                continue
            sym_type = 'function' if idc.isCode(flag) else 'object'
            self.symbols[name] = (seg_name, ea - seg_ea, sym_type)

    def run(self):
        self.load_symbols_from_ida()
        err, err_msg = self.objcopy()
        return err, err_msg


if is_ida:
    inp_file = idc.GetInputFilePath()
    if not os.path.isfile(inp_file):
        inp_file = idc.AskFile(0, '', 'Input ELF file')
    out_file = idc.AskFile(1, '', 'Output file')
    a = AddSym(inp_file, out_file)
    err, err_msg = a.run()
    if err != 0:
        idc.Warning(err_msg)
        if out_file != inp_file:
            os.remove(out_file)
    else:
        idc.Message('Saved to {}\n'.format(out_file))
