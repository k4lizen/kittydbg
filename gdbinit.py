import os
import atexit

import gdb
from pwndbg.commands.context import contextoutput

def path_from_id(id: int):
    return os.popen(f"kitten @ ls | jq -r '.[] | .tabs[].windows[] | select(.id == {id}) | .pid' | xargs -I{{}} ls -l /proc/{{}}/fd | grep pts | awk '{{print $NF}}' | uniq").read().strip()

panes = {}
main_section = os.popen("kitten @ ls | jq -r '.[].tabs[].windows[] | select(.is_self).id'").read().strip()
panes["disasm"] = os.popen('kitten @ launch --location=hsplit --cwd=current --bias=25 cat').read().strip()
# https://github.com/kovidgoyal/kitty/issues/4216
os.popen("kitten @ action layout_action rotate 180").read()
panes["stack"] = os.popen("kitten @ launch --location=hsplit --cwd=current --bias=40 cat").read().strip()
panes["backtrace"] = os.popen("kitten @ launch --location=after --cwd=current --bias=30 cat").read().strip()
os.popen(f"kitten @ focus-window --match id:{panes["disasm"]}").read()
panes["regs"] = os.popen("kitten @ launch --location=after --cwd=current --bias=30 cat").read().strip()
os.popen(f"kitten @ focus-window --match id:{main_section}").read()
panes["python"] = os.popen("kitten @ launch --location=after --cwd=current --bias=30 python").read().strip()
os.popen(f"kitten @ focus-window --match id:{main_section}").read()

panes_paths = {}
for sec in panes:
    panes_paths[sec] = path_from_id(panes[sec]) 

# Tell pwndbg which panes are to be used for what
for section, id in panes.items():
    contextoutput(section, panes_paths[section], False, 'top', None)

# Also add the sections legend and expressions to already existing panes
contextoutput("legend", panes['stack'], None)
contextoutput("expressions", panes_paths['regs'], False, 'top', None)
contextoutput("code", panes_paths["disasm"], False, 'top', None)

# To see more options to customize run `theme` and `config` in gdb
# Increase the amount of lines shown in disasm and stack
gdb.execute("set context-disasm-lines 25")
gdb.execute("set context-stack-lines 18")
# Give backtrace a little more color
gdb.execute("set backtrace-prefix-color red,bold")
gdb.execute("set backtrace-address-color gray")
gdb.execute("set backtrace-symbol-color red")
gdb.execute("set backtrace-frame-label-color green")
# Remove the panes when gdb is exited
atexit.register(lambda: [os.popen(F"kitten @ close-window --match id:{id}").read() for id in panes.values()])
