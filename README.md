# kittydbg

A `gdbinit` configuration that uses [kitty](https://github.com/kovidgoyal/kitty) tiling to take better advantage of the empty space present in the pwndbg output.

Inspired by [pwnmux](https://github.com/joaogodinho/pwnmux) ([blog post](https://blog.jcfg.re/posts/pwndbg-tmux/)). 

# Installation
Requirements: pwndbg, gdb, kitty(v0.39.1+). Linux only.
```bash
git clone https://github.com/k4lizen/kittydbg.git
echo "source $PWD/kittydbg/gdbinit.py" >> ~/.gdbinit
```
Make sure that kittydbg is sourced *after* pwndbg is loaded.

In your kitty config you need:
```
allow_remote_control yes
enabled_layouts splits
```
you can have enabled layouts other than `splits`, but you need to be using
`splits` for kittydbg to spawn the windows correctly.

# Usage
Start pwndbg from kitty.
![image](https://github.com/user-attachments/assets/04e57a6d-710a-4bce-8d9c-af79cd2a3086)

It also works if pwndbg is started from a pwntools script, I use this in my scripts: 
```python
context.terminal = "kitten @ launch --location=before --cwd=current --bias=65".split()
```
![image](https://github.com/user-attachments/assets/056b99fd-146e-4330-b39f-ea36cd28fdbc)

Tbh I'm not sure if this is the best layout, if you fork this / make some adjustments please do share!
