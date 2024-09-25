---
title: "Router firmware extraction & ld based emulator development"
dateString: July 2024
draft: false
tags: ["firmware extraction", "userland emulator development"]
weight: 30
date: 2024-07-19
categories: ["ETC"]
# cover:
    # image: ""
---
# 계기
BoB 교육기간중에 갑자기 흥미가 생겨서 친구 라우터를 빼았고 UART에 땜질한다고 나대다가 부숴먹고 새로 구매했다.
# 시도
![](/blog/Router_firmware_extraction_emulator_dev/d8bb4b2a9229554347eb2855afa1ecc8.webp)
![](/blog/Router_firmware_extraction_emulator_dev/a87975743866efe4d20be0d6a6aa54d1.webp)
![](/blog/Router_firmware_extraction_emulator_dev/3effc797338abcfb5cb7fdba34942b56.png)
당연하지만 알리산 3천원 땜질기로는 제대로된 땜질을 할 수 없었고 이걸로 열심히 기판을 지지다 망가뜨렸다.
유튜브보고 대충 땜질을 배우고 알리에서 열풍기를 포함한 땜질 키트와 방진 마스크를 샀다.
열풍기 써보려고 테스트하다 또 하나 더 부숴먹었다.
납 발라놓고 열풍기로 조지니까 잘 달라붙는다.
# Firmware 추출
![](/blog/Router_firmware_extraction_emulator_dev/36a5a9b73016b9694c59a209fde8feda.png)
쿠팡에서 제일 위에 떠있는 라우터를 사왔다.
제일 기본적으로 디버깅 인터페이스부터 찾으려고 했다.
JTAG나 UART가 어디 없나 찾던중 UART를 찾은것 같았다.
![](/blog/Router_firmware_extraction_emulator_dev/e70dfc9eea62e071b233c4089fb3a392.png)
앞서 부숴먹은 라우터들의 경험을 바탕으로 열풍기를 잘 이용해가면서 USB to TTL을 손수 땜질을 했고, 시리얼 포트로 접속했다.
baudrate를 맞춰야해서 인터넷에서 자주 사용되는 baudrate를 하나 하나 손수 넣어보면서 제대로된 출력이 나올때까지 기다렸다.
```
Booting...
init_ram
bond:0x00000005
MCM 128MB

 dram_init_clk_frequency ,ddr_freq=1066 (Mbps), 533 (MHZ)

DRAM init disable

DRAM init enable

DRAM init is done , jump to DRAM
enable DRAM ODT

SDR init done dev_map=0xb8142000

Detect page_size = 2KB (3)

Detect bank_size = 8 banks(0x00000002)

Detect dram size = 128MB (0x08000000)

DDR init OK
init ddr ok

DRAM Type: DDR2
        DRAM frequency: 533MHz
        DRAM Size: 128MB
JEDEC id EF4018, EXT id 0x0000
found w25q128
flash vendor: Winbond
w25q128, size=16MB, erasesize=4KB, max_speed_hz=29000000Hz
auto_mode=0 addr_width=3 erase_opcode=0x00000020
Write PLL1=80c00042
=>CPU Wake-up interrupt happen! GISR=89000080

---Realtek RTL8197F-VG boot code at 2023.08.24-12:28+0900 v3.4.14.2 (999MHz)
bootbank is 1, bankmark 80000001, forced:0
no rootfs signature at 00330000!
```
이런식으로 부팅이 되는걸 UART로 볼 수 있었고, 정확한 맵인진 모르겠지만 다음과 같은 플래시 맵도 보였다
```
loop: module loaded
m25p80 spi0.0: change speed to 15000000Hz, div 7
JEDEC id EF4018
m25p80 spi0.0: found w25q128, expected m25p80
flash vendor: Winbond
m25p80 spi0.0: w25q128 (16384 Kbytes) (2;000000 Hz)
Creating 6 MTD partitions on "m25p80":
0x000000000000-0x000000340000 : "boot+cfg+linux(bank1)"
0x000000340000-0x000000800000 : "root fs(bank1)"
0x000000800000-0x000000b40000 : "linux(bank2)"
0x000000b40000-0x000001000000 : "root fs(bank2)"
0x000000fe0000-0x000001000000 : "flatfs"
0x000000000000-0x000001000000 : "all image"
tun: Universal TUN/TAP device driver, 1.6
tun: (C) 1999-2004 Max Krasnyansky <maxk@qualcomm.com>
PPP generic driver version 2.4.2
NET: Registered protocol family 24
MPPE/MPPC encryption/compression module registered
Realtek WLAN driver - version 3.8.0(2017-12-26)(SVN:)
Adaptivity function - version 9.7.07
Do MDIO_RESET
```
bootshell이 뜰거란 행복회로를 돌렸지만 어림도 없었고 일종의 매직키가 있나 싶어서 serial 포트에 연결해서 매직키 알려진 것들을 자동으로 막 보내는 스크립트도 열심히 작성했지만 아무것도 동작하지 않았다.
## SPI Dump
![](/blog/Router_firmware_extraction_emulator_dev/4e088581b3296acb9912b15270212d27.png)
이렇게 연결된다고 한다.
MISO, MOSI가 데이터 보내고 받는 핀이니 저렇게 연결했다.
![](/blog/Router_firmware_extraction_emulator_dev/5b0ba90f9fd2ef722bf278f42e95e876.png)
SPI flash를 읽는건 라즈베리파이에서도 지원하길래 데이터시트를 검색해서 그거대로 연결했다. 
![](/blog/Router_firmware_extraction_emulator_dev/44c564a1bb5ae4d41d9b842ca6efe50c.png)
![](/blog/Router_firmware_extraction_emulator_dev/7bfdf2b060a86a0a8a7c8993375c8bfc.png)
되었다가 안되었다가해서 핀을 계속 다시 연결했다.
![](/blog/Router_firmware_extraction_emulator_dev/26082494eb9adc301dbc0a1a8e0bd275.png)
![](/blog/Router_firmware_extraction_emulator_dev/e3a2e8caa6076bf934e6d81fa881f24a.png)
이대로 파이썬으로 간단하게 코드를 구현했지만 어림도 없었다.
![](/blog/Router_firmware_extraction_emulator_dev/07fe2c98611ae96416621e7fefec411a.png)
![](/blog/Router_firmware_extraction_emulator_dev/2e20026b1ecb5d27ebcce38fddbb1e4b.png)
그래서 다시 차근 차근 데이터시트를 읽어보고 실제로 세팅하지 않아도 되는 핀들이나 세팅해야하는 핀들을 세팅했다.

메뉴얼을 읽던 도중 CS를 Low로 내리고 instruction을 보낸뒤 High로 올리라고 되어있었는데 인터넷에서 찾은 예제 코드는 그러한 핸들링이 되어있지 않았다.
메뉴얼대로 SPI 통신 코드를 마저 작성했고 성공적으로 덤프했다.
신호가 약해 조금만 흔들려도 md5sum이 달랐기에 조금씩 잘라서 덤프하기 시작했다.
```python
#!/usr/bin/env python3

import gpiozero
import spidev
import time
import tqdm
import os

#winbond_reset = gpiozero.LED("GPIO0")
winbond_reset = gpiozero.OutputDevice("GPIO0")
#winbond_wp = gpiozero.LED("GPIO3")
winbond_wp = gpiozero.OutputDevice("GPIO3")
#spi_cs = gpiozero.LED("GPIO2")
spi_cs = gpiozero.OutputDevice("GPIO2")


winbond_reset.off()
winbond_wp.off()
spi_cs.on()

print("Starting up...")
time.sleep(1)

# Set /RESET high taking the Winbond out of reset state.
# Set /WP high to make the chip's memory writable.
winbond_reset.on()
winbond_wp.on()

spi = spidev.SpiDev()
spi.open(0, 0)
spi.mode = 0
spi.lsbfirst = False
spi.max_speed_hz = 1000000

spi_cs.off()
ids = spi.xfer2([ 0x90, 0x00, 0x00, 0x00, 0x00, 0x00 ])
spi_cs.on()

spi_cs.off()
status_1 = spi.xfer2([ 0x05, 0x00 ])
spi_cs.on()

spi_cs.off()

'''
loop: module loaded
m25p80 spi0.0: change speed to 15000000Hz, div 7
JEDEC id EF4018
m25p80 spi0.0: found w25q128, expected m25p80
flash vendor: Winbond
m25p80 spi0.0: w25q128 (16384 Kbytes) (2;000000 Hz)
Creating 6 MTD partitions on "m25p80":
0x000000000000-0x000000340000 : "boot+cfg+linux(bank1)"
0x000000340000-0x000000800000 : "root fs(bank1)"
0x000000800000-0x000000b40000 : "linux(bank2)"
0x000000b40000-0x000001000000 : "root fs(bank2)"
0x000000fe0000-0x000001000000 : "flatfs"
0x000000000000-0x000001000000 : "all image"
tun: Universal TUN/TAP device driver, 1.6
tun: (C) 1999-2004 Max Krasnyansky <maxk@qualcomm.com>
PPP generic driver version 2.4.2
NET: Registered protocol family 24
MPPE/MPPC encryption/compression module registered
Realtek WLAN driver - version 3.8.0(2017-12-26)(SVN:)
Adaptivity function - version 9.7.07
'''
data = spi.xfer2([ 0x0b]+[0]*3)
print([hex(x) for x in data[2:]])
spi_cs.on()

data = spi.xfer2([0x9f] + [0]*3)
print([hex(x) for x in data[2:]])

print("ids=" + str(ids))
print("status_1=" + str(status_1))
print("JEDEC_ID=" + str(data))

def dump(filename, address, size):
    if os.path.isfile(filename):
        os.remove(filename)
    f = open(filename,'ab')
    sz = 0x30
    for i in tqdm.tqdm(range(size//sz+sz)):
        it = i*sz + address
        addr = [(it>>16)&0xff, (it>>8)&0xff, (it)&0xff]
        spi_cs.off()
        data = spi.xfer3([ 0x03]+ addr + [0] *(sz))[4:] # first 4bytes invalid
        spi_cs.on()
        assert len(data) == sz
        f.write(bytes(data))
    f.close()
#dump('./boot.cfg.linux1',0 ,0x000000340000-0x000000000000)
#dump('./rootfs_bank1.1',0x000000340000,0x000000800000-0x000000340000)
#dump('./rootfs_bank2.2',0x000000b40000,0x000001000000 - 0x000000b40000)
#dump('./flatfs',0x000000fe0000,0x000001000000-0x000000fe0000)
dump('./linux_bank2',0x000000b40000,0x000000b40000-0x000000800000)


spi.close()
```

![](/blog/Router_firmware_extraction_emulator_dev/e7731d6c059a102555df55e83ba62741.png)
![](/blog/Router_firmware_extraction_emulator_dev/6039d0d9e42313d4b9de13f8b6bf4901.png)
![](/blog/Router_firmware_extraction_emulator_dev/992f148f2cc93b03e6f7d9b45a8cfe4b.png)
그래서 열심히 맵을 보고 같은 영역을 5번 정도씩 읽고 md5를 비교해서 같은 md5를 가진 파일들로 걸러냈다.
![](/blog/Router_firmware_extraction_emulator_dev/2b0a37deed96345530a1b730b6b40187.png)
init script를 분석해봤는데 cgi 바이너리를 돌리는 것을 확인했고 테스트를 해보려는데 생소한 라이브러리를 사용해서 qemu로 에뮬레이션하는데 실패했다.
그래서 뭔가 나중에 에뮬레이터 하나 만들어서 이거 돌려보면 재밌을것 같아서 미뤄두고 까먹고 있었다.
# Emulator 개발
bob가 끝나고 나중에 시간이 남아서 cgi 바이너리를 보면서 분석을 시작했다.
mips kernel을 빌드하고 직접 올려서 qemu로 에뮬레이션을 시도했지만 실패했다.
그래서 직접 에뮬레이터를 만들고자 하였다.
dynamic linked binary인데 어떻게 환경을 유사하게 맞출 수 있을까 고민을 하다가 기본적인 커널 로더만 구현하고 유저에선 ld-linux.so를 메모리에 올리고 잘 조건 맞추면 알아서 실행되지 않을까라고 생각했다.
나중에 크로스아키텍처 퍼징을 위해서 syscall도 후킹하듯이 대체해서 입력도 넣을 수 있고, 라이브러리도 그냥 후킹해서 속이면 편하게 할 수 있을 것이라고 생각해서 이를 구현하고자 하였다.

선행 연구들을 조금 찾아보았는데 이미 이런 아이디어를 가지고 파이썬으로 구현한 프로젝트가 있었다.
https://github.com/qilingframework/qiling
근데 이걸 퍼징할때도 쓰는것 같았다.
파이썬으로 구현된 에뮬레이터를 이용해서 퍼징을 돌리는 것 보다는 C가 훨씬 빠르니 바로 C로 구현을 시작했다.
열심히 메모리를 봐가면서 커널 로더가 어떤 동작을 수행하는지 분석했고 그대로 구현했다.

https://github.com/msh1307/N.2-EMUl
오랫동안 개발한 프로젝트는 아니라서 시스템콜도 일부만 지원되고 x86_64 아키텍처만 된다.
```c
> make test
gcc  -c src/main.c -o src/main.o
gcc  -c src/util.c -o src/util.o
gcc  -c src/elf.c -o src/elf.o
gcc  -c src/emul.c -o src/emul.o
gcc  -c src/syscalls.c -o src/syscalls.o
gcc  -c src/user_defined_hooks.c -o src/user_defined_hooks.o
gcc -o app.out ./src/main.o ./src/util.o ./src/elf.o ./src/emul.o ./src/syscalls.o ./src/user_defined_hooks.o -lunicorn -lpthread -lm -lelf -lcapstone
gcc  -c tests/test.c -o tests/test.o
gcc  tests/test.o -o test.out
./app.out ./test.out
[+] Loader path: /lib64/ld-linux-x86-64.so.2
[+] Entrypoint: 0x7ffff7fe3290
[+] Mapping Memory [0x7ffff7fc3000 ~ 0x7ffff7fc5000 (0x2000)] FileOffset=0x0 FLAGS=0x4
[+] Mapping Memory [0x7ffff7fc5000 ~ 0x7ffff7fef000 (0x2a000)] FileOffset=0x2000 FLAGS=0x5
[+] Mapping Memory [0x7ffff7fef000 ~ 0x7ffff7ffa000 (0xb000)] FileOffset=0x2c000 FLAGS=0x4
[+] Mapping Memory [0x7ffff7ffb000 ~ 0x7ffff7fff000 (0x4000)] FileOffset=0x37620 FLAGS=0x6
[+] Writing Memory [0x7ffff7fc3000 ~ 0x7ffff7fc4b50 (0x1b50)]
[+] Writing Memory [0x7ffff7fc5000 ~ 0x7ffff7fee315 (0x29315)]
[+] Writing Memory [0x7ffff7fef000 ~ 0x7ffff7ff9f34 (0xaf34)]
[+] Writing Memory [0x7ffff7ffb620 ~ 0x7ffff7ffe110 (0x2af0)]
[+] Entrypoint: 0x555555555060
[+] Mapping Memory [0x555555554000 ~ 0x555555555000 (0x1000)] FileOffset=0x0 FLAGS=0x4
[+] Mapping Memory [0x555555555000 ~ 0x555555556000 (0x1000)] FileOffset=0x1000 FLAGS=0x5
[+] Mapping Memory [0x555555556000 ~ 0x555555557000 (0x1000)] FileOffset=0x2000 FLAGS=0x4
[+] Mapping Memory [0x555555557000 ~ 0x555555559000 (0x2000)] FileOffset=0x2db8 FLAGS=0x6
[+] Writing Memory [0x555555554000 ~ 0x555555554628 (0x628)]
[+] Writing Memory [0x555555555000 ~ 0x555555555175 (0x175)]
[+] Writing Memory [0x555555556000 ~ 0x5555555560f4 (0xf4)]
[+] Writing Memory [0x555555557db8 ~ 0x555555558010 (0x258)]
[+] Mapping Stack  [0x7ffffffde000 ~ 0x7ffffffee000 (0x10000)]
[+] rsp = 0x7ffffffede50

0x0000000000000001 0x00007ffffffedfb2 
0x0000000000000000 0x0000000000000000 
0x0000000000000033 0x00000000000006f0 
0x0000000000000010 0x00000000078bfbfd 
0x0000000000000006 0x0000000000001000 
0x0000000000000011 0x0000000000000064 
0x0000000000000003 0x0000555555554040 
0x0000000000000004 0x0000000000000038 
0x0000000000000005 0x000000000000000d 
0x0000000000000007 0x00007ffff7fc3000 
0x0000000000000008 0x0000000000000000 
0x0000000000000009 0x0000555555555060 
0x000000000000000b 0x0000000000000000 
0x000000000000000c 0x0000000000000000 
0x000000000000000d 0x0000000000000000 
0x000000000000000e 0x0000000000000000 
0x0000000000000017 0x0000000000000000 
0x0000000000000019 0x00007ffffffedfbd 
0x000000000000001f 0x00007ffffffedfcd 
0x000000000000000f 0x00007ffffffedff1 
0x0000000000000000 0x0000000000000000 
0x0000000000000000 0x0000000000000000 
0x747365742f2e0000 0x4141410074756f2e 
0x4141414141414141 0x6f722f4141414141 
0x736b726f572f746f 0x322e4e2f65636170 
0x2f2e2f6c554d452d 0x74756f2e74736574 
0x0034365f36387800 0x0000000000000000 

[+] Running /root/Workspace/N.2-EMUl/./test.out
[+] emul: brk(0x0)
[+] emul: arch_prctl(0x3001, 0x7ffffffedc90)
[+] emul: sys_uname(0x7ffffffed870)
[-] emul: sys_access("/etc/ld.so.preload", 0x4) == 0xffffffffffffffff
[+] emul: sys_openat(0xffffff9c, "/etc/ld.so.cache", 0x80000, 0x0)
[+] emul: sys_newfstatat(0x3, "", 0x7ffffffecde0, 0x1000)
[+] emul: sys_mmap(0x0, 0x1115f, 0x1, 0x2, 0x3, 0x0) == 0x7ffff7fb1000
[+] emul: sys_close(0x3)
[+] emul: sys_openat(0xffffff9c, "/lib/x86_64-linux-gnu/libc.so.6", 0x80000, 0x0)
[+] emul: sys_read(0x4, 0x7ffffffed018, 0x340) == 0x340
[+] emul: sys_pread64(0x4, 0x7ffffffecc20, 0x310, 0x40) == 0x310
[+] emul: sys_pread64(0x4, 0x7ffffffecbe0, 0x30, 0x350) == 0x30
[+] emul: sys_pread64(0x4, 0x7ffffffecb90, 0x44, 0x380) == 0x44
[+] emul: sys_newfstatat(0x4, "", 0x7ffffffeceb0, 0x1000)
[+] emul: sys_pread64(0x4, 0x7ffffffecaf0, 0x310, 0x40) == 0x310
[+] emul: sys_mmap(0x0, 0x228e50, 0x1, 0x802, 0x4, 0x0) == 0x7ffff7d88000
[+] emul: sys_mprotect(0x7ffff7db0000, 0x1ee000, 0x0)
[+] emul: sys_mmap(0x7ffff7db0000, 0x195000, 0x5, 0x812, 0x4, 0x28000) == 0x7ffff7db0000
[+] emul: sys_mmap(0x7ffff7f45000, 0x58000, 0x1, 0x812, 0x4, 0x1bd000) == 0x7ffff7f45000
[+] emul: sys_mmap(0x7ffff7f9e000, 0x6000, 0x3, 0x812, 0x4, 0x215000) == 0x7ffff7f9e000
[+] emul: sys_mmap(0x7ffff7fa4000, 0xce50, 0x3, 0x32, 0xffffffff, 0x0) == 0x7ffff7fa4000
[+] emul: sys_close(0x4)
[+] emul: sys_mmap(0x0, 0x2000, 0x3, 0x22, 0xffffffff, 0x0) == 0x7ffff7d86000
[+] emul: arch_prctl(0x1002, 0x7ffff7d870c0)
[+] emul: sys_set_tid_address(0x7ffff7d87390)
[+] emul: sys_set_robust_list(0x7ffff7d873a0, 0x18)
[+] emul: sys_rseq(0x7ffff7d87a60, 0x20, 0x0)
[+] Hooked at 0x7ffff7fe688e
[+] RIP = 0x7ffff7fe6894
[+] Hooked at 0x7ffff7fe688e
[+] RIP = 0x7ffff7fe6894
[+] emul: sys_mprotect(0x7ffff7f9e000, 0x4000, 0x1)
[+] emul: sys_mprotect(0x555555557000, 0x1000, 0x1)
[+] emul: sys_mprotect(0x7ffff7ffb000, 0x2000, 0x1)
[+] emul: sys_prlimit64(0x0, 0x3, 0x0, 0x7ffffffed9f0)
[+] emul: UNIMPLEMENTED SYSCALL - syscall(rax=0xb, rdi=0x7ffff7fb1000, rsi=0x1115f, rdx=0x7ffff7e18c10)
[+] emul: sys_newfstatat(0x1, "", 0x7ffffffedbb0, 0x1000)
[+] emul: UNIMPLEMENTED SYSCALL - syscall(rax=0x13e, rdi=0x7ffff7fa94d8, rsi=0x8, rdx=0x1)
[+] emul: UNIMPLEMENTED SYSCALL - syscall(rax=0xe4, rdi=0x1, rsi=0x7ffffffedb40, rdx=0x1)
[+] emul: UNIMPLEMENTED SYSCALL - syscall(rax=0xe4, rdi=0x1, rsi=0x7ffffffedb40, rdx=0x1)
[+] emul: brk(0x0)
[+] emul: brk(0x55555557a000)
[+] emul: write(fd=0x1, buf=0x5555555592a0, count=0xd)
Hello World!
[+] emul: exit()
0.073835sec
```
