# 상준이가 숙제 줌#3

아래의 코드를 실행하는 기계어 코드를 제작하라

```c
creat("FLAG",0);
chmod("FLAG",440);
exit(0);
```
※ 64bit 환경에서 동작하는 기계어도 만들어 봐라

---

[64bit syscall number는 여기를 참고 했다](http://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/)  

그리고 검색을 하던 중 x86 과 x86-64의 syscall number가 왜 다른지도 알게되었다.
[링크는 여기](https://unix.stackexchange.com/questions/338650/why-are-linux-system-call-numbers-in-x86-and-x86-64-different)

위의 링크에서 필요한 내용을 표로 정리하면 다음과 같다.

| %rax | system call | %rdi | %rsi |
|:--------:|:--------:|:--------:|:--------:|
|85 (0x55)| sys_creat | const char *pathname | int mode |
|90 (0x5A)| sys_chmod | const char *filename | mode_t mode |
|60 (0x3c)| sys_exit | int error_code | NONE |

64bit calling convention을 생각해보자면 %rdi, %rsi, %rdx, %rcx 순서로 인자가 채워진다.

그리고 systemcall number는 %rax 레지스터에 저장된다.

저번 32bit와 똑같은 소스코드를 64bit로 static 컴파일 한 다음 gdb로 열어보자.

```c
int main()
{
  creat("FLAG",0);
  chmod("FLAG",445);
  exit(0);
}
//-fno-stack-protector -zexecstack -static
```

```
pwndbg> disassemble main
Dump of assembler code for function main:
   0x00000000004009ae <+0>:	push   rbp
   0x00000000004009af <+1>:	mov    rbp,rsp
   0x00000000004009b2 <+4>:	mov    esi,0x0
   0x00000000004009b7 <+9>:	mov    edi,0x4a0f64
   0x00000000004009bc <+14>:	mov    eax,0x0
   0x00000000004009c1 <+19>:	call   0x43f410 <creat64>
   0x00000000004009c6 <+24>:	mov    esi,0x1c7
   0x00000000004009cb <+29>:	mov    edi,0x4a0f64
   0x00000000004009d0 <+34>:	mov    eax,0x0
   0x00000000004009d5 <+39>:	call   0x43f140 <chmod>
   0x00000000004009da <+44>:	mov    edi,0x0
   0x00000000004009df <+49>:	call   0x40ea10 <exit>
End of assembler dump.
pwndbg>
```
이제 한눈에 보인다.
```
0x00000000004009b2 <+4>:	mov    esi,0x0
0x00000000004009b7 <+9>:	mov    edi,0x4a0f64
0x00000000004009bc <+14>:	mov    eax,0x0
0x00000000004009c1 <+19>:	call   0x43f410 <creat64>
```
먼저 creat 함수의 두 번째 인자인 0을 세팅한다.

그리고 두 번째 인자로 들어가는 0x4a0f64는 "FLAG" 일 것이다.

마지막으로 eax 0x0을 통해 최적화를 하고 creat64함수를 호출한다.

```
0x00000000004009c6 <+24>:	mov    esi,0x1bd
0x00000000004009cb <+29>:	mov    edi,0x4a0f64
0x00000000004009d0 <+34>:	mov    eax,0x0
0x00000000004009d5 <+39>:	call   0x43f140 <chmod>
```
마찬가지로 두 번째 인자인 445(0x1bd)를 세팅하고

첫 번재 인자인 "FLAG"를 세팅한 다음 chmod 함수를 호출한다.

이제 Assembly를 이용해서 두 함수를 만들어 보자.

```asm
.global main

main:
        call func
        .string "FLAG"

func:
        mov $0x55, %rax
        pop %rdi
        mov $0x00, %rsi
        syscall

        mov $0x5a, %rax
        push %rdi
        mov $0x125, %rsi
        syscall

        mov $0x3c, %rax
        mov $0x00, %rdi
        syscall
```

컴파일 하고 정상적으로 잘 동작하는지 확인해보자.

```
secretpack@ubuntu:~/Desktop/shellcode/ndr$ gcc -fno-stack-protector -zexecstack -o ass ass.s
secretpack@ubuntu:~/Desktop/shellcode/ndr$ ./ass
secretpack@ubuntu:~/Desktop/shellcode/ndr$ ls -al
total 924
drwxrwxr-x 2 secretpack secretpack   4096 Dec  8 23:34 .
drwxrwxr-x 3 secretpack secretpack   4096 Dec  8 23:32 ..
-rwxrwxr-x 1 secretpack secretpack   8592 Dec  8 23:34 ass
-rw-rw-r-- 1 secretpack secretpack    211 Dec  8 23:34 ass.s
-r--r--r-x 1 secretpack secretpack      0 Dec  8 23:31 FLAG
-rw------- 1 secretpack secretpack    261 Dec  8 23:14 .gdb_history
-rwxrwxr-x 1 secretpack secretpack 912768 Dec  8 23:15 sc64
-rw-rw-r-- 1 secretpack secretpack     63 Dec  8 23:15 sc64.c
```

정상적으로 잘 동작한다 이제 objdump 를 사용하여 바이너리를 열어보자.

```
00000000004004d6 <main>:
  4004d6:	e8 05 00 00 00       	callq  4004e0 <func>
  4004db:	46                   	rex.RX
  4004dc:	4c                   	rex.WR
  4004dd:	41                   	rex.B
  4004de:	47                   	rex.RXB
	...

00000000004004e0 <func>:
  4004e0:	48 c7 c0 55 00 00 00 	mov    $0x55,%rax
  4004e7:	5f                   	pop    %rdi
  4004e8:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
  4004ef:	0f 05                	syscall
  4004f1:	48 c7 c0 5a 00 00 00 	mov    $0x5a,%rax
  4004f8:	57                   	push   %rdi
  4004f9:	48 c7 c6 25 01 00 00 	mov    $0x125,%rsi
  400500:	0f 05                	syscall
  400502:	48 c7 c0 3c 00 00 00 	mov    $0x3c,%rax
  400509:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
  400510:	0f 05                	syscall
```

이제 저 기계어 코드를 순서대로 연결해서 테스트 해보자.

```c
int main()
{
        char *code = "\xe8\x05\x00\x00\x00\x46\x4c\x41\x47\x48\xc7\xc0\x55\x00\x00\x00\x5f\x48\xc7\xc6\x00\x00\x00\x00\x0f\x05\x48\xc7\xc0\x5a\x00\x00\x00\x57\x48\xc7\xc6\x25\x01\x00\x00\x0f\x05\x48\xc7\xc0\x3c\x00\x00\x00\x48\xc7\xc7\x00\x00\x00\x00\x0f\x05"

        void (*ptr)(void);

        ptr = (void *)code;

        ptr();
}
```
```
secretpack@ubuntu:~/Desktop/shellcode/ndr$ ./test
secretpack@ubuntu:~/Desktop/shellcode/ndr$ ls
ass  ass.s FLAGH??U  sc64  sc64.c  test  test.c
```
오잉 파일이름이 이상하다..

FLAG 문자열을 의미하는 \x46\x4c\x41\x47뒤에 널바이트인 \x00을 붙이고 다시 해봤다.

```
secretpack@ubuntu:~/Desktop/shellcode/ndr$ ./test
secretpack@ubuntu:~/Desktop/shellcode/ndr$ ls
ass  ass.s  FLAG  sc64  sc64.c  test  test.c
```

정상적으로 동작한다.
