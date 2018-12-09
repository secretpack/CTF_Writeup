# 상준이가 숙제 줌#2

아래의 코드를 실행하는 기계어 코드를 제작하라

```c
creat("FLAG",0);
chmod("FLAG",440);
exit(0);

※creat 함수를 create 로 써서 줬는데 햇갈렸다.
```
---

앞에서 공부한 내용을 토대로 직접 만들어 보자.

하기에 앞서 unistd.h에서 위 함수들의 system call number를 찾아보자.
```c
#define __NR_setup	0	/* used only by init, to get system going */
#define __NR_exit	1
#define __NR_fork	2
#define __NR_read	3
#define __NR_write	4
#define __NR_open	5
#define __NR_close	6
#define __NR_waitpid	7
#define __NR_creat	8
#define __NR_link	9
#define __NR_unlink	10
#define __NR_execve	11
#define __NR_chdir	12
#define __NR_time	13
#define __NR_mknod	14
#define __NR_chmod	15
#define __NR_chown	16
#define __NR_break	17
#define __NR_stat	18
#define __NR_lseek	19
```

* creat system call : 8
* chmod system call : 15
* exit system call : 1

먼저 C 코드로 작성하고 컴파일 하자.
```c
int main()
{
  creat("FLAG",0);
  chmod("FLAG",440);
  exit(0);
}

//-fno-stack-protector -mpreferred-stack-boundary=2 -zexecstack -static -m32
```

creat 함수를 disassemble 하여 확인해보자
```
0x0806d26c <+2>:	mov    0x8(%esp),%ecx
0x0806d270 <+6>:	mov    0x4(%esp),%ebx
0x0806d274 <+10>:	mov    $0x8,%eax
0x0806d279 <+15>:	call   *0x80ea9f0
```

* call : cd 80
* eax : system call number(0x8)
* ebx : "FLAG"
* ecx : 0

```
0x0806d012 <+2>:	mov    0x8(%esp),%ecx
0x0806d016 <+6>:	mov    0x4(%esp),%ebx
0x0806d01a <+10>:	mov    $0xf,%eax
0x0806d01f <+15>:	call   *0x80ea9f0
```
* call : cd 80
* eax : system call number(0xf)
* ebx : "FLAG"
* ecx : 445

저렇게 들어가야 한다. 이제 어셈블리로 구현해보자.

```asm
.globl main
main:
        call func
        .string "FLAG"

func:
        movl $0x08, %eax
        popl %ebx
        movl $0x00, %ecx
        int $0x80

        movl $0x0f, %eax
        push %ebx
        movl $0x125 %ecx
        int $0x80
        
        movl $0x01, %eax
        movl $0x00, %ebx
        int $0x80

-fno-stack-protector -mpreferred-stack-boundary=2 -zexecstack -m32
```
chmod 는 8진수를 인자로 받으므로 455o 의 값인 0x125를 넣어줘야 한다.

그리고 creat 함수를 어셈블리로 구현하면서 스택에 있는 값을 pop 했으므로

다시 push 명령어로 집어 넣어 주면 된다.


만들어진 파일을 objdump로 열어보자.

```
080483db <main>:
 80483db:	e8 0a 00 00 00       	call   80483ea <func>
 80483e0:	46                   	inc    %esi
 80483e1:	4c                   	dec    %esp
 80483e2:	41                   	inc    %ecx
 80483e3:	47                   	inc    %edi
 80483e4:	00 46 4c             	add    %al,0x4c(%esi)
 80483e7:	41                   	inc    %ecx
 80483e8:	47                   	inc    %edi
	...

080483ea <func>:
 80483ea:	b8 08 00 00 00       	mov    $0x8,%eax
 80483ef:	5b                   	pop    %ebx
 80483f0:	b9 00 00 00 00       	mov    $0x0,%ecx
 80483f5:	cd 80                	int    $0x80
 80483f7:	b8 0f 00 00 00       	mov    $0xf,%eax
 80483fc:	53                   	push   %ebx
 80483fd:	b9 25 01 00 00       	mov    $0x125,%ecx
 8048402:	cd 80                	int    $0x80
 8048404:	b8 01 00 00 00       	mov    $0x1,%eax
 8048409:	bb 00 00 00 00       	mov    $0x0,%ebx
 804840e:	cd 80                	int    $0x80
```

```c
int main()
{
        char *code = "\xe8\x0a\x00\x00\x00\x46\x4c\x41\x47\x00\xb8\x08\x00\x00\x00\x5b\xb9\x00\x00\x00\x00\xcd\x80\xb8\x0f\x00\x00\x00\x53\xb9\x25\x01\x00\x00\xcd\x80\xb8\x01\x00\x00\x00\xbb\x00\x00\x00\x00\xcd\x80"

        void (*ptr)(void);

        ptr = (void *)code;

        ptr();
}
```

```
secretpack@ubuntu:~/Desktop/shellcode$ ls -al
total 1504
drwxrwxr-x 2 secretpack secretpack   4096 Dec  8 10:07 .
drwxr-xr-x 8 secretpack secretpack   4096 Dec  7 08:34 ..
-rwxrwxr-x 1 secretpack secretpack   7316 Dec  8 07:00 codtest
-rw-rw-r-- 1 secretpack secretpack    250 Dec  8 07:00 codtest.c
-r--r--r-x 1 secretpack secretpack      0 Dec  8 10:07 FLAG
-rw------- 1 secretpack secretpack    952 Dec  8 08:37 .gdb_history
-rwxrwxr-x 1 secretpack secretpack 725288 Dec  8 08:01 homework
-rw-rw-r-- 1 secretpack secretpack     63 Dec  8 07:52 homework.c
```
