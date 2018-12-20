# 상준이가 숙제 줌#1

아래의 코드를 실행하는 기계어 코드를 제작하라

```c
creat("FLAG",0);
chmod("FLAG",440);
exit(0);
```
---
위 숙제를 수행하기 에 앞서 먼저 기계어 코드 제작 방법을 정리했다.
[이 링크를 보며 기계어 코드 제작 방법을 익혔다.](http://research.hackerschool.org/Datas/Research_Lecture/sc_making.txt)

예시에 있는 것을 하나 하나 따라하면서 기계어 코드 제작 방법을 익혀보자.

먼저 위의 문서 처럼 다음을 수행하는 기계어 코드를 제작해본다.
```c
printf("Hello, Students!\n");
```

printf 함수의 경우 내부에서 write() 함수를 사용한다고 한다.

그렇다면 더욱 간단하게 하기 위해서는?
```c
write(1, "Hello, Students!\n", 17);
```
이 더욱 간단하게 표현될 수 있을 것이다.

기계어 코드로 바꾸기 위해 다음과 같이 작성하고 컴파일 한다.

```c
int main()
{
  write(1, "Hello, Students!\n", 17);
}

// compile option : -fno-stack-protector -mpreferred-stack-boundary=2 -zexecstack
```

main함수를 디스어셈블링 해보았다.
```
pwndbg> disassemble main
Dump of assembler code for function main:
   0x0804887c <+0>:	push   ebp
   0x0804887d <+1>:	mov    ebp,esp
   0x0804887f <+3>:	push   0x11
   0x08048881 <+5>:	push   0x80badc8
   0x08048886 <+10>:	push   0x1
   0x08048888 <+12>:	call   0x806d0e0 <write>
   0x0804888d <+17>:	add    esp,0xc
   0x08048890 <+20>:	mov    eax,0x0
   0x08048895 <+25>:	leave  
   0x08048896 <+26>:	ret    
End of assembler dump.
```

함수 프롤로그가 보이고 스택에 0x11이 push 된다.
이후 차례대로 0x80badc8과 0x1이 스택에 push 된다.
그리고 마지막으로 write 함수를 call한다.

스택에 push된 세 가지 값들은
```c
write(1, "Hello, Students!\n", 17);
```
위의 코드와 같다. 이제 write함수를 분석해보자.
```
  0x0806d0eb <+1>:	mov    0x10(%esp),%edx
  0x0806d0ef <+5>:	mov    0xc(%esp),%ecx
  0x0806d0f3 <+9>:	mov    0x8(%esp),%ebx
  0x0806d0f7 <+13>:	mov    $0x4,%eax
  0x0806d0fc <+18>:	call   *0x80ea9f0
```
본문에서는 바로 int 80 system call 로 바로 표시되었으나

여기서는 특정한 주소를 불러온다.

```
pwndbg> disassemble *0x80ea9f0
Dump of assembler code for function _dl_sysinfo_int80:
   0x0806f0b0 <+0>:	int    $0x80
   0x0806f0b2 <+2>:	ret
```
int 80 system call이다.

본문을 참고하면 필자도 write()함수의 인자를 차례대로 스택에 push 한 다음 write() 함수를 call 하면 되지 않을까 라는 생각을 잠시 했다. 하지만 기계어 코드를 만들기 위해서 write() 함수가 하는 일 까지 전부 기계어로 만들어 줘야 한다고 한다. 그래서 gdb를 사용하여 write 함수를 본문처럼 뜯어보기로 했다.

```
0x0806d0eb <+1>:	mov    0x10(%esp),%edx
0x0806d0ef <+5>:	mov    0xc(%esp),%ecx
0x0806d0f3 <+9>:	mov    0x8(%esp),%ebx
0x0806d0f7 <+13>:	mov    $0x4,%eax
0x0806d0fc <+18>:	call   *0x80ea9f0
```

가장 핵심이 되는 부분이다.

마지막 부분에 있는 int opcode (어셈블리) 는 interrupt의 약자로 시스템에 특정 신호를 보내는 역할을 한다고 한다. 이중 0x80 인터럽트는 커널의 시스템 콜, 즉 커널에서 사용자들에게 제공해 주는 함수를 호출하라는 의미를 갖고 있다. 그리고 어떤 함수를 호출할 지는 eax에 저장된 0x4 라는 값을 보면 된다. 이 값은 시스템 콜 테이블에 4번째로 등록된 함수를 말하고 있는 것이라고 한다. 해당 정보는 "unistd.h" 헤더 파일에 정의되어 있다고 한다. 열어보자.

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
...
```
내가 작성해야 하는 creat 와 chmod에 대한 syscall number도 보인다.

어쨋든 write 가 4번째로 정의 되어 있다.

---

##### 아래는 본문을 서너번 읽어본 필자가 중요하다고 생각되는 내용이다. #1

```asm
mov $0x4, eax
```
위의 어셈블리 명령어는 eax레지스터로 4라는 값을 저장하는 명령이다.

실제로 int 0x80 명령을 실행하면 CPU 레지스터들 중 eax, ebx, ecx, edx 등 값들을 불러와서 사용하는데, 이때 가장 첫번째 레지스터인 eax에서 어떤 함수를 호출할지 알게되고 그 다음 ebx, ecx, edx 레지스터 들의 값은 차례대로 이 함수의 인자로 적용이 된다.

---

그렇다면 eax에 4 ebx에 1 ecx에 문자열 edx 17이 들어간다는 뜻이다.

본문에서 Hello, Students! 가 출력되는 과정을 다음과 같이 정리했다.

* write() 함수의 마지막 인자인 17이 스택에 저장됨
* 두 번째 인자인 Hello... 문자열의 시작주소가 스택 에 저장됨
* 첫 번째 인자인 1 이 스택에 저장됨
* write()함수가 호출 됨
* 마지막 인자인 17이 edx에 저장됨
* 두 번째 인자인 문자열의 주소가 ecx에 저장됨
* 첫 번째 인자인 1이 ebx에 저장됨
* int 0x80 인터럽트가 발생
* eax, ebx, ecx, edx 값을 참고하여 해당 시스템 콜인 write()를 실행

이제 필요한 내욤난 빼내어 간단하게 어셈블리로 작성하는 과정이 필요하다.

```asm
.LCO:
	.string "Hello, Students!\n"

.globl main
main:
	movl $0x04, %eax
	movl $0x01, %ebx
	movl $.LCO, %ecx
	movl $0x11, %edx
	int $0x80
	ret

//gcc -fno-stack-protector -mpreferred-stack-boundary=2 -zexecstack -o writeas writeas.s
```
```
secretpack@ubuntu:~/Desktop/shellcode$ ./writeas
Hello, Students!
```
본문과는 다르게 Segmentation Fault 에러가 나지 않았다.

하지만 만일을 대비해서 본문과 똑같이 exit(0) 까지 구현해주자.

```asm
.LCO:
        .string "Hello, Students!\n"

.globl main
main:
        movl $0x04, %eax
        movl $0x01, %ebx
        movl $.LCO, %ecx
        movl $0x11, %edx
        int $0x80
        movl $0x01, %eax
        movl $0x00, %ebx
        int $0x80

//gcc -fno-stack-protector -mpreferred-stack-boundary=2 -zexecstack -o writeas writeas.s
```

만들어진 바이너리를 objdump로 열어보았다.

```
80483ed:	b8 04 00 00 00       	mov    $0x4,%eax
80483f2:	bb 01 00 00 00       	mov    $0x1,%ebx
80483f7:	b9 db 83 04 08       	mov    $0x80483db,%ecx
80483fc:	ba 11 00 00 00       	mov    $0x11,%edx
8048401:	cd 80                	int    $0x80
8048403:	b8 01 00 00 00       	mov    $0x1,%eax
8048408:	bb 00 00 00 00       	mov    $0x0,%ebx
804840d:	cd 80                	int    $0x80
```

본문과 비슷하게 어셈블리어 코드가 그대로 출력됨과 동시에 왼쪽에 기계어가 출력되었다.

하지만 문자열의 시작 주소가 정작 그 문자열은 보이지 않고 달랑 주소값만 사용되고 있다.

---

##### 아래는 본문을 서너번 읽어본 필자가 중요하다고 생각되는 내용이다. #2

```asm
mov $0x80483db
```
이는 컴파일될 때 문자열의 주소 값이 지정되고, 실제 명령 부분에서는 미리 정해진 주소 다시 말해 절대 주소를 가져와 사용하고 있는 것이다. 따라서 이 상태로 기계어 코드를 만들면, 실제 실행할 때에도 위 0x80483d0에서 문자열을 가져오려고 할 것이고 당연히 그 환경에서는 문자열이 그 주소 부분에 존재할 확률으 0에 가깝기 때문에 이 주소값을 사용하는 것은 전혀 무의미한 짓이다.

본문에서는 다음과 같은 해결 방안을 제시했다.

* 문자열 시작 주소가 스택에 저장되도록 하고
* 그 다음 스택에서 그 주소 값을 꺼내 %ecx 레지스터에 저장한다.

이 과정을 어셈블리로 표현하면 아래와 같다.

```asm
.globl main
main:
        call func
        .string "Hello, Students!\n"

func:
        movl $0x04, %eax
        movl $0x01, %ebx
        popl %ecx
        movl $0x11, %edx
        int $0x80
        movl $0x01, %eax
        movl $0x00, %ebx
        int $0x80
```
call 명령에 의해 어떤 함수가 호출되면, 함수 종료 후 실행될 리턴 어드레스 즉 call 명령 바로 다음 명령의 주소가 스택에 저장된다. 따라서 위의 경우엔 call func 바로 다음에 있는 Hello... 문자열의 시작 주소가 스택에 저장이 된다. 이제 func 함수 안에선 %eax에 write() system call임을 의미하는 4가 저장되고 %ebx에는 표준 출력을 의미하는 1, 그리고 바로 %ecx의 값을 지정해주는 단계에서 popl 명령으로 스택에 저장된 값들 중 가장 꼭대기에 있는 값을 빼와 저장한다. 이때 스택의 가장 꼭대기에는 앞서 지정된 리턴 어드레스, 즉 문자열의 시작 주소가 저장되어 있으므로 결국 문자열의 시작 주소가 %ecx 레지스터에 저장된 것이다.

---
이제 다시 컴파일 하고 objdump로 확인해보자.

```
 080483db <main>:
 80483db:	e8 12 00 00 00       	call   80483f2 <func>
 80483e0:	48                   	dec    %eax
 80483e1:	65 6c                	gs insb (%dx),%es:(%edi)
 80483e3:	6c                   	insb   (%dx),%es:(%edi)
 80483e4:	6f                   	outsl  %ds:(%esi),(%dx)
 80483e5:	2c 20                	sub    $0x20,%al
 80483e7:	53                   	push   %ebx
 80483e8:	74 75                	je     804845f <__libc_csu_init+0x4f>
 80483ea:	64 65 6e             	fs outsb %gs:(%esi),(%dx)
 80483ed:	74 73                	je     8048462 <__libc_csu_init+0x52>
 80483ef:	21 0a                	and    %ecx,(%edx)
	...

 080483f2 <func>:
 80483f2:	b8 04 00 00 00       	mov    $0x4,%eax
 80483f7:	bb 01 00 00 00       	mov    $0x1,%ebx
 80483fc:	59                   	pop    %ecx
 80483fd:	ba 11 00 00 00       	mov    $0x11,%edx
 8048402:	cd 80                	int    $0x80
 8048404:	b8 01 00 00 00       	mov    $0x1,%eax
 8048409:	bb 00 00 00 00       	mov    $0x0,%ebx
 804840e:	cd 80                	int    $0x80

```

이제 기계어 코드를 쭉 잇기만 하면 된다.
문자열은 그대로 쓰고 기계어 코드를 이어서 제대로 동작 하는지 확인해보자.

```c
int main()
{
        char *code = "\xe8\x12\x00\x00\x00Hello, Students!\n\x00\xb8\x04\x00\x00\x00\xbb\x01\x00\x00\x00\x59\xba\x11\x00\x00\x00\xcd\x80\xb8\x01\x00\x00\x00\xbb\x00\x00\x00\x00\xcd\x80";

        void (*ptr)(void);

        ptr = (void *)code;

        ptr();
}
```

```
secretpack@ubuntu:~/Desktop/shellcode$ ./codtest
Hello, Students!
```
