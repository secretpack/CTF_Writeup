# 상준이가 숙제 줌#4

아래의 코드를 실행하는 기계어 코드를 제작하라

```c
creat("FLAG",0);
chmod("FLAG",440);
exit(0);
```
##### 단! mov 인스트럭션을 쓰지 말고
---
숙제를 준지 1주일이 넘었지만

동생 휴가에, 훈련이 겹쳐서 제대로 하지 못했다 ㅇㅇ

그래서 세연이와 함께 카페에서 공부하면서 했다.(경원아 미안)

이 숙제의 핵심은 mov 인스트럭션을 어떻게 대체할 것인가 이다.

나는 mov 대신 xor 과 add instruction을 사용하여 문제를 해결했다.

앞서 mov 인스트럭션을 사용한 inline asm 코드는 아래와 같다.

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

그리고 mov(movl) 인스트럭션 대신 xor과 add를 사용한 코드는 아래와 같다.

```asm
.globl main
main:
        call func
        .string "FLAG"
func:
        xor %eax, %eax
        xor %ebx, %ebx
        xor %ecx, %ecx

        add $0x08, %eax
        pop %ebx
        push %ebx
        int $0x80
        xor %eax, %eax
        xor %ebx, %ebx
        xor %ecx, %ecx

        add $0x0f, %eax
        pop %ebx
        add $0x125, %ecx
        int $0x80
        xor %eax, %eax
        xor %ebx, %ebx
        xor %ecx, %ecx

        add $0x01, %eax
        int $0x80

-fno-stack-protector -mpreferred-stack-boundary=2 -zexecstack -m32
```

xor instruction을 사용하여 레지스터의 값을 0으로 만들고

add 연산자를 통해 값을 더함으로써 mov 대신 레지스터에 원하는 값을 집어 넣을 수 있다.

레지스터에 새로운 값을 쓰려면 계속 초기화 해서 사용해야 한다는 단점이 있어 함수를 따로 만들어 call 하는 방법은 코드의 가독성을 높인다는 장점이 있지만 shellcode가 길어진다는 단점이 있다.

shellcode를 제작하는 과정은 앞서 했던 과제와 똑같기 때문에 생략해도 될 것같다. 그래서 실행 결과만 올리기로 했다.

```
secretpack@ubuntu:~/Desktop/last$ ls
nomov  nomov.s
secretpack@ubuntu:~/Desktop/last$ ./nomov
secretpack@ubuntu:~/Desktop/last$ ls -al
total 24
drwxrwxr-x 2 secretpack secretpack 4096 Dec 29 23:25 .
drwxr-xr-x 9 secretpack secretpack 4096 Dec 29 22:21 ..
-r--r--r-x 1 secretpack secretpack    0 Dec 29 23:25 FLAG
-rw------- 1 secretpack secretpack  331 Dec 29 22:42 .gdb_history
-rwxrwxr-x 1 secretpack secretpack 7340 Dec 29 22:42 nomov
-rw-rw-r-- 1 secretpack secretpack  335 Dec 29 22:42 nomov.s
```
