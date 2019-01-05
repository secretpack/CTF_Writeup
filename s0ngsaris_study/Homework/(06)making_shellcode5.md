# 상준이가 숙제 줌#5

아래의 코드를 실행하는 기계어 코드를 제작하라

```c
creat("FLAG",0);
chmod("FLAG",440);
exit(0);
```
##### 단! mov 인스트럭션을 쓰지 말고
##### 추가로 xor, add도 쓰지마
---
오늘도 세연이와 함께 카페를 왔다. 경원아 미안(2)

나한텐 친동생 같은 애니까 상관 없지?

상준이가 어떤 의도로 말하는지는 모르겠지만 어셈블리에 점점 익숙해지고있다.

xor, add, mov를 쓰지 말라 했으니 sub와 or instruction을 사용해보자

```asm
.globl main
main:
        call func
        .string "FLAG"

func:
        call re_zero
        or $0x08, %eax
        pop %ebx
        int $0x80

        call re_zero
        or $0x0f, %eax
        or $0x125 %ecx
        int $0x80

        call re_zero
        or $0x01, %eax
        int $0x80

re_zero:
        sub %eax, %eax
        sub %ecx, %ecx

-fno-stack-protector -mpreferred-stack-boundary=2 -zexecstack -m32
```
x86 Assemly tutorial 문서들을 참고하면서 여러가지 방법을 사용해 레지스터의 값을 0으로 초기화 할 수 있다는 것을 알게되었다.

```
secretpack@ubuntu:~/Desktop/last$ ls
nomov  nomov.s  sjass  sjass.s
secretpack@ubuntu:~/Desktop/last$ ./sjass
secretpack@ubuntu:~/Desktop/last$ ls -al
total 48
drwxrwxr-x 2 secretpack secretpack  4096 Jan  5 03:45 .
drwxr-xr-x 9 secretpack secretpack  4096 Dec 29 22:21 ..
-r--r--r-x 1 secretpack secretpack     0 Jan  5 03:45 FLAG
-rwxrwxr-x 1 secretpack secretpack  7340 Dec 29 22:42 nomov
-rw-rw-r-- 1 secretpack secretpack   335 Dec 29 22:42 nomov.s
-rwxrwxr-x 1 secretpack secretpack  7364 Jan  5 03:37 sjass
-rw-rw-r-- 1 secretpack secretpack   265 Jan  5 03:37 sjass.s
```
