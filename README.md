## Meltdown (CVE-2017-5754) checker


Checks whether system is affected by Variant 3 (MELTDOWN - CVE-2017-5754)

*** Only works on Linux X64 for now ***

#### How it works?
It works by using */proc/kallsyms* to find system call table and checking whether the address of a
system call found by exploiting MELTDOWN match the respective one in */proc/kallsyms*.

#### What to do when you face this error "Unable to read /proc/kallsyms..."
That's because your system may be preventing the program from reading kernel symbols in /proc/kallsyms
due to /proc/sys/kernel/kptr_restrict set to 1.

NOTE: if you get this error, it doesn't mean you're not vulnerable. It just means MY way of exploiting it won't work.
This is a test, after all !

The following command will do the tricky:
```
sudo sh -c "echo 0  > /proc/sys/kernel/kptr_restrict"
```



You should see this output if you're vulnerable
```
Checking whether system is affected by Variant 3: rogue data cache load (CVE-2017-5754), a.k.a MELTDOWN ...
Checking syscall table (sys_call_table) found at address 0xffffffffaea001c0 ...
0xc4c4c4c4c4c4c4c4 -> That's unknown
0xffffffffae251e10 -> That's SyS_write

System affected! Please consider upgrading your kernel to one that is patched with KAISER
Check https://security.googleblog.com/2018/01/todays-cpu-vulnerability-what-you-need.html for more details
```

This output is shown if you're not vulnerable

```
Checking whether system is affected by Variant 3: rogue data cache load (CVE-2017-5754), a.k.a MELTDOWN ...
Checking syscall table (sys_call_table) found at address 0xffffffff816c6ee0 ...
so far so good (i.e. meltdown safe) ...
so far so good (i.e. meltdown safe) ...
so far so good (i.e. meltdown safe) ...
so far so good (i.e. meltdown safe) ...
so far so good (i.e. meltdown safe) ...
so far so good (i.e. meltdown safe) ...
so far so good (i.e. meltdown safe) ...
so far so good (i.e. meltdown safe) ...
so far so good (i.e. meltdown safe) ...
so far so good (i.e. meltdown safe) ...
```
