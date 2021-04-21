# Welcome to CTF

# Table of Contents
1. [What is CTF?](#what-is)
2. [CTF Challenge Types](#challenges)
3. [How To Get Into CTF](#how-to-get-into)
4. [Learning Resources](#learning-resources)
5. [Practice](#practice)

## What is CTF?<a name="what-is" />

Capture the Flag (CTF) competitions are online information security competitions. CTF events are made up of challenges, usually in multiple disciplines. These challenges are each worth points, and the team that finishes the CTF with the most points wins! Players can play alone, or they can play in teams (much more fun). You can play to learn (recommended) or you can play to win (not for the faint of heart). All CTFs are learning experiences though, often introducing novel vulnerabilities or exploitation techniques across security disciplines. Most players are friendly and excited to share their solves after the competition ends, so community is an important aspect of CTF playing. Generally, CTF competitions are organized through [CTFTime](https://ctftime.org), an unofficial calendar and ranking hub that lets top teams show off their hard-earned rating points. CTFtime has their own [WTF is CTF](https://ctftime.org/ctf-wtf/) for the curious.

Points are gained by getting `flags`, which are strings that look something like `flag{th1s_15_y0ur_f1r5t_fl4g}`. They can be anything, but are usually distinctive, and the format is different for each CTF event. These flags are hidden various places. For example, in pwn the flag is traditionally in a file called `flag.txt` that can only be read by executing arbitrary code on the remote machine. In crypto, the flag will be in the plaintext after the challenge is solved and decrypted!

CTF competitions come in many varieties, but there are two formats most adhere to:

### Jeopardy Style

These CTFs are the most common, and there are usually one or more events every single weekend. Contestants play either solo in teams, and the CTF site has a board of challenges (hence jeopardy), each with a point value. Take a look at an always-on jeopardy style CTF [here](https://play.picoctf.org/practice). Jeopardy style CTFs generally last between 24 and 72 hours. Most top-tier CTF events fall into the jeopardy format, for example [Plaid](https://plaidctf.com/) and [OOO DEF CON Quals](https://oooverflow.io/).

### Attack-Defense (A-D)

These CTFs are generally shorter than Jeopardy style CTFs, generally taking place in one day. These CTFs are faster paced! Each team runs a server that has several services running on it (these services are the "challenges" in A-D). Teams reverse engineer the services to find bugs and vulnerabilities, then gain points by exploiting opponents' services. Teams also gain points by patching their own services to remove vulnerabilities and protect their own flags. Examples of popular A-D CTFs are [iCTF](https://shellphish.net/ictf/) and [Faust](https://2020.faustctf.net/).

## What are the challenges? <a name="challenges" />

Challenges come in all varieties, but the following categories are the main staples:

### pwn

(Usually) binary exploitation exercises. Reverse engineer a provided binary that is running on a server, create an exploit for it, and launch your exploit to get arbitrary code execution and grab the flag! Typically, contestants will receive a compiled program (or, if the organizers are either kind or exceedingly evil, source code) and a string like `nc challenge.ctf.com 1337`. This string tells you where the challenge is running: `challenge.ctf.com` on port `1337`.

### re

RE challenges are similar to pwn challenges, but generally everything you need to get the flag is provided to you, including the flag itself! These can be highly varied: they may be a compiled program that performs checks on inputs to form a set of constraints that when run backward gives the flag. They may be interpreters for custom programming languages that challenge contestants to reverse engineer code in a never-before-seen language. The sky is the limit, but the flag will be in the challenge somewhere!

### crypto

Crypto challenges are as widely varied as the other categories. Typically, contestants will be provided a service that does some encrypting or encoding and be given the task of deciphering or decrypting some provided ciphertext. Just as often, the scheme is not provided and contestants are left to figure out how something was encrypted as well as how to decrypt it. Crypto challenges are perfect for mathematically-oriented players, and the hardest crypto challenges involve math that would give an algorithms professor second thoughts. On the other hand, crypto challenges can often be solved with only a discrete mathematics textbook, a pencil, and a pad of paper. For that reason, crypto is thought of as a very accessible discipline in CTF.

### web

Perhaps the most familiar to the layperson, web challenges are extraordinarily varied. As web technology advances and expand, so do the CTF challenges. From chrome n-day memory exfiltration to classic XSS, SSRF, and SQL injection, web exploitation has something for everyone. Many web challenges can be solved using only a web browser with the inspector and JS console open, and like cryptography is accessible to newcomers. Web exploitation is a favorite category of bug bounty hunters, and they tend to have a leg up on the competition here: they know what to look for!

### misc

The misc category can be literally anything. From building a neural network solver for 5D Tic Tac Toe to decoding a flag hidden in minecraft datapacks, you never know what will be in the misc category. It could be a game, it could be malware, or it could be nothing.....or is it?


### other categories

Other categories appear or don't depending on the CTF. A DFIR-oriented CTF will probably have forensics and redteam challenges, but these challenges do not always show up in every CTF.

## How to get into CTF?<a name="how-to-get-into" />

1. Play! Play a lot. The easiest way to get good at CTF is to play as much as possible. The more challenges you see, the more challenges you will have an idea of how to solve in the future.
2. Find a team that you enjoy playing with. CTF is fun alone, it is a stimulating mental exercise, but it is infinitely more fun when played with friends (either online or in person). Playing with a team allows you to share knowledge and begin to specialize as well, and having more eyes on the problem increases your chances of getting flags, ranking higher, and increasing your motivation even more.
3. Learn when not playing! There are many learning resources below, but in general: play always-on, solve challenges, and keep track of your solutions and techniques!
4. Figure out what you like to do. Most players are not pros at all categories except ~~perfect blue~~, so don't expect to be a master of all 4 elements. Pick what you like to learn about and enjoy, and focus on that!

## Learning resources<a name="learning-resources" />

### Informational Resources:

Watch our [b01lers bootcamp](https://www.youtube.com/c/b01lers/videos)

#### pwn
##### online
- [b01lers bootcamp pwn: beginner-oriented training](https://github.com/b01lers/bootcamp-training-2020/tree/master/pwn)
- [pwn.college: advanced pwn training](https://www.youtube.com/c/pwncollege/videos)
- [guyinatuxedo's nightmare: ctf-oriented training by example](https://guyinatuxedo.github.io/)
- [CTF Wiki (translators needed!): huge info hub](https://ctf-wiki.github.io/ctf-wiki/index-en/)
- [malloc.c: yes, you need to learn this](https://github.com/bminor/glibc/blob/master/malloc/malloc.c)
- [how2heap: heap exploitation technique listing](https://github.com/shellphish/how2heap)
- [RPISec Modern Binary Exploitation: another open university course](https://github.com/RPISEC/MBE)

##### tools (OSS+$0 only)
- [gdb: the debugger you must learn to use](https://www.gnu.org/s/gdb/)
- [objdump: classic disassembler](https://sourceware.org/binutils/docs/binutils/objdump.html)
- [pwntools: python library and tooling for exploit development](https://github.com/Gallopsled/pwntools)
- [Ghidra: the best free reversing tool](https://ghidra-sre.org/)
- [pwndbg: gdb extension for exploitation](https://github.com/pwndbg/pwndbg)

##### books (>$0)
- Hacking: The Art of Exploitation, by Jon Erickson (outdated!)
- The Ghidra Book, by Chris Eagle and Kara Nance (also outdated!)

#### re

##### online
- [b01lers bootcamp rev: beginner-oriented training](https://github.com/b01lers/bootcamp-training-2020/tree/master/rev)
- [Azeria ARM Tutorial](https://azeria-labs.com/writing-arm-assembly-part-1/)
- [x86 Instruction Reference](https://www.felixcloutier.com/x86/)
- [Intel Official x86 Reference](https://software.intel.com/content/www/us/en/develop/articles/intel-sdm.html)
- [RPISEC Malware Analysis](https://github.com/RPISEC/Malware)
- Many of the pwnable resources will also help you with RE!

##### tools (OSS+$0 only)

See pwn...same tools!

##### books (>$0)
- Reversing: Secrets of Reverse Engineering, by Eldad Eilam
- Assembly Language for Intel-Based Computers, by Kip R. Irvine
- Practical Reverse Engineering: x86, x64, ARM, Windows Kernel, Reversing Tools, and Obfuscation, by Dang, Gazet, Bachaalany

#### crypto

##### online

- [Cryptohack](https://cryptohack.org/)
- [cryptopals](https://cryptopals.com/)
- [Root-Me](https://www.root-me.org/en/Challenges/Cryptanalysis/)
- [Ctf-Wiki: needs translation](https://github.com/ctf-wiki/ctf-wiki/tree/master/docs/zh/docs/crypto)


##### tools
- [Ciphey](https://github.com/Ciphey/Ciphey)
- [CyberChef](https://gchq.github.io/CyberChef/)
- [Sage Math](https://www.sagemath.org/)
- [Yafu](https://github.com/DarkenCode/yafu)
- [RsaCTFTool](https://github.com/Ganapati/RsaCtfTool)

##### books (>$0)

Unlike the other categories, cryptography books are pretty good.

- Serious Cryptography, by Jean-Philippe Aumasson
- [TLS RFC](https://tools.ietf.org/html/rfc5246)
- [The Other TLS RFC](https://tools.ietf.org/html/rfc8446)
- [Cryptography Engineering](https://www.schneier.com/books/cryptography-engineering)
- [Introduction to Modern Cryptography](http://www.cs.umd.edu/~jkatz/imc.html)
- [An Introduction to Mathematical Cryptography](http://www.math.brown.edu/~jhs/MathCryptoHome.html)
- [A Course in Number Theory And Cryptography](http://www.amazon.com/Course-Number-Cryptography-Graduate-Mathematics/dp/0387942939)
- [Handbook of Applied Cryptography](http://cacr.uwaterloo.ca/hac/)
- [Real-World Cryptography](https://www.manning.com/books/real-world-cryptography?a_aid=Realworldcrypto&a_bid=ad500e09)

#### web

Web exploitation is quite varied and constantly evolving, some classics remain though.

##### online

- [Trail of Bits Guide](https://trailofbits.github.io/ctf/web/exploits.html)
- [ctf101](https://ctf101.org/web-exploitation/overview/)
- [CTF Academy](https://ctfacademy.github.io/web/index.htm)

##### tools
- [Chrome](https://www.google.com/chrome/)
- [python](https://www.python.org/)
- [wireshark](https://www.wireshark.org/)
- [Burp Suite](https://portswigger.net/burp)

##### books (>$0)
- [Web Application Hacker's Handbook](https://portswigger.net/web-security/web-application-hackers-handbook)
- [Attacking Network Protocols](https://nostarch.com/networkprotocols)
- [Real-World Bug Hunting](https://nostarch.com/bughunting)

### Always-On CTFs:<a name="practice" />

Thanks to [zardus](https://github.com/zardus/wargame-nexus) for many of these!

#### pwn
- [Over The Wire Bandit](http://overthewire.org/wargames/bandit/)
- [PicoCTF](http://picoctf.com/)
- [Exploit Education](https://exploit.education/)
- [pwnable.kr](http://pwnable.kr/)
- [pwnable.tw](http://pwnable.tw/)
- [pwnable.xyz](https://pwnable.xyz/)
- [ROP Emporium](https://ropemporium.com/)
- [Micro Corruption](https://microcorruption.com/login)
- [pwn.college challenges](https://pwn.college/)

#### re
- [Challenges.re](https://challenges.re/)
- [Crackmes.one](https://crackmes.one/)
- [Microcorruption](https://microcorruption.com/)
- [Reversing.kr](https://reversing.kr/challenge.php)
- [OSX Crackme](https://reverse.put.as/crackmes/)
- [Pwnable.XYZ](https://pwnable.xyz/challenges/)
- [W3Challs.com](https://w3challs.com/challenges/list/reversing)
- [io.netgarage.org](http://io.netgarage.org/)
- [Crackme Forum](https://0x00sec.org/c/reverse-engineering/challenges/13)
- [crackmes.de (mirror)](https://tuts4you.com/e107_plugins/download/download.php?view.3152)

#### Crypto

- [Cryptohack](https://cryptohack.org)
- [Cryptopals](https://cryptopals.com)
- [id0](https://id0-rsa.pub/)
- [Root-Me](https://www.root-me.org/en/Challenges/Cryptanalysiso)

#### web
- [https://xss-game.appspot.com/](https://xss-game.appspot.com/)
- [https://www.hackthebox.eu/](https://www.hackthebox.eu/)
- [https://www.hackthissite.org/](https://www.hackthissite.org/)
- [http://www.dvwa.co.uk/](http://www.dvwa.co.uk/)
- [https://tryhackme.com/](https://tryhackme.com/)
