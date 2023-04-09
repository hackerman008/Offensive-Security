@ECHO OFF

ml64.exe /c /Foproject0_ project0_.asm
cl.exe /nologo /W0 /Tcproject0.c project0_.obj /link /SUBSYSTEM:CONSOLE /MACHINE:x64 /OUT:project0.exe