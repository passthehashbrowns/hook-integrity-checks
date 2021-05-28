# hook-integrity-checks
This repository contains the source code for [this](https://passthehashbrowns.github.io/hook-integrity-checks) blog post about checking hook integrity with Frida.

main.c contains the "malicious" code. It will perform a call to NtOpenProcess to verify that hooks in place, store the hooked version of NTDLL and then unhook it, and perform another call to NtOpenProcess which should not show up in Frida. Then it will rehook NTDLL and perform a final NtOpenProcess call which will show up. If you want to verify that the hooking integrity check is working, you can comment out the call to rehookNtdll().

ntdll_hook.js contains some Javascript calling the Frida API. It will register a hook on NtOpenProcess, get the hooked bytes, and periodically check that the hook has not been removed for the lifetime of the process.
