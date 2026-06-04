"""av_evasion tier2_advanced - process hollowing + direct syscall tests.

Process Hollowing: classic CreateProcess(SUSPENDED) +
ZwUnmapViewOfSection + WriteProcessMemory + ResumeThread call sequence.
Direct Syscall: inline `syscall` instruction for NtAllocateVirtualMemory
bypassing ntdll user-mode hooks.

Both probes are benign (re-write the original section / immediately free
the allocation) but trigger the API-pattern detection rules that any
modern EDR ships with.
"""
