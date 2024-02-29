memory library written in Golang, a project I just started creating (preview), current for testing:
- openProcess (opens process and returns handle)
- dll injection via remote thread (injects a library into process by via VirtualAlloc & CreateRemoteThread
- readMemory (reads memory into buffer)
- writeMemory (writes memory from buffer)
- enumerateModules (enumerates loaded modules into the process)
- getMainExecutable (gets the main executable (entry) of the process)
- Get base address of main module (Gets the base address uintptr of the main module)
  todo:
  - add memory page scanning for strings
  - AOB (array of bytes) memory scan
