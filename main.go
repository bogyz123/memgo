package main

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Process struct {
	// Definise Windows proces.
    processID   uint32
	handle syscall.Handle
}

type ModuleInfo struct {
	// Definise Modul iz Procesa.
    BaseOfDll  unsafe.Pointer
    SizeOfImage uint32
    EntryPoint unsafe.Pointer
}


func (p *Process) CloseHandle() bool {
	// Zatvara handle ka procesu, true ukoliko je success, false ako nije.
    err := syscall.CloseHandle(p.handle)
    return err == nil
}
func (p *Process) Kill() {
	// Todo
}
func (p *Process) QueryString(query string /* ostali parametri od VirthualQueryEx */) uintptr {
	// Todo
	// Pronalazi string u memoriji procesa pomocu VirtualQueryEx, vraca adresu stringu.
	return 0;
}
func (p *Process) GetMainExecutable() string {
	// Vraca path ka glavnom executable programa.
    psapi := syscall.NewLazyDLL("psapi.dll")
    getName := psapi.NewProc("GetProcessImageFileNameW")
    buffer := make([]uint16, syscall.MAX_PATH)
    _, _, err := getName.Call(uintptr(p.handle), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	if (err != nil) {
		fmt.Println(err);
	}
	data := syscall.UTF16ToString(buffer);
	return data;
}
func (p *Process) WriteMemory(handle syscall.Handle, baseAddress uint32, dataBuffer []byte, bytesToWrite uint32, bytesWritten *uint32) bool {
	// Pise memoriju iz dataBuffera u Proces.
	memory := syscall.NewLazyDLL("kernel32.dll");
	write := memory.NewProc("WriteProcessMemory");
	syscall.Close(p.handle);

	_, _, err := write.Call(uintptr(handle), uintptr(baseAddress), uintptr(unsafe.Pointer(&dataBuffer[0])), uintptr(bytesToWrite), uintptr(unsafe.Pointer(bytesWritten)));
	if (err != nil) {
		fmt.Println(err);
		return false
	}
	return true
}
func (p *Process) ReadMemory(handle syscall.Handle, baseAddress uint32, dataBuffer []byte, bytesToRead uint32, bytesRead *uint32) bool {
	// Cita memoriju u dataBuffer.
	memory := syscall.NewLazyDLL("kernel32.dll");
	read := memory.NewProc("ReadProcessMemory");
	_, _, err := read.Call(uintptr(handle), uintptr(baseAddress), uintptr(unsafe.Pointer(&dataBuffer[0])), uintptr(bytesToRead), uintptr(unsafe.Pointer(bytesRead)));
	if (err != nil) {
		fmt.Println(err);
		return false
	}
	return true
}
func getMod(processHandle windows.Handle, moduleHandle windows.Handle, moduleInfo *windows.ModuleInfo) error {
    err := windows.GetModuleInformation(processHandle, moduleHandle, moduleInfo, uint32(unsafe.Sizeof(*moduleInfo)))
    if err != nil {
        return err
    }
    return nil
}

func (p *Process) GetBaseAddress() uintptr {
	// Vraca glavnu adresu (entry point) glavnog modula p Procesa.
	// Da uzmemo base adresu iz glavnog modula, prvo enumerisemo sve module koji su loaded u procesu.
	var modules [1024]syscall.Handle
	modes, err := p.EnumerateModules(modules[:]) // modes = [x]syscall.Handle
	if (err != nil) {
		fmt.Println("e");
		return 0;
	}
	// Ako smo uzeli module, loadujemo GetModuleFileNameExW funkciju koja vraca full path ka modulu. Moduli moraju biti loadovani kada se poziva ova funkcija.
	 api := syscall.NewLazyDLL("psapi.dll");
	 getExeName := api.NewProc("GetModuleFileNameExW");
	 fileName := make([]uint16, 1024); // Buffer koji updatujemo u loopu, sadrzi path ka modulu kao UTF16
	 moduleInfo := windows.ModuleInfo {}
	for i := 0; i < len(modes); i++ {
		// Cilj je pronaci glavni modul iz liste modula, proverom da li sadrzi ime glavnog executabla.
		_, _, err := getExeName.Call(uintptr(p.handle), uintptr(modes[i]), uintptr(unsafe.Pointer(&fileName[0])), uintptr(len(fileName)));
		// U svakoj iteraciji loopa, fileName ce biti popunjen sa pathom modula kao UTF16.
		file := syscall.UTF16ToString(fileName); // Path ka modulu kao string
		if (err != nil) {
			fmt.Println("e");
		}
		if (strings.Contains(file, "notepad.exe")) { // Proveravamo da li path ka modulu sadrzi ime glavnog executable (Ako je glavni modul)
			getMod(windows.Handle(p.handle), windows.Handle(modes[i]), &moduleInfo)
			fmt.Println(moduleInfo);
			break;
		}
	}
	return moduleInfo.BaseOfDll;
}


func OpenProcess(inheritHandle bool, processID uint32, fileMode uint32) (bool, *Process) {
	// Otvara Process i vraca syscall.Handle ka tom processu, 0 = InvalidHandle !0 = validan Process Handle.

	
    handle, err := syscall.OpenProcess(fileMode, inheritHandle, processID)
	
    if err != nil {
        return false, nil
    }
    process := Process {
		processID: processID,
		handle: handle,
	}
	return true, &process;
}
func (p *Process) EnumerateModules(modules []syscall.Handle) ([]syscall.Handle, error) {
    psapi := syscall.NewLazyDLL("psapi.dll")
    getModules := psapi.NewProc("EnumProcessModules") // Load function from library

    var neededBytes uint32


    res, _, err := getModules.Call(uintptr(p.handle), uintptr(unsafe.Pointer(&modules[0])), uintptr(len(modules) * int(unsafe.Sizeof(modules[0]))), uintptr(unsafe.Pointer(&neededBytes)))
	// Param1= process handle, Param2 = (out) bufferArray, Param3 = size of the bufferArray, Param4 = (out) neededBytes

    if res == 0 { // 0 = Failed !0 = Success
        return nil, err
    }
	// Needed bytes je broj bajtova koliko je napisano u array za svaki modul, da bi dobili kolicinu modula u array podelimo bajtove napisane sa velicinom jednog modula
	// bytesWritten / singleModule = amount of modules in array
	written := neededBytes / uint32(unsafe.Sizeof(modules[0]))
	return modules[:written], nil;
}

func main() {
	success, process := OpenProcess(false, 15536, windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ|windows.PROCESS_VM_WRITE) // This is notepad
	if !success {
		fmt.Println("Failed")
		return
	}
	base := process.GetBaseAddress()
	fmt.Printf("base: %v\n", base)

}
