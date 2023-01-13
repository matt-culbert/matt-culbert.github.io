# Sliver vs Havoc - Two Adversary Emulation Frameworks

I wanted to objectively measure two well known frameworks against one another and see which fits certain needs best. 
To this end, each platform has been measured by if you can expand on them, how easy they are to get using,
and why you might want one over the other. Before going further, for those unfamiliar, both Sliver and Havoc are 
command and control frameworks that are free to use on GitHub. Sliver is developed by BishopFox and is a reasonably
old project that first started in 2019. It's seen some major upgrades since then, with the most recent being in October 2022. 
Havoc is a much newer tool developed by three independent contributors that was first started in September 2022. 
Both teams are responsive to questions and issues and, since they're open source, you are free to expand on them
as you need. With that said, the first question that should be answered is how easy is it to spin one of these up?

##How easy is it to spin one up and get going vs the other?

###Havoc
- Havoc utilizes team profiles at launch to dictate implant functionality
- The documentation is fairly well laid out, but online only.
- You should have prior knowledge with C++ and implementing bypass techniques
because out of the box the implants are detected quickly.

Havoc is very neat. Much like Cobaltstrike, you can start the teamserver by passing it a json profile of users and their 
passwords as well as some general functionality things like sleep time and jitter of your implants. An opsec concern 
right off the bat for teams may be that the passwords in this file not encrypted, so setting proper read permissions 
of it and the directory is very important. Once the server is started, the dashboard is very intuitively laid out if 
you've ever used Cobaltstrike.

![Havoc dashboard](/assets/img/Sliver-v-Havoc/havoc-dashboard.png)

Starting a listener is easy as well. Hitting `view -> listeners` allows us to add a new one. From here, you just step
through the simple option menu and configure a few things like the port, if we'll be using hostnames, and the header to
use, and you're set.

![Listener](/assets/img/Sliver-v-Havoc/Havoc-listener-default-options.png)

And the payload options, while slim, have enough to them that we can make the necessary modifications to let them
slip by the EDR we anticipate meeting. We can output in four file formats. These are exe, dll, shellcode, or service exe.

![File formats](/assets/img/Sliver-v-Havoc/havoc-payload-formats.png)

The default implant of an EXE gets detected very quickly, so we'll be testing the shellcode option here and implant it
through the resource section of another EXE we develop ourselves.

Next, we have to select the memory allocation and execution methods. For those, our options are syscalls or Win32.
My understanding is that this means either performing a VirtualAlloc or NtAllocateVirtualMemory in the case of allocation, and for 
execution it would be NtCreateThreadEx or CreateRemoteThread. 

NtAllocateVirtualMemory is typically called through VirtualAlloc since it is an undocumented function. As we briefly
touched on in the NTDLL article in September 2022, these undocumented functions can change on a dime but are very useful
for bypassing detection methods that focus solely on break points in NTDLL when called. Their downside is that seeing syscalls like this is
quite unusual and alarming, so EDR watching for this could alert very quickly.
VirtualAlloc on the other hand is the lowest level call from user space that we can perform and hooks into Ring0
using syscalls to allocate memory within the bounds of what's known as the system granularity boundary. For most
Windows systems, this will be 64kb. Allocations also must be a multiple of this boundary, so for example a 3 byte allocation
would cause errors. Moving to the execution methods, 
NtCreateThreadEx is the undocumented, lower level, version of CreateRemoteThread. Like NtAllocateVirtualMemory, it is contingent
on syscalls being up to date and suffers from the same pitfalls. CreateRemoteThread is much safer *but* also easier
to detect. Finding a balance between the two options is important when generating your implant. Different EDR might
be tuned to detect one method more over the other.

After taking all this into account and developing our executable for the shellcode, we can see that the detection
levels has dropped from 26 to 16. That's not ideal, but if your target platform is Microsoft, you've made it past 
stage 1 with only a few changes.

![Improvements](/assets/img/Sliver-v-Havoc/Havoc-improved-detection.png)

While using Havoc, it felt like their target audience was professionals who are experienced with other C2 platforms
and want something that they can build off of on their own. It's hard to get leadership buy in on a project that is
only maintaned by three people and doesn't have a company backing it like BishopFox, so it's hard to say how likely
you are to encounter it in an enterprise. For those who really enjoy working in a GUI though, this will definitely 
scratch that itch.

###Sliver
Let's now shift a little and check out Sliver.

- Sliver is completely terminal based meaning if you need a GUI to be able to visualize things, this won't work for you.
- The documentation is expansive and intimidating, which is great, and you can type help for any function.
- Sliver also lets you set expiration dates for beacons, so they stop working after a set time.

Sliver gives you everything and expects you know what to do with it. If you don't know what to do with it, there's a 
help dialogue for each option, but aside from that you are left to figure it out. Just check out the options for compiling
an implant.

![Compile Options](/assets/img/Sliver-v-Havoc/sliver-implant-flags.png)

If you don't know why you might want to disable the Shikata-Ga-Nai shellcode encoder, you're offered no explanation.
There are numerous guides available online for Sliver, which lowers the learning curve significantly and if you would
like to get started, these are almost mandatory readings. [Some can be found here](https://dominicbreuker.com/post/learning_sliver_c2_06_stagers/).
The linked reading does a deep dive into Slivers code and finds some interesting shortcuts taken by the developers.
For example, generating stagers under the hood is handled through MSFVenom and, while you can specify a DNS name,
only hardcoded IPs are passed. This is not publicly documented and a potential drawback when trying to fly under the radar.

Again, we will be compiling and outputting shellcode for us to further obfuscate and hide. This can be done with 
the `-f` flag. 

Because Sliver does not make it obvious what their execution and injection methods are like Havoc does, we'll have to do some 
digging. Looking at the `task_windows.go` file, `VirtualAlloc` and `CreateRemoteThread` are both used to allocate and 
execute the in memory objects. Really interestingly, BishopFox has gone out of their way to implement their own syscalls
package, which only has the commands that they will need to use. It's a smart way of limiting bloat and reducing imports.
For comparison, 7zip has 69 imports from Kernel32 alone. This is definitely a key piece as well in reducing their detection
rate combined with EDR sometimes not being equipped to analyze Go binaries. 

Sliver also has its own methods for evasion, though this is not something the authors have focused heavily on. They provide
two functions that work in tandem in order to accomplish this. The first is `RefreshPE` which reloads the .text section of
a file from disk.
The second is what they call `writeGoodBytes`. This function takes a process name and a few other variables and proceeds 
to reload the clean version of a dll into the current processes memory through the first function mentioned. 
This is called through `err := evasion.RefreshPE('c:\windows\system32\ntdll.dll')`. Do note, to do this they allocated RWX
memory sections, which will set off EDR.

Now that we have an idea of how things are executed, we can go back to loading our shellcode into the resource section of 
our executable. Without even encrypting it, we see a strikingly lower detection rate than Havocs shellcode loaded the same way.

![Sliver exe](/assets/img/Sliver-v-Havoc/sliver-unencrypted-payload-test.png)

A final piece to touch on, BOFs. Sliver allows operators to port over custom beacon object files that were written for
Cobaltstrike, as well as downloading prebuilt ones. Let's see how easy they are to drop. Sliver uses something
called Armory to manage these in a sort of extension manner. You can list extensions available through `armory` and install
them through `armory install`. Then, once you've gotten the BOFs installed, you hop into a session for a beacon and can run
any of them just by typing their name and the flags that they require. This is very reminiscent of Metasploit modules and
is intuitive to use and figure out. In fact, the whole program is reminiscent of Metasploit down to the help dialogue and 
how information is presented. This is not surprising, Sliver utilizes MSF internally and has built in functionality that
allows operators to do things like inject MSF payloads.

![msf](/assets/img/Sliver-v-Havoc/sliver-vs-msf.png)

Sliver had a lot of touches to it that really gave it the feel of an enterprise ready software. There's a reputable
company backing it, it has touches like beacon kill dates built in, and there's a wide range of support for expanding
the software while staying within their ecosystem such as with BOFs. It's no surprise that threat actors have caught
onto this framework and are integrating it with more and more campaigns. Microsoft has even noted that it is being used
in tandem with Cobaltstrike in some attacks.

##How can you expand on them?

###Havoc
Custom agents are a little tricky to figure out but there are examples provided. It will take some trial and error on your
end to determine the exact way to call arguments and add functionality, but CodeXTF2 was [kind enough to include their own
demo agent](https://github.com/CodeXTF2/PyHmmm) written in Python as a demonstration for ease of understanding. Aside from
custom agents, if you wish to add your own functionality to the teamserver, the codebase is vast and somewhat poorly 
commented which makes customization not the easiest.

###Sliver
Sliver allows you to use beacon object files from Cobaltstrike to extend the post exploitation capabilities of the
framework. While this isn't necessarily a custom agent, this allows customization of agents to add further capabilities.
To the unfamiliar, BOF are compiled C programs that are position independent code. Meaning that like Donut, no matter
where it is placed in memory, it can execute. BOFs are injected directly into the beacon process typically, avoiding
IoC's associated with alternative approaches like execute-assembly which spawns a new empty process to run these 
assemblies in. Cobaltstrike never intended for BOFs to be executing long-running commands, that's what execute-assembly,
is for. Instead, these are for quick functions that return data shortly after launch. Sliver including these as a method
for expanding functionality is a very neat approach. Read more about BOFs in the sources section. Regarding their codebase
it's only marginally better commented with comments above primary functions describing what they do, but very little otherwise.
This is disappointing to see, I wish commenting code was a more common practice as it helps new people get up to speed
with each functions purpose much quicker.

##Why might you want one over the other?

###Havoc
- The GUI is very intuitive and well thought out.
- Visualizing compromised machines and SSH tunnels was intelligently setup.
- Less can be more. Giving people less to work with means they go deeper on working with what they have. Breeds innovation.

Havoc has the more user-friendly GUI of the two and makes it easy to start and deploy listeners and implants.
If you're wanting to get an introduction to C2s and customization, their GUI
makes it much easier for newer operators to get accustomed to the environment. The profiles also work more intuitively
than Slivers method of saving configurations for listeners and implants by having you edit a JSON file. The roundrobin
technique of hosts and URIs is also very clever, allowing much more randomness to be added, which it makes the defenders
job that much harder.

###Sliver
- Multi platform framework.
- Deeper resources to put into development.
- BOFs implementation is very smooth.
- More listener options like wireguard and mTLS.

If you want the end game experience of free C2's, this hands down goes to Sliver with their implementation of BOFs.
Sliver also has agents that can be deployed to not only Windows machines, but also Mac and Linux. On top of this, their
default detection rate with shellcode was also much lower. These can all be attributed to the number of resources that
BishopFox has to throw at things compared to Havocs development team. 

> Sources
> 
> (BOF) https://www.trustedsec.com/blog/a-developers-introduction-to-beacon-object-files/
> 
> (BOF) https://www.cobaltstrike.com/blog/writing-beacon-object-files-flexible-stealthy-and-compatible/
> 
> https://0x00sec.org/t/process-injection-remote-thread-injection-or-createremotethread/24399
> 
> https://github.com/BishopFox/sliver
> 
> https://github.com/HavocFramework/Havoc
> 
> https://mez0.cc/posts/detecting-syscalls-with-fennec/