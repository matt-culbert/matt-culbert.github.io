![header](/assets/img/cnd8.jpg)
I have been quietly hard at work the past few months turning an old project that didn't quite work even half the time into a framework that provides the solid base of functionality required to build something much larger off of. But first, some background.

Last year, I made a post about designing a red team framework. It was the offshoot of a Vault 7 project I made in Python and the first one I had built from the ground up after testing things like Covenant, Sliver, and Havoc. Compared to those, you'd never have wanted to use mine, turns out building something is harder than critiquing it. Mine was overly complicated, didn't scale well at all, was hard to understand for anyone looking at the first time, and so on. That's not even mentioning just piping all commands sent by the operator to the implant through ```cmd.exe```, so there was a lot to improve upon. Over time I just kept writing down ideas that I wanted implemented and things that I was confused about to research further and add in. And over time the project grew from a simple Python script of less than a hundred lines to a few hundred lines of Go, Python, and Bash and then to a pure Go implementation with templating and reusable functions and gRPC servers.

Up front, I'm not one of those amazing Windows devs who can whip up spoofed thread call stacks and pretend I have backed memory in my implant (yet!) (especially in Go) but what I do focus on in my day to day is a lot of networking. So this is where I spent my time thinking about the frameworks attack surface. Who can read the communications, who could send unauthorized commands to my implants, could someone MitM me and decrypt comms with sensitive data, could my control server get flooded with fake registry of new implants, and so on, so this is where I spent my time developing. The core functionality of the framework features using public key infrastructure to authenticate all the commands sent to an implant using RSA signatures and authenticating the C2 server on the implant side through TLS fingerprinting.

Realistically as well, I didn't want to spend a lot of time focusing on "hiding" and "evasion" for a tool I was going to release publicly (I know, convenient excuse for me to be bad at it.) That can be saved for private repos where the authors can actually get mileage out of the tools they develop. OSS and evasion don't generally mix well with one another. I would rather have a robust framework that was error resistant and provided a platform for easy expansion.

## What did I want to solve?

My specific niche I set out to fill was that I thought C2 frameworks on the market were too fast and loose with their default security protections. As security minded people, we always preach security forward approaches to development. But then that kind of just goes out the window when it comes to products that we develop. I wanted to change that with a security forward approach to managing implants and have a framework that tries to be resistant to exploitation itself from probing defenders.

For example, I noticed that a lot of frameworks register implants at the point that they check in. This is because you only want to list implants that are active and have executed their main payload. However, a lot of frameworks are [vulnerable to a denial of service](https://github.com/ACE-Responder/RogueSliver) through the same function. Because they wait for implants to tell the C2 that they are alive, if you flood the server with these notifications it will get overwhelmed. I wanted to avoid this. All the implant registration occurs server side, meaning that the scope of that exploitation is limited to snagging implant commands before they can be executed - but that requires an individual implant ID that should be impossible to guess from implant to implant so any analysis on a compromised device will only result in that ID being burned. 

Another security forward development approach I took was that commands being executed require a signature of a private key alongside them to verify that they are in fact legitimate. This is to prevent someone taking over the upstream route and trying to issue commands to implants reaching out that would uninstall or otherwise disrupt the operation. On the topic of prevent up stream routes being taken over as well, the framework implements SSL pinning for their self signed certificates. Each generated implant has this fingerprint embedded inside of it and checks when making any communication if the fingerprint lines up. Both of these methods leave observable information in the implant that defenders and investigators can use to further track down domains used, so it's a trade off of less security in one area and more security in another. This can be minimized to a degree by using different certificates for different listeners and pointing different implants to those, but it won't be completely hidden. Later, I'll discuss some other methods employed to try and minimize that observability impact though.

## Guiding development principles

Before going further into the features, I wanted to explain some guiding principals I had. When I first started working on what would become Dagger it began with a lot of writing down notes at odd times of the day then getting around to implementing them some time later. These notes after a while became what I called my guidelines. They were non technical ideas that I wanted the project to follow no matter where it went.

- Cross compilation
  - Golang can target just about any architecture. I wrote this on an Arm Mac, tested it on an Intel Windows VM, and hosted the C2 on an Arm Kali VM. No issues.

- Secure by design
  - What I mean when I say this is that I want a very secure interaction. No one but me should be sending commands to implants. The commands sent should be encrypted and they should be verified using PKI. Finally, information sent back should be encrypted with the public key and decrypted on the receiving end with the private key in order to stop anyone who did a packet capture and is hoping to sniff information out on the wire.

- Avoid using the shell
  - Many adversary groups will run ```whoami``` when they first get on a box, and it works because they're not operating in mature environments typically that have logging and sensors on all their end points and servers. However, for the use case I designed this around, that wouldn't really pass muster. I wanted to demonstrate the issue with focusing in on the command interpreter. So for example with the aforementioned ```whoami```, we can completely avoid creating an event ID by using the Go package ```os/user``` and querying the security context of the logged in user. 

- Easy to expand
  - I wanted it to be relatively obvious when looking at the code to see where you can add your own functions. People fork and take over projects all the time so making it maintainable is important. Unit tests and clear coding standards all make that possible. I am by no means an expert in this area and there's still a long way to go with getting the code base up to par (so many structs that could just be one) but I'm aware of it and continuing to work on it.

## Overview of features (that I think are cool)

### API

The API is designed to abstract away from end users and the controller the ability to directly interact with the DB, and instead we expose a select set of features that have a narrow purpose. Now, instead of having to correctly write and format every insertion into the DB and every request for information out of it, we can send this through our API which checks for errors and retrieves the information in a way that can easily be parsed through.

Originally, I stuck to making native calls to Redis through each application individually, relying on myself to make sure that I structured each Get and Set correctly so that the information would be consistent between each service. As the code base grew though, and as I wanted to add in the ability to automate tasks dependent on things like check-in times, it became apparent that this functionality had to be abstracted away from the user. It would not be very development friendly if I left it open ended how to insert information.

So I returned to gRPC. This time around, I started with a very narrow implementation. I only wanted to take away having to directly interface with the Redis DB. From there, the scope was expanded to include the `builder` component and the `controller`. Instead of the `controller` relying on passing arguments to the compiled `builder`, it would be a lot easier to run it as a gRPC server that would intake the different aspects needed to compile the implant.

#### Automation

On the topic of exposed API functions, Outflank OST is very cool (for a number of other reasons than this one) because it lets you run Jupyter Notebooks as an automation point for your Cobalt Strike beacon. I wanted the same sort of automation with Dagger implants. That was the motivation behind making the API too, as I said before. Implants check in at weird times so requiring an operator be present to issue the initial information gathering is inefficient, and sometimes when you're available and the implant is will never match up at all. An API and automation scripts resolve a lot of this headache. Each function exposed by the API gRPC server has an associated Golang app in the examples folder which details a basic function to work with it and display data. From here, it's quite easy to build out a script that checks, for instance, the last time an implant checked in with the server or if it checked in for the first time and give it commands to run and record the output. 

### Customizable implants

Implants will always be the first thing to get burned. Defenders will have access to them, so minimizing the potential for information to be gathered quickly is important. To that end, there's a lot of useful information in the Dagger implant that a defender would want. We have ungarbled certificates, domain names, public key fingerprints for SSL pinning, the list goes on. There's a lot of ways that this can be hidden and made to be consistently inconsistent across generated implants. This is also where I found a lot of opportunity to implement evasions that I felt more confident in implementing as opposed to figuring out dynamic module stomping and syscalls without just copying other peoples work - there's a dearth of information on Golang topics like those mentioned while C, on the other hand, has copious amounts to learn from.

#### String hashing

String hashing is a fast and reliable way to obfuscate strings in order to make static analysis harder. For this implementation, using string hashing on the key fingerprint used in SSL pinning allows the implant to avoid having the exact fingerprint and instead only a hash. This has an added bonus of being exponentially faster compute time wise when it comes to doing the actual comparison of fingerprints. With string comparison, the operation works character by character. But with an integer comparison, the whole integer is compared at once. With the implementation in the Dagger implant, we don't benefit from this time complexity trade off since we still have to hash the incoming signature, but it's just fun to know how much faster these two comparisons are. This is not a completely fault tolerant system though. This is prone to collisions and that frequency is dependent on the algorithm you choose. In the case of Dagger, the algorithm is just left shifting then adding. It's nothing complicated and collisions are more likely than something like SHA.

#### Editing the config live

It sucks when keys and infrastructure gets burned, so I never understood why more frameworks don't let you edit things like listener addresses, public keys, etc. on the fly. In the Dagger implant, the fingerprint, domains, and server keys are replaceable with whatever data you want. You can completely brick your implant by setting new values for these that don't exist if you so choose. Setting up a new listener that can accept implants registered to another is tricky unless you make the central Redis DB accessible - it's up to you to do that properly though.

## What does the future hold

RSA is inherently a poor algorithm choice. While the implementation in Dagger is not terrible, upgrading this to ECDSA is a big priority. Check out the following two links for more on why 
[Seriously, stop using RSA - Trail of Bits Blog](https://blog.trailofbits.com/2019/07/08/fuck-rsa/) 
[Using RSA Securely in 2022 - Dhole Moments](https://soatok.blog/2022/02/09/using-rsa-securely-in-2022/) 

There are some core areas that Dagger is lacking. Things like support for lateral movement techniques outside of copying the implant to another directory and getting another user to run it. Up to this point, the commands that Dagger supports has been misusing the OS package since so much functionality exists there in a simple form. However for more complicated actions like lateral movement, this will no longer suffice. Anything to do with COM or SMB or general remote management is stepping into the custom library territory.

Something I want to get better at is unit testing. I only recently started adding unit tests for new functions and they are magic. In the most basic cases, they make you absolutely sure that your function works properly and returns the data you expect.

There are also a number of known bugs identified that need time put towards resolving them. These include:

>If you look at the compiled implant in a debugger and search for http strings, you'll quickly find the listener address. This is because there is a non failing error to do with an incorrect header. Trying to fix that but for now it's a great point for analysts to look at and find C2's.
>
>Upon building your first implant for a platform, you will get an error on the status and control will return to the main function. Then after a moment the UUID will be displayed and a message that it was added to the DB. If you search the UUID, you will find it was properly added with no apparent issues.
>
>The fingerprint is hashed on the implant side using a string hashing method that is not second preimage resistant or collision resistant. This could lead to failure to properly verify down the line if someone can generate a hash of another message that equals this hash (H(x1) == H(x2)) I'm unsure if this will be addressed or not.
>
>If you try to create a listener, get to the URL handler section, and exit, it will still try to serve on that port causing issues when you attempt to start another listener.
