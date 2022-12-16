# Another fake ad, another fake product

Wow, there's been a lot of malvertising recently. The last post was on a bitcoin scam and it looks like we're continuing this trend.
Some of you might remember back in 2021, there was an ad on Google pointing to a website that was hosting a fake version
of lightshot. When downloaded, this installed a remote assistance tool alongside the real software that allowed an 
attacker to connect in and drop further malware. Well, this is obviously a great way to spread your malware as you
instantly become the top result on Google, and we can see this in the latest scam taking advantage of it. 

# Giipm - An image editing software

Wait that's not right. Gimps the software, so what's Giipm? 
![The homepage](/assets/img/giipm scam/giipm.png)
This is called typosquatting. The name is similar to gimp.org, and you'd be forgiven for looking at this and thinking
at first that the name is the same. But if you go to download this, you're given a URL that is not at all related
to Gimp. Originally, this was a discord link:

![Discord](/assets/img/giipm scam/discord-link.png)

But since then the site has been updated to use the following:

![URL](/assets/img/giipm scam/new-download.png)

# The TTPs

The functionality of the malware originally had it execute a powershell script to sleep 15 seconds

![Powershell](/assets/img/giipm scam/powershell.png)

It would then reach out to a Russian IP and download a PNG. 

![Russian PNG](/assets/img/giipm scam/png.png)

This PNG, however, was not actually a PNG. It contained bytecode and upon examination, this bytecode appeared to be XOR encoded.

![ByteCode](/assets/img/giipm scam/pasting_into_x64dbg.png)

If this is XOR encoded, then the key was either sent with the file or it's hardcoded into the program. 
Unfortunately, none of the strings from the primary setup file worked as key and there was nothing sent in the 
communication logs either that would work. It's not 100% clear though if this is encoded. Pasting it into x64dbg,
we can see other information.

![Pasted](/assets/img/giipm scam/obfuscated_bytes.png)

Turning back to the dropper, putting the Setup.exe file in PEstudio we can see a number of very odd strings.

![Oracle](/assets/img/giipm scam/oracle-vm-virtualbox.png)

It looks like the installer uses Oracles Virtualbox installer to kick off the setup, possibly attempting to piggyback
off of their trusted and signed software so the attackers don't need to figure that out on their own. It was at this
point I wanted to see if the attackers were hiding shellcode in the .ico included resources, [a very common evasion
technique](https://www.ired.team/offensive-security/code-injection-process-injection/loading-and-executing-shellcode-from-portable-executable-resources).
Unfortunately, that wasn't the case here and the icon files were just that. But! A fun feature of Virustotal is that
it shows you files that also include the file you uploaded. So we can see that the attackers have tested their payload
multiple times on Virustotal.

![Dumbdumbs](/assets/img/giipm scam/virusTotal%20associated%20files.png)

# The Updated TTPs

The malware campaign is under active development, as evident by the IPs changing, the download URL changing to 
something more legitimate and harder to take down than a Discord hosted EXE, and the deliverable no longer being 
byte code hiding in a PNG file.

![New IP](/assets/img/giipm scam/new-russian-ip.png)

Instead of downloading further malware to run, we can see that the initial dropper is only receiving instructions to look
in common places for crypto wallets. 

![wallets](/assets/img/giipm scam/looking-for-wallets.png)

We can also glean some new information from the dropper itself.
The authors were kind enough to include some debug symbols and more identifying information.

![updated dropper](/assets/img/giipm scam/new-dropper.png)

This is quite different from the original dropper which just tried to piggyback off Virtualboxes installer. This to me
is further indication that the campaign is still under active development and may even have a new goal. What this new
goal is, apart from being just a stealer, is not entirely clear to me and they may have detection in place to prevent
the payload from running on a VM. The overarching lesson though from this is that you cannot trust Google ads and you
must be vigilant about the URLs you click on.