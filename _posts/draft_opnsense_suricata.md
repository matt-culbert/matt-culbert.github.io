
Most peoples first recommendation to others interested in learning more about cybersecurity is to build a homelab, after all practiced applications of what you learn is the best way to solidify it in your mind. Where I think these guides and suggestions fall short is that they combine a ton of different software that's hard to link in a cohesive manner. You want an IDS, a SIEM, an active firewall, VPN solution, VLANs and subnets, this that and everything else. And all of these are sandboxed components that require linking in a number of ways that aren't really obvious at first. I think there's a better way to go about this, introduce a lot of the same concepts in a more cohesive manner, and build a skillset in an underappreciated niche - traffic analysis and detection. 

By the end of this post, I hope to have accomplished two goals. The first is giving the reader a better alternative to a generic traffic log collection endpoint by setting up OPNsense. OPNsense comes with a log management system preconfigured that will be on par with any other free solution you want to ship them off to. The second goal is to learn more about alerting and counter measures to C2 traffic. OPNsense contains a Suricata powered IDS/IPS engine that you can write custom rules for, so the possibilities are pretty endless there. By combining the routing, firewalling, log analysis, and detection/prevention into one product, you don't have to concern yourself with why one component isn't working and instead can focus on what matters; learning!

Bear with me through the setup process, there's a lot that needs to be done before moving onto the fun bit of actually writing rules. If you want to skip the setup and go straight to the section on generating traffic and writing detections, [you can click here](# Generating & Analyzing Attack Traffic) or just scroll all the way down to the section on generating and analyzing attack traffic. 

>[!IMPORTANT]
>There is an assumption of baseline skills or the ability to search unknown terms and learn on the fly. Things like CIDR notation, what a subnet is, how to exit Vi, that won't be reviewed. 
# The Hypervisor

Starting from the top, the hypervisor being used. The whole point of a homelab is to virtualize away a bunch of VMs of varying configurations that can each be taken down and spun back up as needed, and this guide is no different. For a long time, the free tier of ESXI was the go to choice for many people, but that option has gone away. Since then, lot of people are migrating to Proxmox or Hyper-V. Each of these has its own pros and cons but you can't go wrong with either choice. I am choosing to use Proxmox.

Proxmox ships with their enterprise updates configured, so if you don't have a license you will need to disable these. Don't skip this step, it's important to make sure that you're updating from the correct repositories otherwise you won't get any updates. Proxmox [outlines the process here](https://pve.proxmox.com/wiki/Package_Repositories) but I've also included a brief summary of the steps below. Note that `bookworm` is the latest release I am configuring but in the future this will change. Adjust to your needs.

Configure Proxmox to update from the non-enterprise repository by moving the enterprise repo to a backup location `/etc/apt/sources.list.d/pve-enterprise.list` and then creating `/etc/apt/sources.list.d/pve-no-subscription.list` with the below content.
```shell
deb http://download.proxmox.com/debian/pve bookworm pve-no-subscription
```

Next configure the `/etc/apt/sources.list` file.
```shell
deb http://ftp.debian.org/debian bookworm main contrib
deb http://ftp.debian.org/debian bookworm-updates main contrib

# security updates
deb http://security.debian.org/debian-security bookworm-security main contrib
```

Once this is done, run `apt update` and you should be able to pull the latest updates. 

Alternatively, there is a script available to do all the [configurations for you available here](https://github.com/tteck/Proxmox/raw/main/misc/post-pve-install.sh). Of course, please review the script and what it executes before running it yourself. The script will handily also disable the subscription nag prompt and adjust some other quality of life things like the HA configuration which most don't need.

Next, we need to configure the primary VNet and our secondary unmanaged VNETs. Proxmox has [a helpful guide for that here](https://pve.proxmox.com/wiki/Setup_Simple_Zone_With_SNAT_and_DHCP) which includes the `apt` installs and configuration changes. Follow the steps outlined and create three VNets. The first VNet should have a subnet defined and SNAT enabled for it as this will be our route out to the internet but the other two will be left empty. They will be managed by OPNSense. In case that link no longer works, I've again added the steps below.

Run `apt install dnsmasq` to get a very lightweight DNS/DHCP server. Per their documentation, it is designed to support small networks and handle the DNS/DHCP requirements, as well as the router advertisements and the network boot.

With that configured, navigate to `Datacenter > SDN > Zones` and create a new zone. Give it an ID you will recognize if you have multiple (in this case I have `internal` and `external`) and ensure you tick the box for `automatic DHCP`.
![[Pasted image 20240708105953.png]]

With that configured, under `SDN` navigate to `VNets`. This is where `SNAT` will be configured to allow one of the `VNets` to reach the outside network by forwarding requests. In my case for `VNets` I have configured, there is `VNetInt`, `OPNsense`, and `OPNS2`. Only `VNetInt` has `SNAT` enabled.
![[Pasted image 20240708110532.png]]

After all of these steps are completed, navigate up to the `SDN` panel and make sure you hit `apply` to apply the changes made. `Dnsmasq` will automatically use the host DNS configuration.
# The VMs 

Next, it's time to setup OPNsense, Kali, and a victim machine to emulate attack traffic to. The victim machine can be anything you want, I chose to use a clone of my Kali machine and set it up on the 3rd VNet, `OPNS2`, to emulate what cross interface traffic looks like.
## OPNsense

The OPNsense VM is going to be our route to the internet for the two unconfigured networks created when designing the Proxmox networks in step 1. I chose OPNsense because of issues with PFSense that cropped up after Netgate took over, but a lot of the steps I will go through below are almost directly translatable from one to the other if you feel more confident using PFSense.

My OPNsense VM has two cores, 8GB of RAM, and 64GB of storage. I also configured it with three network adapters, assigning each to a VNet. 
![[Pasted image 20240627133535.png]]

After the hardware is set, you're ready to turn on the OPNsense VM. You will be presented with options but you're not going to do any of them. When asked to import a configuration, select no. For the manual interface assignment, also select no. OPNsense will perform some autoconfiguration and then prompt you to log in. Use the name `installer` and password `opnsense` to kick off the install process. You can use the `tab` key, `arrows`, and `space` bar to navigate the menus that come up during this process. Be sure to double check you're using the correct disk to install to:
![[Pasted image 20240701101925.png]]

Use the default options for everything else and reboot again to finally log in as `root` with the same password as the `installer` account (unless you opted to change it.) Now to configure some interfaces. Your VM right now most likely looks similar to mine below. You only have two interfaces, missing the third that is setup under the hardware options.
![[Pasted image 20240701102516.png]]

You will have to use options 1 and 2 in the terminal to set all three interfaces up properly but a bit of fiddling should get you there. For ease of reference, I suggest popping the console out and having it next to your hardware configurations like I have in order to easily see which device is which MAC address.
![[Pasted image 20240701102714.png]]

Use option `1` to begin configuring the `WAN` and select no to the `LAGG` and `VLAN` options. `LAGG` is for link aggregation and we're not playing with `VLANs` right now. Next you will be prompted for the interface name. In my case, `vtnet0` in OPNsense has the same hardware ID as the hardware network adapter assigned to the SNAT network in Proxmox so that's how I know it's the right choice. Next you will be prompted to enter your `LAN` interface name so do the same. This one is more flexible, both the remaining VNets are fine to use here and the one you don't choose will be assigned to the additional `opt1` interface afterwards. 
![[Pasted image 20240701103109.png]]

Once the interfaces are assigned, you can begin configuring them. Using option `2`, begin with setting up the `WAN` interface. I've opted to manually configure the IPv4/6 addresses, leaving 6 blank for now. Recall the `WAN` is the `SNAT` network so assign an IP in the range you defined for it, along with the `gateway` and `CIDR` notated `subnet`.
![[Pasted image 20240701104220.png]]

The WebGui protocol, self-signed cert, and access defaults are all fine to select `No` for as we are building this for demonstration purposes.

With the `WAN` configured, we now have to do the same for the `LAN` and `OPT1` interfaces.
![[Pasted image 20240701104816.png]]

The IP assignment steps are the same as what was done for the `WAN` interface, just be sure to select a different IP range. For the sake of clarity when observing traffic, I opted to put both non-`WAN` interfaces on the `172.16.1.0` and `172.17.10.0` ranges. The only extra step for these configurations is to enable the `DHCP` server, define an IP range, netmask in `CIDR` notation, and set a `gateway`. The `gateway` is what you set as the interface IP in OPNsense. As shown in my configuration, the interfaces each match up with their interface shown in the hardware settings. 
![[Pasted image 20240627133923.png]]

That's it for now in the OPNsense terminal, now for our attack box.
## The Attack Box

For the attack box I suggest assigning 4GB of RAM and 2 processors, but this is really preference. Add a new Kali virtual machine and edit the network device so that it uses the LAN bridge configured for OPNsense. This will allow you to reach the OPNsense web management interface and you will have a route from the 172.16.1.0 network through the 10.1.1.0 network out to the internet.
![[route-to-internet.png]]

For the C2, I want to write Suricata rules relevant to my personal tools, so I'll be using CloakNDagger. Feel free to use whatever you would prefer though instead.
## Final Configuration Steps

From the Kali VM you have setup to use the OPNsense LAN interface, navigate to the OPNsense `LAN` IP and login again, swapping the username `installer` for `root` but using the same password. I suggest skipping the Wizard you're prompted to use on first login. In the GUI, if you did not enable DHCP for your interfaces, navigate to `Services -> ISC DHCPv4 -> InterfaceName` and configure your respective DHCP options by defining a range, gateway, netmask, and DNS. I just use Google DNS. Before leaving, navigate to `Firewall -> Rules -> InterfaceName` and add two rules to both the internal interfaces that allow traffic in and out unrestricted. From here, you can play around with the different services. I suggest you go and take a look at the `Live View` of the firewall logs. This can be found under `Firewall -> Log Files -> Live View`.  You'll see all the traffic flowing out through the WAN interface but very minimal interface to interface traffic. Navigate to `Services -> Intrusion Detection -> Administration -> Settings tab`, turn the IDS on by checking 'Enabled,' and then make sure the interfaces that you setup are selected. Mine looks like the below:
![[Pasted image 20240627132952.png]]

You're now ready to begin with your attack traffic analysis and alerting. 
# Generating & Analyzing Attack Traffic

Now that the different boxes are ready, OPNsense is configured, and traffic is flowing, let's dive into Suricata. There's been quite a lot of setup leading up to this but it'll all have been worth it. Ensuring the lab is configured properly for routing and analyzing traffic is much more arduous than the actual rule writing. 
## The Attack Traffic

From your C2, setup a listener and generate a standard payload. Send the payload over to your victim machine and, when you start getting traffic back, you're ready to go.

Go back to the OPNsense web GUI and we're going to take a look at traffic flowing through the firewall. You should see similar traffic to the below example: 
![[Pasted image 20240627134615.png]]

This is all well and good, but how do you alert on this?
## OPNsense IDS Rules

Now that traffic is being logged, you're ready to begin writing rules. Before we get into writing the rules themselves, let's review some specifics on the language documentation and uploading custom rules. The rule format is Suricata, documentation for writing these rules can be [referenced from here](https://docs.suricata.io/en/suricata-5.0.5/rules/intro.html). In order to upload the custom rules file to OPNsense, it must be hosted with a `.rules` extension at a URL OPNsense can fetch from when updating. Follow [the forum post here](https://forum.opnsense.org/index.php?topic=7209.0) for more information on adding your custom rules but, in case that link no longer works when you're reading this, I've copied the relevant bits below. Thanks, as always, to the original author `dcol`. For the publicly reachable URL requirement, I store my custom rules in a GitHub repository. To fetch these, OPNsense needs an XML file that tells it where to go. Create `custom.xml` and store it in the directory
`/usr/local/opnsense/scripts/suricata/metadata/rules/` with the following lines:
```xml
<?xml version="1.0"?>
<ruleset documentation_url="http://docs.opnsense.org/">
    <location url="https://raw.githubusercontent.com/matt-culbert/suricata_rules/main/" prefix="cnd"/>
    <files>
        <file description="rules for detecting CND">cnd.rules</file>
        <file description="Custom" url="inline::rules/cnd.rules">cnd.rules</file>
    </files>
</ruleset>
```

OPNsense ships with Vi only by default for editing files, it's not that bad I promise. With all that now in place, when you go back to the web GUI and reload the `Download` tab of the IDS, you should now see that Suricata has loaded your custom rules and you can download them.
![[Pasted image 20240628131747.png]]

But what do these Suricata rules look like? Let's review an example. C2's often use a non-standard port range and alerting on this is simple. In the below example, the rule action is to `alert` on traffic that uses the protocol `tcp` from a source of the `home_net` to a destination that is not the `home_net`, which is indicated through the `external_net` option with a `port` of anything higher than the standard range. Much like Python the syntax`1024:` just tells the rule to look for any port above 1024. Traffic flow for the rule is dictated by the `->`, indicating in this case that traffic flowing from the home network to a non-home network will be analyzed by it:
``` suricata
alert tcp $HOME_NET any -> any 1024: (msg:"A non standard port was requested HOME flow to EXTERNAL"; sid:100000001; rev:1;)
```

There's so much more to rules than that brief example, but I think it's more helpful to look at that in context to what we're doing. First, to be able to apply this to our scenario, we need to get an idea of what the C2 traffic looks like on the wire. OPNsense has a built in tool for just such an occasion. Under `Interfaces -> Diagnostics -> Packet Capture` you have the option to launch a packet capture for any interface. Select the appropriate one and, with C2 traffic running between it and a victim machine, begin your PCAP. 

After a sufficient amount of time with check-ins and command execution, there should be enough data in the PCAP so stop it, download it, and open it in WireShark. There's a lot that CloakNDagger gives defenders to begin searching for it on the wire. The first and easiest place to look at is the default certificate that it ships with. Just generate a JA3 fingerprint which Suricata can then use for alerts. Install `JA3` on the machine you're using to look at the PCAP with `pip install pyja3` and run `ja3 -a <pcap>`. The `-a` flag is required to find the `client Hello's` on any port:
![[Pasted image 20240628132652.png]]
>[!INFO]
>We will enable JA4 signatures later on when we re-install Suricata as part of the process for enabling Lua

For each stream in the PCAP, `JA3` outputs some details about the source and destination and two fingerprints of the server. The `digest` field is what we want to focus on right now as it's the most likely to be consistent between between captures. An example alert for tracking the digest can be seen below:
``` suricata
alert tcp any any -> any any (msg:"Match JA3 digest"; ja3.hash; content:"4287b6079ba0c8f574ae4d871aed15f9"; sid:10000003;)
```

And the following alert is what's generated:
![[Pasted image 20240628133055.png]]

That's all well and good but if that cert is rotated then this is no longer an effective alert. Have no fear, you can alert on quite a few field and multiple fields at the same time. Take for example the TTL seen in requests. While it is consistently `63`, this alone isn't enough to confidently say that seeing it is an IOC. However, combine this with also filtering on the header length, and now the rule is very scoped down to only the malicious traffic. 
``` suricata
alert tcp any any -> any any (msg:"Match header length and TTL"; ipv4.hdr; bsize:20; ttl:63; sid:100000002;)
```
![[Pasted image 20240708155753.png]]

Zooming back out to the broader picture, a general pattern that can be alerted on is how C2's generally check-in at a consistent pace. Compare the two traffic samples below, one a check-in process and the other a request for `yahoo.com`:
![[Pasted image 20240628140113.png]]
![[Pasted image 20240628141425.png]]

What this indicates is that a series of partial handshakes are being performed regularly and no data is being exchanged, i.e. a check-in is occurring where the C2 is queried for any waiting commands. A high jitter and sleep time can help lower this detection confidence but it's a very telltale sign of malicious traffic. An example alert would look like the following, taking advantage of the `threshold` flag to set a required number of occurrences and `track by_src` to set which address we are tracking the threshold by:
```suricata
alert tcp any any -> any any (msg: "Matched TCP flags for CND"; tcp.flags:AP; threshold: type threshold, track by_src, count 6, seconds 60; sid:100000006;)
```

Hmm this alert is quite noisy but there is a `type` set already as `threshold` which means that there can't be another limiter added. OPNsense again has you covered with the `threshold.config` file. This lets you set additional thresholds for any alert. In the case of the above rule, the added threshold will look like the following:
`threshold gen_id 1, sig_id 100000006, type limit, track by_src, count 1, seconds 60` 

Now you should only see one alert per tracked source IP every minute. This can be further adjusted as you see fit for your environment and be done for any rule you need. When writing rules, your environments uniqueness is your strength. You may find that the provided rules here are loud and alert on false positives without additional tuning. That's the great thing though about these rules, the patterns I set here only picked up the traffic I needed it to.  This is only the surface of Suricata and OPNsense - we haven't even touched the Lua scripting engine that can have traffic offloaded to it for further alert and log generation.
# Lua

Configuring Suricata to support Lua took maybe the longest part of this whole writeup. There's little documentation I've found from people who have added Lua support to OPNsense instances running the Suricata IDS so, through a *lot* of trial and error, I've tried to document the process here as fully as I can. I've walked through these steps a number of times on a fresh VM so I feel fairly confident nothing is missing. If you want to skip the manual configuration, I've also compiled the below steps into a `sh` script that [can be downloaded from my Git here](https://github.com/matt-culbert/suricata_rules/blob/main/lua_setup.sh). 
## Configuring Lua Support

Out of the box, Lua support is not enabled. You can check this by running `suricata --build-info | grep LUA` and you will get an output like the following (if yours *is* enabled, congrats!):
![[Pasted image 20240710123404.png]]

To enable this, there's a bunch of requirements that need to be met first. Rust needs to be installed alongside a few other `pkg` components. To install these run `pkg install lua54 autoconf automake libtool pkgconf wget git`. Next up is to download Rust. The download is piped right to `sh` which is always risky so review the URL and script before continuing. `curl https://sh.rustup.rs | sh`  and just use the default options. After this is installed, Rust requires some manual configuration. Using `vi`, edit `~/.cshrc` and at the bottom add the following entries: 
```
setenv PATH $HOME/.cargo/bin:$PATH
setenv CARGO_HOME $HOME/.cargo
```
Then run `source ~/.cshrc` after writing the changes to reload the terminal config.

Now to install Suricata. Instead of using `git` to clone the Suricata repo, which downloads the latest dev release, I suggest using `wget` to download the latest *stable* release. These can be found by navigating to https://github.com/OISF/suricata/releases. When you find a suitable version, download the `tarball` with `wget` by supplying it with the download URL, then `untar` it. Navigate into the new directory and run `git clone https://github.com/OISF/libhtp` to pickup the required library. Additionally, run `cargo install --force cbindgen` for a missing Rust library. Once both requirements are met, run `./autogen.sh` and `autoreconf --install`.

Before running `configure` and `make`, there's some manual linking required. Lua is currently setup in paths containing numbers but Suricata is not looking for those and so won't find it. An example can be seen below:
![[Pasted image 20240710132352.png]]
![[Pasted image 20240710132512.png]]

Resolving this requires creating a few symlinks:
```
ln -sf /usr/local/include/lua54/lua.h /usr/include/lua.h 
ln -sf /usr/local/include/lua54/lualib.h /usr/include/lualib.h 
ln -sf /usr/local/include/lua54/lauxlib.h /usr/include/lauxlib.h 
ln -sf /usr/local/include/lua54/luaconf.h /usr/include/luaconf.h
ln -sf /usr/local/include/lua54/ /usr/local/include/lua

ln -sf /usr/local/lib/liblua-5.4.a /usr/local/lib/liblua54.a 
ln -sf /usr/local/lib/liblua-5.4.so /usr/local/lib/liblua54.so

ln -sf /usr/local/libdata/pkgconfig/lua-5.4.pc /usr/local/libdata/pkgconfig/lua.pc
```
>[!WARNING]
>The file `lauxlib.h` is not misspelled and you may have misread it the first time. Trying to look out for all the other people reading things too quickly like myself.

We're getting close to the end, I promise.  Two more edits to make sure Lua can be found: `setenv LUA_CFLAGS "-I/usr/local/include/lua5.4"` and `setenv LUA_LIBS "-L/usr/local/lib -llua-5.4"`. These are setting compiler flags in the `Makefile`. Now it's finally time to run configure `./configure --enable-lua --with-lua=/usr/local/lib` followed by `make && make install-full` to complete the setup. Just restart the service and now when `suricata --build-info | grep LUA` is run, it shows as enabled.
>[!INFO]
>Keep in mind some of these paths may be different for you. If you try one and find that it results in an error while running `make`, be sure to re-run `configure` after each edit and before you try and run `make` again. Some errors may require you to go back a step further and run `./autogen.sh`. When all else fails, try `make clean`

If you run `suricata --build-info | grep yes` you can see all the enabled components. Among these, `JA4` is now enabled as well.
## Writing Lua Scripts

So you've got Lua enabled, but what does a Lua script look like? Suricata's [documentation is seriously your biggest asset](https://docs.suricata.io/en/suricata-6.0.18/rules/rule-lua-scripting.html#lua-scripting), use it, love it, cherish it. All scripts require an `init` function in them which determines which piece of the packet to pull in. We'll examine a script to generate an alert first. Different packet properties have different `needs`. For instance, to analyze TLS packets, the `init` function would look like the following:
```lua
function init (args)
    local needs = {}
    needs["tls"] = tostring(true)
    return needs
end
```

Then, to alert on a self-signed certificate, you would add something like the below. A quick explanation for the `return` statement, `1` is when you get a match and `0` is when you don't. 
```lua
function match (args)
    version, subject, issuer, fingerprint = TlsGetCertInfo()
    if subject == issuer then
        return 1
    end
    return 0
end
return 0
```

Using this in a rule is simple, just add `lua: script1.lua` anywhere you want it to be run. For instance, a simple version would look like this:
```suricata
alert tcp any any -> any any (msg: "Lua script found a self signed cert"; flow:established; lua: script1.lua; tls.store; sid:100000007;)
```

When the alert is triggered, it looks like the below:
![[Pasted image 20240710113244.png]]

There's more than just alerting however, there's also the option to generate robust log information. By changing the `init` function from `needs["tls"] = tostring(true)` to `needs["protocol"] = "tls"`  and the `match` function to `log`, you can now generate log messages for certain traffic patterns. The `log` scripts are more involved than `match` scripts as they also require additional `setup` functions and `deinit` functions, but it's not a big jump in difficulty.
# Wrapping Up

And that's it! I would say more than half the guide is dedicated to the proper configuration, but having that correct means way less headaches down the line. My goal with writing this was to help create a baseline with where to start with OPNsense and lay out some paths to progress with to expand what you've created here. You should have a set of interfaces, subnets, and three firewalls to fiddle with in addition to the IDS and Suricata rules. When you introduce Lua, the possibilities for detection methodology truly are endless. 

If you're unsure about next steps, one would be to play with the `drop` function for alerts. After all, if traffic patterns match your rules for malware, why should they be allowed to keep flowing freely? This will be a real test of your rule writing as you don't want to inadvertently affect normal traffic flows. Additionally, as I mentioned `JA4` support is enabled now for your rule engine, so check out the expanded fields offered. While this guide focused almost solely on the IDS side of OPNsense, there's a lot more to it than just this.

Other aspects of OPNsense you can consider are setting up the VPN service. There is a WireGuard VPN built into it and, for those uninitiated, WireGuard has quickly become one of the dominant forces in the VPN industry for good reason. It's fast, lightweight, and works on about any platform. Or if you want instead, you can start setting up additional interfaces with VLANs and learn more about VLAN tagging. And all of these services can be filtered through the IDS engine you spent so long setting up for yourself.
