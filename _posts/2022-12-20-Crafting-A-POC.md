# Finding The Issue

The Linux kernel is a great testing ground for figuring out how to write proof of concept code. 
The changes are public and they show how the vulnerability was fixed.
In the case of CVE-2022-42719, the issue was that "A use-after-free in the mac80211 stack when parsing a multi-BSSID element in the Linux kernel 5.2 through 5.19.x before 5.19.16 could be used by attackers (able to inject WLAN frames) to crash the kernel and potentially execute code."
A BSSID is the Basic Service Set ID - essentially the MAC address of your router. 
A Multi-BSSID "allows an AP to collapse information for collocated networks running on the same Wi-Fi channel into a single beacon or probe response frame. It avoids sending the same information elements (e.g., Supported Rates, HE Capabilities, HE Operation, etc.) in separate beacons or probe responses, unnecessarily consuming more airtime."
From the code below, we can determine that the issue stems from the nontransmitted element profile, which is a sub-element of the Multi-BSSID element.



```C
+	size_t scratch_len = params->len;
 
-	elems = kzalloc(sizeof(*elems), GFP_ATOMIC);
+	elems = kzalloc(sizeof(*elems) + scratch_len, GFP_ATOMIC);
 	if (!elems)
 		return NULL;
 	elems->ie_start = params->start;
 	elems->total_len = params->len;
-
-	nontransmitted_profile = kmalloc(params->len, GFP_ATOMIC);
-	if (nontransmitted_profile) {
-		nontransmitted_profile_len =
-			ieee802_11_find_bssid_profile(params->start, params->len,
-						      elems, params->bss,
-						      nontransmitted_profile);
-		non_inherit =
-			cfg80211_find_ext_elem(WLAN_EID_EXT_NON_INHERITANCE,
-					       nontransmitted_profile,
-					       nontransmitted_profile_len);
-	}
+	elems->scratch_len = scratch_len;
+	elems->scratch_pos = elems->scratch;
+
+	nontransmitted_profile = elems->scratch_pos;
+	nontransmitted_profile_len =
+		ieee802_11_find_bssid_profile(params->start, params->len,
+					      elems, params->bss,
+					      nontransmitted_profile);
+	elems->scratch_pos += nontransmitted_profile_len;
+	elems->scratch_len -= nontransmitted_profile_len;
+	non_inherit = cfg80211_find_ext_elem(WLAN_EID_EXT_NON_INHERITANCE,
+					     nontransmitted_profile,
+					     nontransmitted_profile_len);
-	kfree(nontransmitted_profile);
-
 	return elems;
 }
 
```

"The Nontransmitted BSSID Profile sub-element contains a list of information elements that, together with the elements sent in the beacon or probe response, define the set of elements for the nontransmitted BSSID."
The first thing we should do then is craft a packet in Scapy and try to cause the exploit.
A use-after-free exploit is triggered when a program fails to remove a pointer to a recently freed memory location.
We can see in the code that one of the removed lines is for the kfree function, so from this we can infer that the
pointer to this location is not properly removed. This puts us in an interesting position. We do not actually need
physical access to the device in order to exploit this, it can be exploited over WiFi.


# Testing It Out

Alright, we have our theory, but now we have to actually test this out. First we'll need a machine capable of listening
to the wireless network, a machine that can inject WLAN frames, and the code to do so.

##***References***
> https://www.intuitibits.com/2021/08/24/the-multiple-bssid-element-improving-airtime-efficiency/
> 
> https://git.kernel.org/pub/scm/linux/kernel/git/wireless/wireless.git/commit/?id=ff05d4b45dd89b922578dac497dcabf57cf771c6
> 
> https://encyclopedia.kaspersky.com/glossary/use-after-free/
> 
> Further reading on kmalloc, GFP, and kfree in C https://stackoverflow.com/a/20118572/9329272