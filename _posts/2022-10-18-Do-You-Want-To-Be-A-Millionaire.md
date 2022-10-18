# Do You Want To Be A Millionaire?

I got the weirdest phishing email the other day. It was a link to a cryptocurrency exchange called protoncoin[.]net with a username
and password. So naturally, I chose to go there and attempt to log in! They wanted a new phone number to enable MFA
since the account had such a large amount of money, so I made a fake number and set that up. I finally log in, and what
do I see?
![The main dashboard](/assets/img/ProtoCoin/WhatASight.png)

Yeah, um, wow that's a big number just sitting in an account that I now "own". So what's the catch, how is the scammer
going to make money because no one just donates 158 BTC to strangers.

# There's Gotta Be A Catch

"How can I get the money out of here" is the first question running through my head. Ignoring the feasibility of 
getting this moved from BTC to USD that I can ***actually spend without the IRS having an aneurysm***, how can I move
this into a wallet I actually own instead of sitting on a random exchange that doesn't allow new user signups. 

The astute among you have probably noticed already the "Withdraw" tab along the top bar, so let's check it out.

![Withdraw](/assets/img/ProtoCoin/WalletOrBank.png)

Ok so it seems you can either withdraw into another wallet or directly into your bank. However, bank deposits are 
frozen at this time (because this exchange is not at all real) so withdrawing to another wallet is 
our only option.

![Don't get ahead of yourself](/assets/img/ProtoCoin/NoWithdrawForYou.png)

Ah, the first catch. I cannot withdraw the whole account immediately, I have to send a verification amount of $2.
No big deal, send that and move on to trying to withdraw the rest. 

![The final hook](/assets/img/ProtoCoin/AndHeresTheScam.png)

I knew it had to be here somewhere. In order to withdraw the full amount in the account, I would need to bring the 
account balance up by, at the time of writing, $550~. No, I'm not going to deposit money into here. It's like the
Nigerian Prince scam but updated for cryptocurrency - you give me money so I can give you money. 

# What's The Actual Scam?

So what's the actual scam and who's operating this? The financial part is clear, they want you to deposit money. 
But who is running this operation?
The verification withdrawal I had to do into my wallet was legit and verified on the chain, and I am now $2 richer from it. 
However, this doesn't mean there is actually 158 BTC residing here. There's no recovery information attached to the 
account, so my best theory is that the site owners are operating this scam and can pull the rug out on any account
that hits this BTC goal. Backing this up, the domain appears to only be two weeks old as of posting.

![Domain Age](/assets/img/ProtoCoin/domainAge.png)

But from the first image, we can see that there are supposedly transactions on this account dating back to 2021. 
Looking this domain up further on a WhoIs site, the site is registered in Hong Kong which is a stark difference from
the UK which the site alludes to at the footer of their webpage.

![Wrong Location](/assets/img/ProtoCoin/domainLocation.png)

There are numerous other errors suggesting that the site was not coded by a native English speaker either. Looking
back through the messages I received while trying to withdraw the BTC, there were a lot of small mistakes that are
easy to overlook. Things like not capitalizing your "I" when used on its own, or how the sentence 
"To reduce cases of error withdrawals from new portfolios" just reads very oddly. 

It was fun for a time to pretend I was a Bitcoin millionaire though.
