# A quick story of a misconfiguration

This is a very quick post, I'm working on others I promise. On Dec 8, I went to my site, git.culbertreport.com, and all looked good. I then went to cr.culbertreport.com to try and fix an issue with that returning a 404 and I found a crypto site.

![Defacement](/assets/img/subdomain_takeover/my_poor_site.png)

I'm not going to lie, I kinda panicked for a minute. What happened, was my Cloudflare hacked, how I have 2fa, was my Git hacked and also how since I have 2fa there, was my SIM copied, and down the rabbit hole I spiraled for a minute while looking through records. All looked good in Cloudflare.

![All looks normal](/assets/img/subdomain_takeover/cloudflare_domain.png)

So I had to look elsewhere and remembered that the domain is also configured through GitHub. On GitHub pages, you set a custom domain for fancier domain names than just 'xxx.github.io' and mine is currently 'git.culbertreport.com'

![Git Pages](/assets/img/subdomain_takeover/custom_domain.png)

But back when this site was hosted through Google, I had used the subdomain 'cr.' When I transferred to Cloudflare I had kept it in the hopes of eventually fixing the routing with it and some others but I just never dedicated a lot of time to the issue and honestly didn't think too much of it since it returned only a 404. This then got me thinking, did someone setup their 'pages' setting with 'cr.culbertreport.com' taking advantage of my routing?

![Hunting](/assets/img/subdomain_takeover/hunting_the_configuration.png)

Yep! Sure looks like someone did just that. Let's take a look at what else this person is doing.

![A lotta commits](/assets/img/subdomain_takeover/the_perps_git.png)

That sure is a lot of commits in just a few days, they must be working really hard. This is a classic example of subdomain takeovers. You can [read more about it through Mozilla](https://developer.mozilla.org/en-US/docs/Web/Security/Subdomain_takeovers). I got so lucky that this had only been up for a few days and I happened upon it by chance, and this is really a cautionary tale about keeping tidy and up to date DNS records. I reported the user to GitHub, let's hope the person is taken down quickly.
