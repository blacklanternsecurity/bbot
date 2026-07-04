# Scan Sanity Guide

BBOT's recursive nature is a double-edged sword. Let's talk about the *bad* edge. Any scan is a few settings away from scanning the entire internet, or sending millions of packets to your targets and never finishing.

There are two things to consider when trying to keep your scan "sane": your scan settings (modules and config choices) and your target.

## Scan Settings

Back in the earliest days of BBOT there was once an `--all` feature that turned on every module. That was fine when there were only a handful of modules, but as BBOT grew it quickly became a terrible idea, so we removed it.

Imagine you turn on -f `subdomain-enum`, -m `http` and `webbrute`, and -p `lightfuzz`. This *might* be a reasonable scan if you only had a few targets. But let's say your subdomain-enum ends up finding 1000 websites.

For each of those 1000 websites, webbrute is going to brute-force every directory it knows about. By default that's 5000 requests. Enable recursion and every directory it finds kicks off another 5000. Then, for every URL that turns up, lightfuzz sends its full suite of probes (in the hundreds).

But that's not all, because while that's happening the content of each page is being parsed for additional links. If you also turned on `-p spider`, every one of those gets re-emitted. It feeds into itself.

Let's imagine you also enabled `-p wayback-heavy`, so each host also gets a queue of every wayback URL result. This can very quickly devolve into gigantic queues that never drain. And although we've put a lot of effort into optimizing memory, BBOT is memory-unbounded: theoretically you could have a scan big enough that it eventually takes all of your RAM.

On the other hand, with maybe five hard-coded URLs? This might be a pretty nice scan for doing an initial recon before a web assessment. 

We realize that when most people crack open a security tool, they just want to run it with all the settings. We get that. That's one of the reasons we added presets in the first place: to help people pick pre-configured settings to suit different tasks, and also to empower people to create their own. But you can stack multiple presets, and things can very quickly get out of hand.

We allow you a ton of flexibility with your scans: you can add any combination of modules, flags, and presets, add presets while excluding modules, exclude flags, and so on. However, there are a few things you **can** do that are just plain a terrible idea, and that might not be super apparent. We'll walk through one of them below, but it's far from the only one:

### The `active` flag

```
bbot -f active
```

This is bad for multiple reasons! Every module is required to have EITHER `active` or `passive`. So by just selecting `active`, you are guaranteeing that all of the most aggressive modules are also included, since they would obviously be active. Furthermore, this WON'T run the passive modules, which are actually pretty important for most any scan!

This is probably a design flaw we need to work on in the future (perhaps active or passive should be a module attribute, rather than a flag), but for now we're hoping this guide can steer people in the right direction. Where the `active` flag is genuinely useful is with `-ef active`: excluding it when you want to be really careful about how aggressive the scan is.

If you truly just want the "throw everything at it" experience, we do have a preset for you: `kitchen-sink`. It's basically the most insane scan setting we can officially endorse, with the caveat that you still wouldn't want to point it at a very large target.

### Settings best left alone

Most of BBOT's config is safe to tune. A small handful of settings are not, and this is where the warning at the top of this guide really bites: it wouldn't take more than one or two of these, nudged the wrong way, to go from a tidy scoped scan to trying to enumerate the entire internet. Unless you know exactly why you're changing them, leave these at their defaults:

- **`scope.search_distance`** (default `0`) is the big one. It controls how many hops out from your target BBOT is allowed to explore. At `0`, modules only act on in-scope events. Raise it and a single certificate full of affiliate names pulls in those hosts, then *their* subdomains, then *their* infrastructure, and scope balloons outward hop by hop until there's no natural stopping point. The config comment says it outright: don't change this unless you know what you're doing. (This is *not* the same as `dns.search_distance`, which only governs DNS resolution and is safe to adjust.)
- **`web.spider_distance`** / **`web.spider_depth`** (default `0` / `1`). A `spider_distance` of `0` means no spidering at all. Raise it and the crawler follows links from links from links, and every URL it turns up feeds webbrute and lightfuzz. On a large site that loop is effectively unbounded.
- **`dns.threads`** / **`dns.brute_threads`** (default `10` / `1000`) control DNS concurrency. Cranking them won't make your scan meaningfully faster (the real lever is adding more resolvers to `/etc/resolv.conf`); it'll just flood your nameservers and get you rate-limited.
- **`dns.runaway_limit`** (default `5`) and **`dns.wildcard_disable`** (default `false`) are guardrails. `runaway_limit` stops BBOT from chasing a malicious chain of DNS records forever, and wildcard detection is the only thing keeping a `*.example.com` wildcard from spawning infinite bogus subdomains. Turning either off removes a safety net that's there for a reason.

## Scan Target

When it comes to the scan target, the main thing to keep in mind is that by default, every domain added to a target also brings all of its possible subdomains into scope. Some domains are truly massive, with thousands and thousands of subdomains, and you're saying they are ALL in scope. `--strict-scope` can be useful here: it changes that behavior so subdomains of targets aren't automatically included in scope. Great if you actually just want to target `evilcorp.com` directly, and NOT `a.evilcorp.com`, `b.evilcorp.com`, `c.evilcorp.com`, etc., which would likely be found during the scan.

Using an IP-based scope is often a great choice, because it allows you to be very specific about what you want scanned when you don't know the full extent of what `*.whatever.com` actually has in it. For example, a lot of big organizations own their own ASN, where they host a lot of content. But they'll also have a lot of services running with third parties, often pointed to by subdomains in `*.whatever.com`. So if you just want targets within `whatever.com`'s ASN but still want to do subdomain discovery, you can use a seed.

```
bbot -s whatever.com -t 192.168.0.0/24 
```

Here, BBOT will do subdomain enumeration against whatever.com, but only things that resolve within 192.168.0.0/24 will be in-scope, so none of your active modules will actually go after anything outside that range (a generalization: active modules CAN be configured to step out of scope, but generally aren't).


