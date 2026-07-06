# Contributing to BBOT

We welcome contributions! There are a number of ways to contribute to BBOT.

If you want to chat about BBOT or get help with a contribution, come find us on [Discord](https://discord.com/invite/PZqkgxu5SA).

## Open an Issue

Opening an issue is the simplest way to contribute. If you spot a bug or see a way to improve something, open an issue and we'll do our best to address it promptly.

## Open a Discussion

If you have an idea for a new module or feature, or just have questions about existing modules, discussions are the correct place for it. Issues opened for these items will most likely be moved here anyway.

## Pull Requests

We love pull requests. Before you submit them though, there are a few things to discuss.

### Should It Be an Issue Instead?

As AI-assisted contributions have become more common, we've seen an increase in large PRs trying to change things that touch complex core internals. Much of the core BBOT code is extremely complicated and load-bearing. If your AI doesn't grasp the full context, untangling your PR is going to take us longer than if we made the changes ourselves.

Basically, don't feel pressured to submit a fix just because you found a bug. If the fix isn't straightforward, an issue that shows clearly how to reproduce the problem is often more helpful than a sprawling PR.

### AI Policy

Modern AI is an incredibly valuable tool for development. We definitely use it. However, it is still just a tool, and it REALLY matters how you use it.

- **Blind trust is not good.** Even the most advanced models make horrific mistakes, just as they have moments of brilliance.
- **Human accountability.** If your name is on the code, it's up to you to understand it. A simple rule: don't submit anything you don't understand.
- **No low quality submissions.** If you just submitted the same slop PR to 20 other repos, we are going to close it. If it ignores all the normal patterns in use in BBOT and does its own thing, we are going to close it. If you make a good-faith attempt at doing it right, we're more than happy to help you along.
- **Don't let the AI edit tests.** Of course, there will be some times where a test edit is legitimately needed, but this is a common antipattern for AI agents. 

We don't require AI disclosure, but it's welcome (and honestly, we can usually tell). If you'd like to include one, add a short **AI Use Disclosure** at the bottom of your PR: how extensively AI was used (fully autonomous, a collaborative back-and-forth, or an AI review of your own work) and which model.

We provide an [AGENTS.md](https://github.com/blacklanternsecurity/bbot/blob/dev/AGENTS.md) file in the repo root. Feed this to your LLM before working on BBOT. It describes our conventions and should help steer AI-assisted contributions in the right direction.

### Other Advice

- **Work off the `dev` branch.** Almost all PRs should target `dev`, not `stable`. Create your feature branch from `dev` and open your PR against it.
- The pull requests we are most likely to approve are ones that address a very specific thing in a focused way. Don't let that stop you from writing a whole new, even complicated module. However, expect some critical feedback and some rounds of revisions.
- Be mindful of security. We have had multiple CVEs, including critical CVEs. If your module is doing potentially dangerous things like running commands, reading and writing files, etc. -  expect a lot of extra scrutiny.

### Tests

We believe tests are the backbone of any large scale project. Think of them like a save-point for a capability. Without them, regressions constantly creep in and accumulate.

Every module MUST have module tests. There are tons of examples to draw from with existing modules. We can also help you write the tests. They shouldn't be there just to be there, they should really exercise as much of the code in your module as possible. 

If you make a change to any core code, helpers, etc - chances are if you break anything, our massive amount of tests (as of this writing's creation over 300) will catch it. So run them. Try to run the entire test suite against your code before you submit it. 

For more details, see [Unit Tests](./dev/tests.md).

## Contributor License Agreement

Like many open-source projects, we ask that you sign our [Contributor License Agreement](https://github.com/blacklanternsecurity/CLA/blob/main/ICLA.md) before we can accept your contribution.

## Development

Ready to dive in? See the following links to get started:

- [Setting up a Dev Environment](./dev/dev_environment.md)
- [How to Write a BBOT Module](./dev/module_howto.md)
- [Discord Bot Example](./dev/discord_bot.md)
