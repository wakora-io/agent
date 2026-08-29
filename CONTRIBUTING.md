# Contributing

This repository is published so you can read, audit and rebuild the agent that runs on your
machines. It is developed in-house and **we do not accept external pull requests.** That is
a licensing decision, not a judgement of your patch: the source is under the Elastic
License 2.0 and taking outside copyright into it would require a contributor agreement we
have deliberately not set up.

Please do not spend your time on a PR here. It will be closed unread, which is a waste of
your effort and rude of us to invite.

## What is genuinely useful

**Security reports.** See [SECURITY.md](SECURITY.md). These get read the same day.

**Bug reports.** If the agent misbehaves on your host, open an issue with the output of:

```bash
wakora doctor
```

plus the agent version, the platform, and the relevant lines from
`/var/log/wakora/agent.log`. Redact anything you would not want public. If the problem
involves your data, contact support instead of filing an issue.

**Telling us a probe is wrong.** If a metric we emit does not match what the service itself
reports, that is worth an issue and we will want the numbers from both sides.

**Asking for a service.** The catalog of monitored services is driven by signed definitions
delivered from our side, so adding one does not need a code change or a release here. Ask
for it and it can appear on existing installs.

## If you want to run your own build

That is allowed and no permission is needed for machines you control. See the build section
in the [README](README.md); note that a release build takes its endpoint, certificate pin
and publisher key at link time, so a build without them will start and do nothing useful.
