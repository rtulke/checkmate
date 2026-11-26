# Reference

| Page | Contents |
|---|---|
| [Policy file](policy.md) | Top-level structure: metadata, `include`, `vars`, `vars_files`, `env`, `defaults`, `snippets`, `checks` |
| [Check keys](checks.md) | Every key a check can have |
| [expect operators](expect.md) | Exit code, comparisons, regular expressions, lists, line counts, combinations |
| [Templating and variables](templating.md) | Jinja2, variables, loops, snippets, raw blocks, available filters |
| [Platforms and facts](platforms.md) | Facts, platform variants, shells |
| [Command line](cli.md) | Commands, flags and exit codes |
| [Reports and exports](exports.md) | Output formats, `checkmate export` and `checkmate diff` |
| [Results, severity and score](results.md) | Statuses, `fail_on`, warnings and the compliance score |
| [Waivers](waivers.md) | Accepted deviations with reason, expiry date and host conditions |
| [Where a policy comes from](trust.md) | Shipped, modified and own policy files, their hashes in reports, signatures and `--require-signed` |
| [Inventory](inventory.md) | Hosts and groups for runs over SSH, their settings and variables, hosts that cannot be checked |
