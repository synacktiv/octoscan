# Octoscan

Octoscan is a static vulnerability scanner for GitHub action workflows.

## Table of Contents

- [Octoscan](#octoscan)
	- [Table of Contents](#table-of-contents)
	- [usage](#usage)
		- [download remote workflows](#download-remote-workflows)
		- [analyze](#analyze)
	- [rules](#rules)
		- [dangerous-checkout](#dangerous-checkout)

## usage

### download remote workflows

```sh
$ octoscan dl -h  
Octoscan.  

Usage:
	octoscan dl [options] --org <org> [--repo <repo> --token <pat> --default-branch --path <path> --output-dir <dir>]

Options:
	-h, --help  						Show help
	-d, --debug  						Debug output
	--verbose  						Verbose output
	--org <org> 						Organizations to target
	--repo <repo>						Repository to target
	--token <pat>						GHP to authenticate to GitHub
	--default-branch  					Only download workflows from the default branch
	--path <path>						GitHub file path to download [default: .github/workflows]
	--output-dir <dir>					Output dir where to download files [default: octoscan-output]
```

```sh
./octoscan dl --token ghp_<token> --org apache --repo incubator-answer
```

### analyze

If you don't know what to run just run this:
```sh
./octoscan scan path/to/repos/ --disable-rules shellcheck,local-action --filter-triggers external
```

It will reduce false positives and give the most interesting results.


```sh
$ octoscan scan -h
octoscan

Usage:
	octoscan scan [options] <target>
	octoscan scan [options] <target> [--debug-rules --filter-triggers=<triggers> --filter-run --ignore=<pattern> ((--disable-rules | --enable-rules ) <rules>) --config-file <config>]

Options:
	-h, --help
	-v, --version
	-d, --debug
	--verbose
	--json                    			JSON output
	--oneline                    			Use one line per one error. Useful for reading error messages from programs

Args:
	<target>					Target File or directory to scan
	--filter-triggers <triggers>			Scan workflows with specific triggers (comma separated list: "push,pull_request_target")
	--filter-run					Search for expression injection only in run shell scripts.
	--ignore <pattern>				Regular expression matching to error messages you want to ignore.
	--disable-rules <rules>				Disable specific rules. Split on ","
	--enable-rules <rules>				Enable specific rules, this with disable all other rules. Split on ","
	--debug-rules					Enable debug rules.
	--config-file <config>				Config file.

Examples:
	$ octoscan scan ci.yml --disable-rules shellcheck,local-action --filter-triggers external
```


## rules

### dangerous-checkout

Triggers like `workflow_run` or `pull_request_target` run in a privileged context, as they have read access to secrets and potentially have write access on the targeted repository. Performing an explicit checkout on the untrusted code will result in the attacker code being downloaded in such context.

![excalidraw](img/excalidraw.png)

The tool curently detect the following vulnerability:
- usage of public dangerous actions (dangerous-action)
- git checkout performed by a dangerous workflow trigger (dangerous-checkout)
- write to `$GITHUB_ENV`, writing data to `$GITHUB_ENV` == RCE (dangerous-write)
- expression injection, for example using `${{github.event.issue.title}}` can result in RCE (expression-injection)
- usage of actions referencing a non existing user or org (repo-jacking)
- usage of OIDC action to get access tokens, it's not a vulnerability but can be interesting to check (oidc-action)
- usage of static credentials in action (credentials)
- usage of self hosted runners (runner-label)
- usage of `ACTIONS_ALLOW_UNSECURE_COMMANDS` (unsecure-commands)
