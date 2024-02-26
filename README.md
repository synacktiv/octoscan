# Octoscan

## description

Octoscan is a static vulnerability scanner for GitHub workflows.

## usage

The tool is still in development, ping hugov if you need help.


### download remote workflows

```sh
$ ./octoscan dl -h  
Octoscan.

Usage:
	octoscan dl [options] --org <org> [--repo <repo> --token <pat> --path <path> --output-dir <dir>]

Options:
	-h, --help  						Show help
	-d, --debug  						Debug output
	--verbose  						Verbose output
	--org <org> 						Organizations to target
	--repo <repo>						Repository to target
	--token <pat>						GHP to authenticate to GitHub
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
octoscan

Usage:
	octoscan scan [options] <target>
	octoscan scan [options] <target> [--debug-rules --filter-triggers <triggers> --filter-run --ignore=<pattern> ((--disable-rules | --enable-rules ) <rules>) --config-file <config>]

Options:
	-h, --help
	-v, --version
	-d, --debug
	--verbose
	--json						Json
	--oneline					Use one line per one error. Useful for reading error messages from programs

Args:
	<target>					Target File or directory to scan
	--filter-triggers <triggers>			Scan workflows with specific triggers (comma separated list: "push,pull_request_target,")
	--filter-run					Search for expression injection only in run shell scripts.
	--ignore <pattern>				Regular expression matching to error messages you want to ignore.
	--disable-rules <rules>				Disable specific rules. Split on ","
	--enable-rules <rules>				Enable specific rules, this with disable all other rules. Split on ","
	--debug-rules					Enable debug rules.
	--config-file <config>				Config file.

Examples:
	$ octoscan scan ci.yml --disable-rules shellcheck,local-action --filter-triggers external
```

```sh
./octoscan scan test/test.yml  
test/test.yml:15:19: "password" section in "container" section should be specified via secrets. do not put password value directly [credentials]
   |
15 |         password: pass
   |                   ^~~~
test/test.yml:22:21: "password" section in "redis" service should be specified via secrets. do not put password value directly [credentials]
   |
22 |           password: pass
   |                     ^~~~
test/test.yml:26:32: Expression injection, "github.event.issue.body" is potentially untrusted. [expression-injection]
test/test.yml:35:15: Use of dangerous action "dawidd6/action-download-artifact@v2" [dangerous-action]
   |
35 |         uses: dawidd6/action-download-artifact@v2
   |               ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
test/test.yml:40:15: Use of local action "./.github/actions/custom-action/action.yml" [local-action]
   |
40 |       - uses: ./.github/actions/custom-action/action.yml
   |               ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
test/test.yml:50:18: Expression injection, "github.event.issue.title" is potentially untrusted. [expression-injection]
   |
50 |         uses: ${{github.event.issue.title}}
   |                  ^~~~~~~~~~~~~~~~~~~~~~~~~~
test/test.yml:58:24: Expression injection, "env.**" is potentially untrusted. [expression-injection]
   |
58 |         run: echo "${{ env.FOO }}"
   |                        ^~~~~~~
test/test.yml:64:23: Expression injection, "steps.**.outputs.**" is potentially untrusted. [expression-injection]
   |
64 |         run: echo ${{ steps.check_deps.outputs.dependencies }}
   |                       ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
test/test.yml:67:23: Expression injection, "needs.**.outputs.**" is potentially untrusted. [expression-injection]
   |
67 |         run: echo ${{ needs.prerequisites.outputs.dependencies }}
   |                       ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
test/test.yml:83:55: Use of "downloadArtifact" in "actions/github-script" action. [dangerous-action]
   |
83 |             var download = await github.actions.downloadArtifact({
   |                                                       ^~~~~~~~~~~~

```


## rules

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
