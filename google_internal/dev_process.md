# Dev process

[TOC]

## Git-on-Borg Repo

There are several ways to view the code

*   [GoB UI](https://privacysandbox.git.corp.google.com/hats/)
*   [Gerrit UI](https://privacysandbox-review.git.corp.google.com/admin/repos/hats,general)
*   [Code Search](https://source.corp.google.com/h/privacysandbox/hats)

We also have a test repo under `hats-test`

## Getting started

### Environment setup

Get docker via [go/install-docker](http://go/install-docker)

Install
[Git-on-Borg](https://g3doc.corp.google.com/company/teams/gerritcodereview/users/user-repository.md#getting-started):

```shell
sudo apt install git-all git-remote-google
```

Set up name and email:

```shell
git config --global user.name "Your Name"
git config --global user.email {{USERNAME}}@google.com
```

#### Optional: Helpful git aliases {#alias}

These are some useful aliases that can be added to `~/.gitconfig`.

`git cl`, based on [go/gob/users/intro-codelab#create-a-change](http://go/gob/users/intro-codelab#create-a-change).
This lets `git cl` push to gerrit without remembering the args.
`git cl other-branch` also works.

```shell
[alias]
        cl = "!f() { \
          git push origin HEAD:refs/for/${1:-main}; \
        }; f"
```

`git amend`: Add `amend = commit --amend --no-edit`.
This helps when editing a commit without needing to change the message.

### Initial repo setup

Clone the repo from the [Gerrit UI](https://privacysandbox-review.git.corp.google.com/admin/repos/hats,general).
Use the **Clone with commit-msg hooks** command.

#### Submodules {#submodules}

To initialize the repo's submodules, or to refresh them:

```shell
git submodule update ---init --remote --force
```

### Pre-commit checks

Pre-commit checks are executed before commits to check formatting, etc.

They execute on every commit, and most only check changed files.
Currently, it is configured to halt on the first failed test.
Note that some tests modify files (e.g. clang-format), which are reported as "files were modified by this hook", and can be checked by `git status` and `git diff`.
Other checks others simply warn (e.g. cpplint), and need to be manually fixed through editing files.
Once the check is fixed (automatically or manually), re-add and re-commit.

#### Installation

The setup needs to be done once in the repo, to set up the hook.
Note that due to symlinks for configurations, [submodules](#submodules) need to be initialized

```shell
builders/tools/pre-commit install
```

This uses builders to run via a docker image.
The first time may be slow to first set up the image, but should be the same as long as the config stays the same.
Note that the image is also set up following the [rbe\_setup](#rbe).

Alternatively, you can use a local version of pre-commit

```shell
sudo apt install pre-commit
pre-commit install
```

#### Other useful commands

To skip the pre-commit checks, use:

```shell
git commit -no-verify
```

To run the checks on all files without committing, use one of the following:

```shell
builders/tools/pre-commit     # This runs on the whole repo
pre-commit run                # Only changed files by default, add `-a` to run on the whole repo
```

To disable the hook entirely, remove/rename `.git/hooks/pre-commit`

## Making changes

Set up a new workspace (using main as a clean branch)

```shell
git checkout main
git pull
git checkout -b my-cl origin/main
```

After making changes, the usual git flow follows

```shell
git add file    # For all files, (git add .) or (git add -a)
git status      # check on files. Recommend also do before add all
git commit      # Optional (-m "commit message")
```

To link to a buganizer ID, add a line with `Bug: b/<bug id>` or `Bug: <bug id>` to the commit message.

Send the CL to Gerrit:
If you set up the [alias](#alias) `git cl` for main, or `git cl other-branch` works too.

```shell
git push origin HEAD:refs/for/main
```

Optionally, pull (and rebase/resolve conflicts) before each push.

If there are unknown changes to the submodules

### Updating a CL

If you want to update the cl (such as in response to comments):

```shell
git add file                         # or all via (git add .) or (git add -a)
git status                           # Check on things. Also git diff --staged
git commit --amend                   # Update the same
git push origin HEAD:refs/for/main   # Update Gerrit review with new patchset
```

Note that the amend and push can be replaced by `git amend` and `git cl` respectively if the [aliases](#alias) are set up.

For changing commits in a chain, try `git rebase -i`

## RBE setup, and building {#rbe}

Bazel execution can be sped up immensely using remote build execution and caching.
This uses Kiwi's GCP, so follows similar instructions

### One time setup

1.  Install gcloud via `sudo apt install google-cloud-cli`.
    For other options, see go/gcloud-cli#advanced-instructions.

1.  Set up account info

    ```shell
    gcloud config set account ${USER}@google.com
    gcloud config set project kiwi-air-force-remote-build
    ```

1.  Log in

    ```shell
    gcloud auth application-default login
    ```

    Also, run this if `bazel_rbe` gives errors about e.g. metadata

1.  Restart bazel

    If you have been using `bazel`, and are switching to `bazel_rbe`,
    then bazel needs to reboot to recognize the new credentials

    ```shell
    bazel shutdown
    ```

### Per terminal setup

Run this in each new terminal window / shell:

```shell
source google_internal/rbe_setup.sh
```

### Build and run

Use `bazel_rbe` in place of `bazel` for general use.
E.g. to run all tests:

```shell
bazel_rbe test //...
```

You should see **remote cache hit*** in the bazel output.

TODO(b/351201455): Support for `builders/tools/bazel-debian instead`.
This sets up RBE for it, but it currently doesn't build.

## Additional information

### Shellcheck

Shellcheck code descriptions can be seen on the wiki, e.g. at [https://www.shellcheck.net/wiki/](https://www.shellcheck.net/wiki/)

Errors/warnings can be bypassed using a [directive](https://github.com/koalaman/shellcheck/wiki/directive).
The easiest is to add a comment related to the code.

```shell
# shellcheck disable=1091
. lib_build.sh   # some line of code that gives 1091 error
```

Shellcheck supports following through imported/executed files within a script.
However, this takes in the `-x` flag, which Kiwi does not use in their presubmit configuration, so currently we also don't.
Therefore 1091 errors specifically should be always be disabled with a directive.

This can still be tested locally using `shellcheck -x my-script.sh`
Rather than the disable directive, the path to the file can be done with `# shellcheck source=path/to/lib.sh`.
Note that this is just for local checking, and currently will not work with pre-commit.
