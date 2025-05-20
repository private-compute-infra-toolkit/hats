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

`git cl`, based on
[go/gob/users/intro-codelab#create-a-change](http://go/gob/users/intro-codelab#create-a-change).
This lets `git cl` push to gerrit without remembering the args. `git cl
other-branch` also works.

```shell
[alias]
        cl = "!f() { \
          git push origin HEAD:refs/for/${1:-main}; \
        }; f"
```

`git amend`: Add `amend = commit --amend --no-edit`. This helps when editing a
commit without needing to change the message.

### Initial repo setup

Clone the repo from the
[Gerrit UI](https://privacysandbox-review.git.corp.google.com/admin/repos/hats,general).
Use the **Clone with commit-msg hooks** command.

#### Submodules {#submodules}

To initialize the repo's submodules, or to refresh them:

```shell
git submodule update --init --remote --force
```

### Pre-commit checks

Pre-commit checks are executed before commits to check formatting, etc.

They execute on every commit, and most only check changed files. Currently, it
is configured to halt on the first failed test. Note that some tests modify
files (e.g. clang-format), which are reported as "files were modified by this
hook", and can be checked by `git status` and `git diff`. Other checks others
simply warn (e.g. cpplint), and need to be manually fixed through editing files.
Once the check is fixed (automatically or manually), re-add and re-commit.

#### Installation

The setup needs to be done once in the repo, to set up the hook. Note that due
to symlinks for configurations, [submodules](#submodules) need to be initialized

```shell
builders/tools/pre-commit install
```

This uses builders to run via a docker image. The first time may be slow to
first set up the image, but should be the same as long as the config stays the
same. Note that the image is also set up following the [rbe\_setup](#rbe).

If you are committing from elsewhere (such as VSCode), then you may need to
build the image first before it works with VSCode (committing in terminal or
running `rbe_setup.sh`). Note also that failure messages this way may be
different.

Alternatively, you can use a local version of pre-commit. This may require you
to download the tools yourself (such as `shellcheck`).

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
This makes it easier to repeatedly call w/o add/commit.

```shell
builders/tools/pre-commit     # This runs on the whole repo
pre-commit run -a             # Whole repo, without -a for just staged
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

To link to a buganizer ID, add a line with `Bug: b/<bug id>` or `Bug: <bug id>`
to the commit message.

Send the CL to Gerrit: If you set up the [alias](#alias) `git cl` for main, or
`git cl other-branch` works too.

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

Note that the amend and push can be replaced by `git amend` and `git cl`
respectively if the [aliases](#alias) are set up.

For changing commits in a chain, try `git rebase -i`

## RBE setup, and building {#rbe}

Bazel execution can be sped up immensely using remote build execution and
caching. This uses Kiwi's GCP, so follows similar instructions

### One time setup

1.  Install gcloud via `sudo apt install google-cloud-cli`. For other options,
    see go/gcloud-cli#advanced-instructions.

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

    If you have been using `bazel`, and are switching to `bazel_rbe`, then bazel
    needs to reboot to recognize the new credentials

    ```shell
    bazel shutdown
    ```

### Per terminal setup

Run this in each new terminal window / shell:

```shell
source google_internal/rbe_setup.sh
```

### Build and run

Use `bazel_rbe` in place of `bazel` for general use. E.g. to run all tests:

```shell
bazel_rbe test //...
```

You should see **remote cache hit*** in the bazel output.

### Bazel Debian

The code can also be built and run via `builders/tools/bazel-debian` instead.
This currently must be done through a wrapper, for example
`google_internal/bazel_debian.sh test //...`. This takes in flags set by
`rbe_setup.sh`. See b/351201455 for more details.

## Additional information

### Status macros

Codebase has useful macros for dealing with Status and StatusOr.
Based on privacysandbox/data-plane-shared-libraries and //util

For more details see Readme in status_macros folder

### Shellcheck

Shellcheck code descriptions can be seen on the wiki, e.g. at
[https://www.shellcheck.net/wiki/](https://www.shellcheck.net/wiki/)

Errors/warnings can be bypassed using a
[directive](https://github.com/koalaman/shellcheck/wiki/directive). The easiest
is to add a comment related to the code.

```shell
# shellcheck disable=XXXX
source lib_build.sh   # some line of code that gives XXXX error
```

### Clangd

clangd is a C++ analyzer that hooks into an editor. See go/clangd and
[the external docs](https://clangd.llvm.org/installation#editor-plugins) for
linking it to your editor.

Use `bazel run @hedron_compile_commands//:refresh_all` to build
`compile_commands.json`, which lets clangd know how to build code. If there are
errors, it may sometimes help to do a normal `bazel build //...`.

There are several issues that can be ignored. * `*.rs.h` includes it sometimes
views as recursive. `#pramga once` fixes it while include guards don't. * The
builtin `_mm_getcsr` that comes from `.pb.h` it flags. This is likely related to
similar past issues (b/35888333) with clangd.

### Depend what you use

Depend-what-you-use tries to have dependencies match includes for C++. It can be
run via `bazel_rbe build --config=dwyu --verbose_failures=false //target`. Some of the issues it runs
into are skipped via `dwyu_ignore_includes.json`, but this is unable to cover
everything. This covers includes that are hard to add, may incorrectly think
unnecessary, or come transitively.

It is unable to handle `rust_cxx_bridge` builds. Generally, it can help to run
it on more narrow targets to avoid rust bridges.
In addition, `@com_github_grpc_grpc//:grpc++` may be incorrectly declared unnecessary. Make
sure build still works.

### VS Code Development

The rust analyzer plugin doesn't recognize a rust project through bazel build
files (only cargo files by default). We must run `bazel run
@rules_rust//tools/rust_analyzer:gen_rust_project` and restart the rust-analyzer
server to
[enable this](https://bazelbuild.github.io/rules_rust/rust_analyzer.html).
