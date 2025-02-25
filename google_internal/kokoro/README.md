# Kokoro integration

Kokoro [(go/kokoro)](go/kokoro) is used to perform presubmit testing. For each
cl, it runs tests on every revision, and votes +1/-1 depending on if it
succeeds.

## Quick Guides

### Checking Failure reasons

1.  Open the latest comment where Kokoro reports FAILURE (generally the one with
    a -1).
1.  Click the second link for `Logs at:`
1.  Check "Target Log" for general execution. Errors should be at the bottom.
    1.  If it says the log will appear once it starts executing, then likely
        Kokoro failed to set up. See below. (The link also leads to the build
        log)
    1.  Generally, test results will show up at the bottom, and info around the
        failing test should be nearby.
    1.  If the error is something along the lines of `no such package` and
        `error running git fetch`, this is likely a repository issue, and Kokoro
        needs to clone the repo.
1.  If Kokoro failed to set up, check "Build log" up on the upper menu bar.
    1.  This is generally if Kokoro itself is not set up correctly. For example,
        insufficient permissions for the relevant repositories.

### Bypassing Kokoro

Currently, the vote has no impact on the ability to submit, so nothing is
needed. This is due to slowness (RBE/docker will improve this) and volatility
(not fully set up yet). Therefore, no bypass is needed, cl's can be submitted
with a -1 Kokoro vote or if Kokoro is still running.

In the future, once the vote has an impact, the plan is to have an override mdb
group also able to set the vote. This will allow for submission when Kokoro
breaks, or when a submit/fix needs to go through fast without waiting. This can
also allow submitting w/ new submodules without needing to update permissions,
but note this will break all future cl's too until Kokoro updates.

### Adding permissions / repositories

When e.g. adding a sub-module or other import that Kokoro needs permissions to.

1.  Update
    [git\_on\_borg\_resource\_acl.gcl](http://google3/devtools/kokoro/config/data/git_on_borg_resource_acl.gcl),
    for access permission
    1.  Find `privacy-sandbox/hats` job prefix
    1.  Add the repo url(s) (or prefix). This should probably `rpc://`. This
        should also cover any imported sub-modules
    1.  Get team member LGTM
    1.  Once team LGTM, add `kokoro-reviews`. (Can enable auto-submit here)
    1.  Note it may take up to 30 min for this to propagate
1.  Update job config to pull the repo
    1.  Currently, this is in
        [hats/hats/common.cfg](http://google3/devtools/kokoro/config/prod/privacy-sandbox/hats/hats/common.cfg)
    1.  Because submodule cloning is disabled, add a separate entry to the
        multi-scm.
        1.  For Git-on-Borg it matches `git clone <url> <name>`, and for github
            it is `git clone https://github.com/<owner>/<repository> <name>`
        1.  Of note, `disable_triggering: true` so Kokoro doesn't watch them for
            updates
    1.  Get team approval, and submit
    1.  Note that passing pre-submit for this cl requires the ACL to propagate,
        so that Kokoro has access.
1.  Kokoro can be re-run on the same revision by replying to the cl with `kokoro
    rebuild`. (Submitting a new revision would also work).

## Behavior

At a high level, Kokoro runs tests on every cl patch, voting -1/+1 depending on
success. A +1 tag is required, which can be overwritten when needed. The logs
can be checked in the Kokoro comment that adds the vote. (This may require "show
all entries" to see the comment in Gerrit) Generally the logs of notes are via
the second link ("Logs at"), under "Targets -> Target Log".

### Triggers

Kokoro monitors cl's in the Gerrit repository for changes. This happens every
few minutes, generally.

Commenting on the cl can also re-trigger Kokoro. * kokoro rebuild: rerun on the
same revision as the last presubmit * kokoro rerun: run on the latest revision
These are the same if Kokoro ran on the latest revision.

It can be triggered manually through Fusion, via "Trigger Build". It requires
flags for Git/Gerrit-on-Borg, which can be added via clicking "+
Git/Gerrit-on-Borg". SCM is the repo, in this case `hats-test`. Change # is the
gerrit cl number.

### Execution

Kokoro uses remote build execution and caching to performs the tests. This uses
Kiwi's GCP instance "kiwi-air-force-remote-build" to do the execution and
caching. In the future, having a more dedicated/fixed toolchain will improve
caching.

### Actions

Kokoro has a tag added, where it can give -1 or +1 depending on success. This
tag is configured to reset on code change, triggering Kokoro to rerun. The +1
tag is required for submission, and a -1 blocks. Anyone in mdb/ps-onprem-eng can
override this tag manually, in case Kokoro is breaking for reasons unrelated to
the cl, or if the cl needs to be submitted quickly without waiting for the tests
to finish.

It also replies to the CL with the result of the test, including a Fusion link.
Fusion info can also be found under
[prod:privacy-sandbox/hats/hats/presubmit](https://fusion2.corp.google.com/ci/kokoro/prod:privacy-sandbox%2Fhats%2Fhats%2Fpresubmit/)

## Documentation followed

*   The original test version in hats-test was set up following the Kokoro
    codelab ([go/kokoro-codelab](go/kokoro-codelab)) for Gerrit-on-Borg
*   This uses a Kokoro instance, following
    [go/kokoro-instances](go/kokoro-instances)
*   Configurations were set up using [go/kokoro-gob-scm](go/kokoro-gob-scm), and
    [go/kokoro-gob-acl](go/kokoro-gob-acl)
*   Bazel setup partially followed
    [go/kokoro-bazel-integration](go/kokoro-bazel-integration), but simplified
    for local execution

## Files

At a high level, this sets up a presubmit job
`privacy-sandbox/hats/hats/presubmit`. The job runs on an instance called
`hats-presubmit-l2`. Generally the jobs have the prefix `privacy-sandbox`, and
it specifically created a presubmit job.

### Google3 Config files

*   Kokoro Instance
    *   Under `google3/configs/devtools/kokoro/prod/instances/ps-onprem-eng`
    *   Sets up `hats-presubmit-l2` with a `cfg` and `syscfg`
    *   Defines the `default` pool
    *   Includes some meta info, like BCID, contact, GCP project
        (ps-hats-playground)
*   ACLs
    *   Under
        [google3/devtools/kokoro/config/data](http://google3/devtools/kokoro/config/data)
    *   For CL's: First get a team LGTM, then request review from
        `kokoro-reviews`.
    *   May also require a `REASON=` in the description.
    *   [pool\_resource\_acl](http://google3/devtools/kokoro/config/data/pool_resource_acl.gcl)
        defines the default pool
    *   [git\_on\_borg\_resource\_acl.gcl](http://google3/devtools/kokoro/config/data/git_on_borg_resource_acl.gcl)
        *   Determines what repos Kokoro is allowed to access
        *   Points to `rpc://privacysandbox", so can work on any sub-repo
        *   Also includes sub-modules and similar that are needed.
    *   [gfile\_resource\_acl.gcl](http://google3/devtools/kokoro/config/data/gfile_resource_acl.gcl)
    *   Gfile resources that Kokoro can grab, see
        [go/kokoro-gfile-inputs](http://go/kokoro-gfile-inputs)
        *   For a fixed version of Bazel from x20
*   Job definition
    *   Under
        [google3/devtools/kokoro/config/prod/privacy-sandbox/hats](http://google3/devtools/kokoro/config/prod/privacy-sandbox/hats)
    *   For Hats team projects
    *   [common.cfg](http://google3/devtools/kokoro/config/prod/privacy-sandbox/hats/common.cfg)
        Top level project common configuration
    *   hats subdirectory
    *   For `rpc://privacysandbox/hats` path specifically
    *   [common.gcl](http://google3/devtools/kokoro/config/prod/privacy-sandbox/hats/hats/common.gcl)
        Bottom level job common
        *   Picks out branch for auto-triggering (main)
        *   Points to label to use (Kokoro)
        *   Path to config directory `hats/kokoro` in the repository
        *   Individually picks which sub-modules for Kokoro to include.
    *   [presubmit.gcl](http://google3/devtools/kokoro/config/prod/privacy-sandbox/hats/hats/presubmit.gcl)
        *   Defines the job type, and the instance pool to use
            (hats-presubmit-l2/default)
        *   Should have the same file name as the executable in the config
            directory
        *   Full path sets job name: `privacy-sandbox/hats/hats/presubmit`
    *   [presubmit_ubuntu.gcl](http://google3/devtools/kokoro/config/prod/privacy-sandbox/hats/hats/presubmit_ubuntu.gcl)
        *   Needed for Keystore access, as Kokoro RBE instances does not support keystore.

### Kokoro meta configuration

Kokoro needs permission to access the repo. This also creates the label.

*   refs/meta/config branch of hats
    *   groups
    *   Define kokoro-dedicated, kokoro-gob-readers
    *   project.config
    *   Define Kokoro label (values, condition, requirement)
    *   kokoro-gob-readers to `refs/for/*` for review read access
    *   kokoro-dedicated to `refs/heads/*`, for (non-meta) label access
*   [google3/configs/production/gerritcodereview/prod/privacysandbox/config.textproto](http://google3/configs/production/gerritcodereview/prod/privacysandbox/config.textproto)
    *   Following
        [go/kokoro-gob-scm#acl-via-config-file-in-piper](go/kokoro-gob-scm#acl-via-config-file-in-piper)
    *   Adding kokoro-gob-readers as reader to acl for directory and host
    *   May not be necessary, TBD

### Repository files

Files used by Kokoro that are executed on the local repository. These are all
stored under the `kokoro` sub-directory

*   presubmit.cfg
    *   Configuration for the presubmit job
    *   Points to the local build file to execute
    *   Includes gfile resources to pull in (such as bazel binary)
    *   Includes docker image, using one of the defaults provided
*   kokoro_build.sh
    *   Wrapper for setting up and building bazel
    *   Copies and sets up bazel binary, then calls it
    *   Patches build to grab "rpc" dependencies from submodules instead
    *   Patches workspace to use local path
    *   Manually applies patch via git
*   bazel_wrapper.py
    *   Based on
        [google3/devtools/kokoro/scripts/bazel_wrapper.py](http://google3/devtools/kokoro/scripts/bazel_wrapper.py)
    *   Provides an invocation ID, which has future uses.

## Other options, TODOs

### Docker images

Kokoro instances execute builds inside Docker container from
[ps-hats-playground presubmit Artificate Registry](https://pantheon.corp.google.com/artifacts/docker/ps-hats-playground/us-central1/presubmit/presubmit?project=ps-hats-playground).

The image contains dependencies necessary to build the code e.g. vhost_vsock
Linux kernel module.

To update the image:

1.  Authenticate with GCP:

    ```shell
    $ gcloud auth login
    $ gcloud config set project ps-hats-playground
    $ gcloud auth configure-docker us-central1-docker.pkg.dev
    ```

1.  Build a docker container:

    ```shell
    $ cd google_internal/kokoro
    $ docker build . -t presubmit
    ```

1.  Tag docker container:

    ```shell
    $ docker tag presubmit us-central1-docker.pkg.dev/ps-hats-playground/presubmit/presubmit
    ```

1.  Push the container to presubmit Artifact Registry in ps-hats-playground:

    ```shell
    $ docker push us-central1-docker.pkg.dev/ps-hats-playground/presubmit/presubmit
    ```

### Release builds

Kokoro also supports e.g. the creation of release builds (and also continuous
testing).

### Additional presubmit checks

Currently `pre-commit run -a` is run at the start of the Kokoro job.
This checks formatting, lint, buildifier, licenses, etc.
This may make more sense as a separate label/job.
