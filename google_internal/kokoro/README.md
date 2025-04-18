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

The developer mdb group is allowed to manually vote with the Kokoro label. This
will allow for submission when Kokoro breaks, or when a submit/fix needs to go
through fast without waiting. This can also allow submitting w/ new submodules
without needing to update permissions, but note this will break all future cl's
too until Kokoro permissions update and propagate.

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
1.  (Optional): Update job config to pull the repo. This is only necessary if
    you need a local copy separate from the submodule.
    1.  Add a separate entry to the multi-scm. This can be either common, or the
        specific job.
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
all entries" to see the comment in Gerrit). Generally the logs of runs are via
the second link ("Logs at"), under "Targets -> Target Log".

### Triggers

Kokoro monitors cl's in the Gerrit repository for changes. This happens every
few minutes, generally.

Commenting on the cl can also re-trigger Kokoro. These are the same if Kokoro
ran on the latest revision.

*   kokoro rebuild: rebuild and run on the same revision as the last presubmit
*   kokoro rerun: run on the latest revision

It can be triggered manually through Fusion, via "Trigger Build". It requires
flags for Git/Gerrit-on-Borg, which can be added via clicking "+
Git/Gerrit-on-Borg". SCM is the repo, in this case `hats`. Change # is the
gerrit cl number.

There is also a continuous build. This runs nightly at midnight, and whenever
head updates, but will not start a run if a run is currently going.

### Execution

Kokoro uses remote build execution and caching to performs the tests. This uses
Kiwi's GCP instance "kiwi-air-force-remote-build" to do the execution and
caching. In the future, having a more dedicated/fixed toolchain will improve
caching.

For remote testing (on SNP machines via swarming), there is currently no remote
execution (b/395680242).

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

All fusion results across different Kokoro jobs can be found
[here](https://fusion2.corp.google.com/ci;ids=1567276032). This includes both
presubmit and continuous runs, along with runs across different repos.

### Swarming

Some tests require specialized hardware, so we use [swarming](go/swarming) to
send tests to our own hardware. Due to requiring keystore for authentication,
these tests run on a separate presubmit_ubuntu job. Currently this is not
blocking, and is meant to be informative.

At a high level:

*   Files are built on Kokoro using bazel and build scripts.
*   Relevant binaries and test files are sent via isolate to the swarming
    server.
*   A job is triggered for each test (and each device type).
*   On our hardware, a bot connected to the swarming server detects the trigger,
    downloads the files, executes them, and reports back.
*   Kokoro collects the results back from the server and reports success or
    failure.

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
*   Swarming based on swarming docs, [go/swarming](go/swarming).

## Files

At a high level, this sets up a presubmit job
`privacy-sandbox/hats/hats/presubmit`. The job runs on an instance called
`hats-presubmit-l2`. Generally the jobs have the prefix `privacy-sandbox`, and
it specifically created a presubmit job. There is also a similar job
`presubmit_ubuntu`, which uses `GCP_DOCKER_UBUNTU` for keystore access, and is
another presubmit job. There is a third `continuous` job which runs as
continuous integration instead of presubmit.

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
    *   [common.cfg](http://google3/devtools/kokoro/config/prod/privacy-sandbox/hats/common.cfg):
        Top level project common configuration, mostly meta info
    *   hats subdirectory (similar for others)
        *   For `rpc://privacysandbox/hats` path specifically
        *   [common.gcl](http://google3/devtools/kokoro/config/prod/privacy-sandbox/hats/hats/common.gcl):
            Bottom level job common, for the specific repo
            *   Picks out branch for auto-triggering (main)
            *   Points to label to use (Kokoro)
            *   Path to config directory `hats/kokoro` in the repository
        *   [presubmit.gcl](http://google3/devtools/kokoro/config/prod/privacy-sandbox/hats/hats/presubmit.gcl)
            *   Defines the job type, and the instance pool to use
                (hats-presubmit-l2/default)
            *   Should have the same file name as the executable in the config
                directory (in this case, `presubmit.cfg`)
            *   Full path sets job name: `privacy-sandbox/hats/hats/presubmit`
            *   Points at branch being monitored (e.g. `main`)
            *   May also include additional repositories separately loaded
        *   [presubmit_ubuntu.gcl](http://google3/devtools/kokoro/config/prod/privacy-sandbox/hats/hats/presubmit_ubuntu.gcl)
            *   Needed for Keystore access, as Kokoro RBE instances does not
                support keystore.
        *   [continuous.gcl](http://google3/devtools/kokoro/config/prod/privacy-sandbox/hats/hats/continuous.gcl)
            *   Sets up the continuous job and frequency
            *   Skips label inheritance since labels don't apply

### Kokoro meta configuration

Kokoro needs permission to access the repo. This also creates the label.

*   refs/meta/config branch of hats
    *   groups
        *   Define kokoro-dedicated, kokoro-gob-readers
    *   project.config
        *   Define Kokoro label (values, condition, requirement)
        *   kokoro-gob-readers to `refs/for/*` for review read access
        *   kokoro-dedicated to `refs/heads/*`, for (non-meta) label access
*   [google3/configs/production/gerritcodereview/prod/privacysandbox/config.txtpb](http://google3/configs/production/gerritcodereview/prod/privacysandbox/config.txtpb)
    *   Following
        [go/kokoro-gob-scm#acl-via-config-file-in-piper](go/kokoro-gob-scm#acl-via-config-file-in-piper)
    *   Adding kokoro-gob-readers as reader to acl for directory and host
    *   May not be necessary, TBD

### Repository files

Files used by Kokoro that are executed on the local repository. These are all
stored under the `kokoro` sub-directory.

*   presubmit.cfg
    *   Configuration for the presubmit job
    *   Points to the local build file to execute
    *   Includes gfile resources to pull in (such as bazel binary)
    *   Includes docker image, see below
    *   Similiar for other cfg files
*   presubmit_ubuntu.cfg / continuous.cfg
    *   Similar structure to presubmit.cfg
    *   For swarming presubmit / continuous job
    *   Keystore information for use by swarming
*   kokoro_build.sh
    *   Wrapper for setting up and building bazel
    *   Copies and sets up bazel binary, then calls it
    *   Patches build to grab "rpc" dependencies from submodules instead
    *   Patches workspace to use local path
    *   Manually applies patch via git
    *   Similar for other sh files referenced by gcl files.
*   bazel_wrapper.py
    *   Based on
        [google3/devtools/kokoro/scripts/bazel_wrapper.py](http://google3/devtools/kokoro/scripts/bazel_wrapper.py)
    *   Provides an invocation ID, which has future uses for monitoring/logging.

## Other options, Future Work

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

1.  (Optional): Update image used by Kokoro jobs (e.g. `presubmit.cfg`) with the
    hash provided in the prior command. The hash can also be found in the
    artifact registry.

### Release builds

Kokoro also supports e.g. the creation of release builds (and also continuous
testing).

### Additional / separate presubmit checks

Currently `pre-commit run -a` is run at the start of the standard presubmit job.
This checks formatting, lint, buildifier, licenses, etc. This may make more
sense as a separate label/job.
