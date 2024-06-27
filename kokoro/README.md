# Kokoro integration

Kokoro is used to perform presubmit testing.

## Behavior

At a high level, Kokoro runs tests on every cl patch, voting -1/+1 depending on success.
This tag currently has no behavior.
The logs can be checked in the Kokoro comment that adds the vote.
(This may require "show all entries" to see the comment in Gerrit)
Generally the logs of notes are via the second link ("Logs at"), under "Targets -> Target Log".

### Triggers

Kokoro monitors cl's in the Gerrit repository for changes.
This happens every few minutes, generally.

Commenting on the cl can also re-trigger Kokoro.
*  kokoro rebuild: rerun on the same revision as the last presubmit
*  kokoro rerun: run on the latest revision

It can be triggered manually through Fusion, via "Trigger Build".
It requires flags for Git/Gerrit-on-Borg, which can be added via clicking "+ Git/Gerrit-on-Borg".
SCM is the repo, in this case `hats-test`.
Change # is the gerrit cl number.

### Execution
Currently, Kokoro essentially runs `bazel test ...` locally.

TODO: This is slow, and building via RBE is in progress.

### Actions

Kokoro has a tag added, where it can give -1 or +1.
This tag is configured to reset on code change.

Currently, this tag has no behavior, beyond appearing on the cl.
Ideally, a +1 tag should be required by Kokoro, and a -1 tag blocks.
Due to potential slowness of execution (local), the current plan is for -1 to block, but not require a +1.

It also replies to the CL with the result of the test, including a Fusion link.
Fusion info can also be found under [prod:privacy-sandbox/hats/hats/presubmit](https://fusion2.corp.google.com/ci/kokoro/prod:privacy-sandbox%2Fhats%2Fhats%2Fpresubmit/)

## Documentation followed.

* The original test version in hats-test was set up following the Kokoro codelab ([go/kokoro-codelab](go/kokoro-codelab)) for Gerrit-on-Borg
* This uses a Kokoro instance, following [go/kokoro-instances](go/kokoro-instances)
* Configurations were set up using [go/kokoro-gob-scm](go/kokoro-gob-scm), and [go/kokoro-gob-acl](go/kokoro-gob-acl)
* Bazel setup partially followed [go/kokoro-bazel-integration](go/kokoro-bazel-integration), but simplified for local execution

## Files

At a high level, this sets up a presubmit job `privacy-sandbox/hats/hats/presubmit`.
The job runs on an instance called `hats-presubmit-l2`.
Generally the jobs have the prefix `privacy-sandbox`, and it specifically created a presubmit job.

### Google3 Config files
* Kokoro Instance
  * Under `google3/configs/devtools/kokoro/prod/instances/ps-onprem-eng`
  * Sets up `hats-presubmit-l2` with a `cfg` and `syscfg`
  * Defines the `default` pool
  * Includes some meta info, like BCID, contact, GCP project (ps-hats-playground)
* ACLs
  * Under [google3/devtools/kokoro/config/data](http://google3/devtools/kokoro/config/data)
  * [pool\_resource\_acl](http://google3/devtools/kokoro/config/data/pool_resource_acl.gcl) defines the default pool
  * [git\_on\_borg\_resource\_acl.gcl](http://google3/devtools/kokoro/config/data/git_on_borg_resource_acl.gcl)
    * Points to `rpc://privacysandbox`
    * Note: supports any sub-repo, but currently only set up for hats.
    * Also disables submodules, as they are not neeeded for building
  * [gfile\_resource\_acl.gcl](http://google3/devtools/kokoro/config/data/gfile_resource_acl.gcl)
    * Gfile resources that Kokoro can grab, see [go/kokoro-gfile-inputs](http://go/kokoro-gfile-inputs)
* Job definition
  * Under [google3/devtools/kokoro/config/prod/privacy-sandbox/hats](http://google3/devtools/kokoro/config/prod/privacy-sandbox/hats)
    * For Hats team projects
  * [common.cfg](http://google3/devtools/kokoro/config/prod/privacy-sandbox/hats/common.cfg) Top level project common configuration
  * hats subdirectory
    * For `rpc://privacysandbox/hats` path specifically
    * [common.cfg](http://google3/devtools/kokoro/config/prod/privacy-sandbox/hats/hats/common.cfg) Bottom level job common
      * Picks out branch for auto-triggering (main)
      * Points to label to use (Kokoro)
      * Path to config directory `hats/kokoro` in the repository
    * [presubmit.cfg](http://google3/devtools/kokoro/config/prod/privacy-sandbox/hats/hats/presubmit.cfg)
      * Defines the job type, and the instance pool to use (hats-presubmit-l2/default)
      * Should have the same file name as the executable in the config directory
      * Full path sets job name: `privacy-sandbox/hats/hats/presubmit`

### Kokoro meta configuration

Kokoro needs permission to access the repo.
This also creates the label.

* refs/meta/config branch of hats
  * groups
    * Define kokoro-dedicated, kokoro-gob-readers
  * project.config
    * Define Kokoro label (values, condition, in the future blocking behavior)
    * kokoro-gob-readers to `refs/for/*` for review read access
    * kokoro-dedicated to `refs/heads/*`, for (non-meta) label access
* [google3/configs/production/gerritcodereview/prod/privacysandbox/config.textproto](http://google3/configs/production/gerritcodereview/prod/privacysandbox/config.textproto)
  * Following [go/kokoro-gob-scm#acl-via-config-file-in-piper](go/kokoro-gob-scm#acl-via-config-file-in-piper)
  * Adding kokoro-gob-readers as reader to acl for directory and host
  * May not be necessary, TBD


### Repository files

Files used by Kokoro that are executed on the local repository.
These are all stored under the `kokoro` sub-directory
* presubmit.cfg
  * Configuration for the presubmit job
  * Points to the local build file to execute
  * Includes gfile resources to pull in (such as bazel binary)
  * Includes docker image, using one of the defaults provided
* kokoro_build.sh
  * Wrapper for setting up and building bazel
  * Copies and sets up bazel binary, then calls it
* bazel_wrapper.py
  * Based on [google3/devtools/kokoro/scripts/bazel_wrapper.py](http://google3/devtools/kokoro/scripts/bazel_wrapper.py)
  * Originally for RBE, simplified for local execution


## Other options

### Docker images
Kokoro instances execute builds inside Docker containers.
Currently it uses a general pre-provided default option.
There is support for custom images.
See go/kokoro-docker-image-options
The codelab has also been recently updated to include instructions for "Container Build".
This can help with coming pre-packaged with build dependencies, build tools, etc. to speed up building.

### Remote execution

Kokoro Bazel integration recommends RBE.
Currently, we use local execution instead for simplicity.
Our current GCP project, `ps-hats-playground`, is not an internal Google project, and therefore does not support RBE.
Also, the documentation for Kokoro instances with bazel is out of date, see [yaqs/258724981620342784#n1](http://yaqs/258724981620342784#n1).
We are looking into RBE to speed up testing.

### Release builds

Kokoro also supports e.g. the creation of release builds (and also continuous testing).
