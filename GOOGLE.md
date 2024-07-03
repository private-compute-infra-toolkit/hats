# Google-internal README

Put any Google-specific documentation here, rather than README.md

## Pushing to github for Alpha

Manually push to github.  The process is:

1. Check out a clean git HATs repo.  Do not load submodules recursively.
1. Check for missing copyright headers.
   * Run ./findNoLicenseRn.sh > files.
   * Manually add copyright headers to any .sh files, and remove them from list.
   * Run `for file in \`< files\`; do; ./addLicense.sh $file; done`.
   * Submit the CL.
1. Run `/google/bin/releases/opensource/thirdparty/cross/cross `.
1. If clean, you can push to github.

## Google specific code comments

# kv-test-client_main.cc

Encryption parameters in are from
https://source.corp.google.com/h/team/kiwi-air-force-eng-team/kv-server/+/main:public/constants.h;drc=7a3397543bfb9c6572813512984cac5629de69a2;l=101.
