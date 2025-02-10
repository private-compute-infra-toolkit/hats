#!/usr/bin/env python3
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import argparse
import json
import os
import subprocess
import sys
import time


def main():
  #### Parse args
  parser = argparse.ArgumentParser()
  parser.add_argument('test_dir', help='Path to a test directory')
  parser.add_argument('--prefix', help='Prefix for Swarming task name')
  parser.add_argument('test_script', help='Name of shell script to run in test_dir')
  args = parser.parse_args()

  #### Sanity checks
  if 'LUCI_ROOT' not in os.environ.keys():
    # Kokoro script does this automatically
    # But will need to be done locally to use manual_run.sh
    raise SystemExit("Error: LUCI_ROOT not in environment. Set it to be the directory containing swarming and isolate")
  assert os.path.isdir(args.test_dir)
  assert os.path.isfile(args.test_script)
  # Process args
  test_dir = os.path.normpath(args.test_dir)
  prefix = (args.prefix + '_') if args.prefix else ''

  params = {
    'test_dir': test_dir,
    'test_name': os.path.basename(test_dir),
    'devices': ['sev-snp'],  # TODO, not used currently.
    'task_prefix': prefix,
    'priority': "100",
    'timeout': "300",
    'expiration': "600",
    'swarming_server': "https://chrome-swarming.appspot.com",
    'cas-instance': "chrome-swarming",
    'pool': "chv-lab",
  }

  params['task_name'] = params['task_prefix'] + params['test_name']

  #### Isolate config file
  isolate_file = params['test_name'] + '.isolate'
  # Trailing '/' to indicate all dir content must be uploaded
  isolate_body = """{
  'variables': {
    'files': [
""" + "'" + params['test_dir'] + "/'" + """,
    ]
  },
}
"""
  with open(isolate_file, 'w') as f:
    f.write(isolate_body)

  #### Upload to isolate
  digest_file = params['test_name'] + '.digest.json'
  if os.path.exists(digest_file):
    os.remove(digest_file)
  cmd = [
    os.path.join(os.environ['LUCI_ROOT'], 'isolate'),
    'archive',
    '--cas-instance', params['cas-instance'],
    '--isolate', isolate_file,
    '--dump-json', digest_file,
  ]
  if (('SWARMING_AUTH_FLAG' in os.environ.keys())
      and (os.environ['SWARMING_AUTH_FLAG'] != '')):
    cmd += [ os.environ['SWARMING_AUTH_FLAG'] ]
  # We expect this command to always succeed
  subprocess.run(cmd, check=True)
  # The isolated file must be produced
  assert os.path.isfile(digest_file)

  #### Get CAS digest
  digest = None
  with open(digest_file, 'r') as f:
      j = json.load(f)
      digest = j[params['test_name']]
  assert digest is not None

  #### Trigger swarming task
  for device in params['devices']:
    triggered_dir = os.path.join('triggered', device)
    os.makedirs(triggered_dir, exist_ok=True)
    task_json = os.path.join(triggered_dir, params['test_name'] + '.json')
    if os.path.exists(task_json):
        os.remove(task_json)
    cmd = [
      os.path.join(os.environ['LUCI_ROOT'], 'swarming'),
      'trigger',
      '--server', params['swarming_server'],
      # Where CAS upload is
      '--digest', digest,
      '--task-name', params['task_name'],
      '--json-output', task_json,
      # Dimension selects bot.
      '--dimension', 'pool=' + params['pool'],
      # The device tag will be supported once there are multiple devices.
      # '--dimension', 'device_type=' + device,
      '--priority', params['priority'],
      '--expiration', params['expiration'],
      '--hard-timeout', params['timeout'],
    ]
    if (('SWARMING_AUTH_FLAG' in os.environ.keys())
        and (os.environ['SWARMING_AUTH_FLAG'] != '')):
      cmd += [ os.environ['SWARMING_AUTH_FLAG'] ]

    # Set up command.
    """
    '${ISOLATED_OUTDIR}' is a special string that must appear as-is, and is
    replaced by Swarming to point to a directory to save to.
    It is accessible by '--output-dir' in collect.
    However, rust tests use this as a filter, so can't be passed arbitrarily.
    In addition, it requires a wrapper or other script that outputs to a dir,
    not just bazel binaries.
    Therefore it is not supported for now.

    Can be standalone executable (+x, shebang, etc) or called (bash script.sh)
    """
    cmd += [
      '--',
      # Binary to be executed. E.g. script with shebang.
      args.test_script,
      # Additional args, if any.
      # '${ISOLATED_OUTDIR}',
    ]

    print("Trigger command:", cmd)
    # We expect this command to always succeed
    subprocess.run(cmd, check=True)
    # The task JSON file must be produced
    assert os.path.isfile(task_json)

if __name__ == '__main__':
  sys.exit(main())
