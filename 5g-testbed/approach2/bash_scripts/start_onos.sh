#!/bin/bash

# Navigate to the ONOS directory and start ONOS with Bazel
cd ~/onos
bazel run onos-local -- [clean] [debug] | grep -iv "Unable to translate flow rule for pipeconf" | tee -a onos.log 

