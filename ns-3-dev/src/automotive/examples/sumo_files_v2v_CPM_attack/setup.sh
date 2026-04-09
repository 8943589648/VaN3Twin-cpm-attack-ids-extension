#!/bin/bash
# Crossroads Scenario — Quick Setup
# ==================================
# 1 km x 1 km area, traffic-light intersection
# Main road (east-west): 50 km/h, 2 lanes each direction
# Side street (north-south): 30 km/h, 1 lane each direction  
# 20 vehicles on 4 different routes, simulation runs 120 seconds

# Step 1: Set SUMO_HOME
export SUMO_HOME=/usr/share/sumo

# Step 2: cd into the scenario folder
cd ~/sumo_cpm_scenario_v2

# Step 3: Generate the network (run this ONE TIME)
netconvert --node-files=crossroads.nod.xml --edge-files=crossroads.edg.xml --output-file=crossroads.net.xml

# Step 4: Test standalone (headless)
sumo -c crossroads.sumocfg

# Step 4b: Test with GUI (only if you have X server / WSLg)
# sumo-gui -c crossroads.sumocfg

# Step 5: Copy into VaN3Twin
# cp -r ~/sumo_cpm_scenario_v2 ~/VaN3Twin/ns-3-dev/src/automotive/examples/sumo_files_cpm_attack/
