#!/bin/bash 

. settings

rm -rf DOWNLOADING_DATA UPLOADING_DATA
# Removing of all containers and objects in current account!!! 
${SWIFT} delete --all
