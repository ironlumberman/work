#!/bin/bash 

. settings

# check that our account is exist
LIST=`${SWIFT} list`
if [ "${LIST}" != "" ]; then
  echo "Can't create set of containers and objects: the containers list is not empty (run ./delete.sh before)"
  exit 1
fi

# preparation of data for uploading 
. create_uplouding_data 

# upload data  

for container in `ls UPLOADING_DATA`; do 
  echo "Creating container: $container"
  ${SWIFT} post $container
  cd UPLOADING_DATA/$container
  ${SWIFT} upload $container *
  cd ../../
done

${SWIFT} list 
