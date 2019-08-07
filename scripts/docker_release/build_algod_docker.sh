#!/usr/bin/env bash
ALGOD_INSTALL_TAR_FILE=$1
if [[ $ALGOD_INSTALL_TAR_FILE == "" ]]
then
   echo "specify filepath of base install file"
   exit 1
fi

echo "building 'Dockerfile_algod_release' with install file $ALGOD_INSTALL_TAR_FILE"
cp $ALGOD_INSTALL_TAR_FILE ./temp_install.tar.gz
docker build --build-arg ALGOD_INSTALL_TAR_FILE=temp_install.tar.gz . -t algorand/release -f Dockerfile_algod_release

#echo "pushing 'algorand/release:latest'"
#docker push algorand/release:latest

mkdir -p algorand_pkg_${FULLVERSION}

echo "exporting 'algorand_docker_release_${FULLVERSION}.tar.gz'"
docker save --output algorand_pkg_${FULLVERSION}/algorand_docker_release_${FULLVERSION}.tar.gz algorand/release:latest

echo "creating package jar file algorand_docker_package_${FULLVERSION}.tar.gz"
cp ./start_algod_docker.sh algorand_pkg_${FULLVERSION}/
cp ./README.md algorand_pkg_${FULLVERSION}/
tar cvf algorand_docker_package_${FULLVERSION}.tar.gz algorand_pkg_${FULLVERSION}

echo "moving resulting docker package to ${HOME}/node_pkg/algorand_docker_package_${FULLVERSION}.tar.gz"
cp algorand_docker_package_${FULLVERSION}.tar.gz ${HOME}/node_pkg

echo "cleaning up temporary files"
rm ./temp_install.tar.gz
rm ./algorand_docker_package_${FULLVERSION}.tar.gz
rm -rf algorand_pkg_${FULLVERSION}
