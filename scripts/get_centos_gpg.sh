# script fragment to be called inline in build_release.sh and related
mkdir -p ${HOME}/docker_test_resources
if [ ! -f "${HOME}/docker_test_resources/gnupg2.2.9_centos7_amd64.tar.bz2" ]; then
    aws s3 cp s3://algorand-devops-misc/tools/gnupg2.2.9_centos7_amd64.tar.bz2 ${HOME}/docker_test_resources
fi
