#!/bin/sh

version="v0.7.1"
wget https://github.com/koalaman/shellcheck/releases/download/$version/shellcheck-$version.zip -O /tmp/shellcheck-$version.zip
if [ $? -ne 0 ]
then
	rm /tmp/shellcheck-$version.zip &> /dev/null
	echo "Error downloading $filename"
	exit 1
fi

unzip -o /tmp/shellcheck-$version.zip shellcheck-$version.exe -d /tmp
if [ $? -ne 0 ]
then
	rm /tmp/shellcheck-$version.zip &> /dev/null
	echo "Unable to decompress shellcheck file"
	exit 1
fi

mv -f /tmp/shellcheck-$version.exe /usr/bin/shellcheck.exe
if [ $? -ne 0 ]
then
	rm /tmp/shellcheck-$version.zip &> /dev/null
	echo "Unable to move shellcheck to /usr/bin"
	exit 1
fi

rm /tmp/shellcheck-$version.zip &> /dev/null
