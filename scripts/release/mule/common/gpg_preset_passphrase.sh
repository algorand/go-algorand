#!/usr/bin/env bash
# shellcheck disable=2016

get_awk_program() {
    if [ "$1" = dev ]
    then
        echo '/Keygrip/{ a=$0 } END { sub(/\s*Keygrip = /, "", a); print a }'
    else
        echo '$1=="Keygrip"{ print $3; exit; }'
    fi
}

get_keygrip() {
    awk "$(get_awk_program "$1")" <(gpg -K --with-keygrip --textmode "$1@algorand.com")
}

if [ "$(uname)" = Linux ]
then
    GPG_PRESET_PASSPHRASE=$(find /usr/lib/gnupg{2,,1} -type f -name gpg-preset-passphrase 2> /dev/null)
else
    GPG_PRESET_PASSPHRASE=$(find /usr/local -type f -name gpg-preset-passphrase 2> /dev/null)
#    GPG_AGENT_LOCATION=$(awk -F: '$1=="agent-socket"{n=sub(/S.gpg-agent/, "", $2); print $2}' <(gpgconf --list-dirs))
#    echo "$GPG_AGENT_LOCATION"
fi

for key in dev rpm
do
    KEYGRIP="$(get_keygrip $key)"
    echo "enter $key@ passphrase"
    "$GPG_PRESET_PASSPHRASE" --verbose --preset "$KEYGRIP"
done

