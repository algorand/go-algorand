#!/bin/bash
compare_semantic_versions() {
    IFS='.' read -ra VERSION1 <<< "$1"
    IFS='.' read -ra VERSION2 <<< "$2"

    for i in "${!VERSION1[@]}"; do
        if (( ${VERSION1[i]} > ${VERSION2[i]} )); then
            if (( i == 0 )); then
                echo "The major version ${VERSION1[i]} of $1 is greater than the major version ${VERSION2[i]} of $2."
            elif (( i == 1 )); then
                echo "The minor version ${VERSION1[i]} of $1 is greater than the minor version ${VERSION2[i]} of $2."
            else
                echo "The patch version ${VERSION1[i]} of $1 is greater than the patch version ${VERSION2[i]} of $2."
            fi
            return 0
        elif (( ${VERSION1[i]} < ${VERSION2[i]} )); then
            if (( i == 0 )); then
                echo "The major version ${VERSION1[i]} of $1 is less than the major version ${VERSION2[i]} of $2."
            elif (( i == 1 )); then
                echo "The minor version ${VERSION1[i]} of $1 is less than the minor version ${VERSION2[i]} of $2."
            else
                echo "The patch version ${VERSION1[i]} of $1 is less than the patch version ${VERSION2[i]} of $2."
            fi
            return 1
        else
            if (( i == 0 )); then
                echo "The major version ${VERSION1[i]} of $1 is equal to the major version ${VERSION2[i]} of $2."
            elif (( i == 1 )); then
                echo "The minor version ${VERSION1[i]} of $1 is equal to the minor version ${VERSION2[i]} of $2."
            else
                echo "The patch version ${VERSION1[i]} of $1 is equal to the patch version ${VERSION2[i]} of $2."
            fi
        fi
    done

    echo "The versions are equal."
    return 0
}

# Test compare_semantic_versions function:
# echo "Testing compare_semantic_versions function with semantic version arguments: 2.4.3 and 3.4.4-alpha"
# compare_semantic_versions "3.4.3" "3.4.2-alpha"

# equal=$?

# if [[ $equal -eq 0 ]]; then
#     echo "First semantic version arg is equal or greater than the second semantic version arg!"
# else
#     echo "First semantic version arg is smaller than the second semantic version arg!"
# fi
