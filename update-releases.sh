#!/bin/bash

set -eu

lineno=1
block=1
license="http://www.php.net/license/3_01.txt"

function read_line
{
    local dummy
    local line

    read -r -u ${FD} line
    if [ "${line:0:$((${#1}+1))}" != "$1:" ]; then
        echo "Error on line $lineno: missing value or invalid tag '${line%:*}' (expected tag: '$1')" >&2
        exit 1
    fi

    if [ -z "${line#*: }" ]; then
        echo "Error on line $lineno: missing value for tag '${line%:*}'" >&2
        exit 1
    fi

    echo "${line#*: }"
}

function xmlstarlet
{
    $(which xmlstarlet) ed -L -N p=http://pear.php.net/dtd/package-2.0 "$@" package.xml
}

exec {FD}<RELEASES
xmlstarlet -d '/p:package/p:changelog/p:release'
while true; do
    version=`read_line Version`
    lineno=$((lineno + 1))
    date=`read_line Date`
    lineno=$((lineno + 1))
    stability=`read_line Stability`
    lineno=$((lineno + 1))

    time=`echo "$date" | sed -nE 's/^([0-9]{4}-[0-9]{2}-[0-9]{2}) ([0-9]{2}:[0-9]{2}:[0-9]{2})$/\2/p'`
    date=`echo "$date" | sed -nE 's/^([0-9]{4}-[0-9]{2}-[0-9]{2}) ([0-9]{2}:[0-9]{2}:[0-9]{2})$/\1/p'`

    api_version=`echo "$version" | sed -nE 's/^([0-9]+\.[0-9]+\.[0-9]+) \(API: ([0-9]+\.[0-9]+\.[0-9]+)\)$/\2/p'`
    version=`echo "$version" | sed -nE 's/^([0-9]+\.[0-9]+\.[0-9]+) \(API: ([0-9]+\.[0-9]+\.[0-9]+)\)$/\1/p'`

    api_stability=`echo "$stability" | sed -nE 's/^(\S+) \(API: (\w+)\)$/\2/p'`
    stability=`echo "$stability" | sed -nE 's/^(\S+) \(API: (\w+)\)$/\1/p'`

    dummy=""
    read -r -u ${FD} dummy || :
    if [ -n "$dummy" ]; then
        echo "Error on line $lineno: an empty line was expected" >&2
        exit 1
    else
        lineno=$((lineno + 1))
    fi

    dummy=`read_line notes`
    notes=`sed -n $lineno',${s/^notes: //;p;n;: loop;/^Version:/Q 0;p;n;b loop}' RELEASES`
    nb_lines=`sed -n $lineno',${s/^notes: //;n;: loop;/^Version:/{=;Q 0};;n;b loop}' RELEASES`

    echo -n "Updating release $version... "
    if [ $block -eq 1 ]; then
        # Update the block reserved for the latest release
        xmlstarlet -u '/p:package/p:date'                 -v "${date}"
        xmlstarlet -u '/p:package/p:time'                 -v "${time}"
        xmlstarlet -u '/p:package/p:version/p:release'    -v "${version}"
        xmlstarlet -u '/p:package/p:version/p:api'        -v "${api_version}"
        xmlstarlet -u '/p:package/p:stability/p:release'  -v "${stability}"
        xmlstarlet -u '/p:package/p:stability/p:api'      -v "${api_stability}"
        xmlstarlet -u '/p:package/p:notes'                -v "${notes}"

        # Sync the release & API versions found in php_tomcrypt.h
        sed -Ei -e 's/(#define PHP_TOMCRYPT_VERSION)\s.*$/\1        "'"$version"'"/'        \
                -e 's/(#define PHP_TOMCRYPT_API_VERSION)\s.*$/\1    "'"$api_version"'"/'    \
                src/php_tomcrypt.h
    else
        # Add a new release to the changelog and populate its properties
        xmlstarlet -s '/p:package/p:changelog' -t elem -n release
        xmlstarlet -s '/p:package/p:changelog/p:release[last()]' -t elem -n date                -v "${date}"
        xmlstarlet -s '/p:package/p:changelog/p:release[last()]' -t elem -n time                -v "${time}"
        xmlstarlet -s '/p:package/p:changelog/p:release[last()]' -t elem -n version
        xmlstarlet -s '/p:package/p:changelog/p:release[last()]/p:version' -t elem -n release   -v "${version}"
        xmlstarlet -s '/p:package/p:changelog/p:release[last()]/p:version' -t elem -n api       -v "${api_version}"
        xmlstarlet -s '/p:package/p:changelog/p:release[last()]' -t elem -n stability
        xmlstarlet -s '/p:package/p:changelog/p:release[last()]/p:stability' -t elem -n release -v "${stability}"
        xmlstarlet -s '/p:package/p:changelog/p:release[last()]/p:stability' -t elem -n api     -v "${api_stability}"
        xmlstarlet -s '/p:package/p:changelog/p:release[last()]' -t elem -n license             -v "PHP"
        xmlstarlet -s '/p:package/p:changelog/p:release[last()]/p:license' -t attr -n uri       -v "${license}"
        xmlstarlet -s '/p:package/p:changelog/p:release[last()]' -t elem -n notes               -v "${notes}"
    fi
    echo "OK"

    lineno=$((lineno + 1))
    if [ -z "$nb_lines" ]; then
        break
    else
        block=$((block + 1))
    fi

    # Read and throw away the rest of the notes for this release
    while [ $lineno -lt $nb_lines ]; do
        read -u ${FD} dummy
        lineno=$((lineno + 1))
    done
done < <( cat RELEASES )
exec {FD}<&-

cat package.xml | $(which xmlstarlet) fo -s 1 -e utf-8 - > package.xml
