#!/bin/bash
username=`npm whoami`
echo $username
if test "$username" = "jccdex"; then
    if test "$1" = "";then
        npm version patch --no-git-tag-version
    else
        npm version $1 --no-git-tag-version
    fi
    gulp build
    npm publish
else
    echo "please login with jccdex account"
    exit 0
fi
