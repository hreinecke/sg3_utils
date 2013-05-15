#!/bin/sh

# If this script fails on a Debian 4.0 ("etch") system then read
# the debian/README.debian4 file.

echo "chmod +x debian/rules"
chmod +x debian/rules

# in some environments the '-rfakeroot' can cause a failure (e.g. when
# building as root). If so, remove that argument from the following:
echo "dpkg-buildpackage -b -rfakeroot -us -uc"
dpkg-buildpackage -b -rfakeroot -us -uc

# If the above succeeds then the ".deb" binary package is placed in the
# parent directory.
