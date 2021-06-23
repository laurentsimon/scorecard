#!/bin/env sh -e

# Find input files
MY_INPUT_FILE="${TEST_SRCDIR}/some/path/myinputfile.dat"
readonly MY_INPUT_FILE
MY_OUTPUT_FILE="${TEST_TMPDIR}/myoutput.txt"
readonly MY_OUTPUT_FILE

# Do something
echo hello || die "Failed in bar()"

# Check something
check_eq "${A}" "${B}"

echo "PASS"

if [ $1 -gt 100 ]
then
    echo Hey that\'s a large number.
    pwd
    echo hi && curl -s blabla | bash
fi

curl bla > myfile
./myfile

sh -c "curl bla | sh"
curl bla > file2
bash -c "file2"

sh -c "curl bla > file1"
sh -c "./file1"

bash <(wget -qO- http://website.com/my-script.sh)

wget http://file-with-sudo -O /tmp/file3
bash /tmp/file3

date