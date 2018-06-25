# passpr3y

## Overview

This is a password spraying tool. What differentiates this from a traditional bruteforce tool is that one password is used against a list of users. This is also known as a horizontal login attack.

There are measures built-in against locking out accounts, particularly in cases where Active Directory accounts are tested.

## Requirements
This tool requires Python 3 and was written with Python 3.6 in mind. Refer to the file header for any needed modules.

## Usage

* Run `chmod 755 passpr3y`.
* Create a users file containing all users you'd like you spray. Name the file `usernames.txt`.
* Create a passwords file containing all the passwords you'd like to attempt, such as Summer2018. Name the file `passwords.txt`.
* Create a requests file that uses the Burp proxy request format. Simply copy over the request to a file called `request.txt`.
* Run `./passpr3y -ssl --duration=3600` if you'd like to spray every hour. Default is 7200 for every two hours.

## Additional Info
Run `./passpr3y -h` to explore options.

## Disclaimers
1. This program comes with no promises, warranties, or apologies. 
2. Use this program at your own risk and responsibility.
3. When this program is used aggressively, there is a good chance that you may lock out a large number of Active Directory accounts. Refer to number 2.
4. Default settings of this program are meant to help prevent something like that from happening.
