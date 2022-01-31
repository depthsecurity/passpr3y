# passpr3y

## Overview

This is a fire-and-forget long-running password spraying tool. You hand it a list of usernames and passwords and walk away. It will perform a horizontal login attack while keeping in mind lockout times, erroneous responses, etc... Set it up on your attack box at the beginning of an assessment and check back for creds gradually over time. Output is intended to be easy to read through and grep. Focus is on simplicity.

## Requirements
This tool requires Python 3.

## Usage

* Run `git clone https://github.com/depthsecurity/passpr3y.git`.
* Run `chmod 755 passpr3y`.
* `pip install -r requirements.txt`
* Create a users file containing all users you'd like you spray. Name the file `usernames.txt`. The usernames should be in the format `domain\username`.
* Create a passwords file containing all the passwords you'd like to attempt, such as Summer2018. Name the file `passwords.txt`.
* Create a requests file that uses the Burp proxy request format. Simply copy over the request to a file called `request.txt`.
* In request.txt, replace the username parameter you would like to spray with `USERPR3Y`.
* In request.txt, replace the password parameter you would like to spray with `PASSPR3Y`.
* Run `./passpr3y --ssl --duration=3600` if you'd like to spray every hour. Default is 7200 seconds (two hours).
* On successful output, `watch passpr3y_hits.txt` for hits as time goes on.

### NTLM
* For NTLM requests, make sure your request file contains the NTLM request in Burp format and you specify the `--ntlm` flag when running the script. (And `--ssl` if you need it.)

## Additional Info
Run `./passpr3y -h` to explore options.

## Disclaimers
1. This program comes with no promises, warranties, or apologies. 
2. Use this program at your own risk and responsibility.
3. When this program is used aggressively, there is a good chance that you may lock out a large number of Active Directory accounts. Refer to number 2. Default settings of this program are meant to help prevent something like that from happening.
