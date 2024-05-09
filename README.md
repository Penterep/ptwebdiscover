[![penterepTools](https://www.penterep.com/external/penterepToolsLogo.png)](https://www.penterep.com/)


## PTWEBDISCOVER - Web Source Discovery Tool

## Installation
```
pip install ptwebdiscover
```

## Adding to PATH
If you're unable to invoke the script from your terminal, it's likely because it's not included in your PATH. You can resolve this issue by executing the following commands, depending on the shell you're using:

For Bash Users
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.bashrc
source ~/.bashrc
```

For ZSH Users
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.zshrc
source ~/.zshrc
```

## Usage examples
```
ptwebdiscover -u https://www.example.com
ptwebdiscover -u https://www.example.com -ch lowercase,numbers,123abcdEFG*
ptwebdiscover -u https://www.example.com -lx 4
ptwebdiscover -u https://www.example.com -w
ptwebdiscover -u https://www.example.com -w wordlist.txt
ptwebdiscover -u https://www.example.com -w wordlist.txt --begin_with admin
ptwebdiscover -u https://*.example.com -w
ptwebdiscover -u https://www.example.com/exam*.txt
ptwebdiscover -u https://www.example.com -e "" bak old php~ php.bak
ptwebdiscover -u https://www.example.com -E extensions.txt
ptwebdiscover -u https://www.example.com -w -sn "Page Not Found"
```

## Options
```
-u    --url                     <url>           URL for test (usage of a star character as anchor)
-ch   --charsets                <charsets>      Specify charset fro brute force (example: lowercase,uppercase,numbers,[custom_chars])
                                                Modify wordlist (lowercase,uppercase,capitalize)
-lm   --length-min              <length-min>    Minimal length of brute-force tested string (default 1)
-lx   --length-max              <length-max>    Maximal length of brute-force tested string (default 6 bf / 99 wl
-w    --wordlist                <filename>      Use specified wordlist(s)
-pf   --prefix                  <string>        Use prefix before tested string
-sf   --suffix                  <string>        Use suffix after tested string
-bw   --begin-with              <string>        Use only words from wordlist that begin with the specified string
-ci   --case-insensitive                        Case insensitive items from wordlist
-e    --extensions              <extensions>    Add extensions behind a tested string ("" for empty extension)
-E    --extension-file          <filename>      Add extensions from default or specified file behind a tested string.
-r    --recurse                                 Recursive browsing of found directories
-md   --max_depth               <integer>       Maximum depth during recursive browsing (default: 20)
-b    --backups                                 Find backups for db, all app and every discovered content
-bo   --backups-only                            Find backup of complete website only
-P    --parse                                   Parse HTML response for URLs discovery
-Po   --parse-only                              Brute force method is disabled, crawling started on specified url
-D    --directory                               Add a slash at the ends of the strings too
-nd   --not-directories         <directories>   Not include listed directories when recursive browse run
-sy   --string-in-response      <string>        Print findings only if string in response (GET method is used)
-sn   --string-not-in-response  <string>        Print findings only if string not in response (GET method is used)
-sc   --status-codes            <status codes>  Ignore response with status codes (default 404)
-m    --method                  <method>        Use said HTTP method (default: HEAD)
-se   --scheme                  <scheme>        Use scheme when missing (default: http)
-d    --delay                   <miliseconds>   Delay before each request in seconds
-p    --proxy                   <proxy>         Use proxy (e.g. http://127.0.0.1:8080)
-T    --timeout                 <miliseconds>   Manually set timeout (default 10000)
-cl   --content-length          <kilobytes>     Max content length to download and parse (default: 1000KB)
-H    --headers                 <headers>       Use custom headers
-ua   --user-agent              <agent>         Use custom value of User-Agent header
-c    --cookie                  <cookies>       Use cookie (-c "PHPSESSID=abc; any=123")
-rc   --refuse-cookies                          Do not use cookies sets by application
-a    --auth                    <name:pass>     Use HTTP authentication
-t    --threads                 <threads>       Number of threads (default 20)
-wd   --without-domain                          Output of discovered sources without domain
-wh   --with-headers                            Output of discovered sources with headers
-ip   --include-parameters                      Include GET parameters and anchors to output
-tr   --tree                                    Output as tree
-o    --output                  <filename>      Output to file
-S    --save                    <directory>     Save content localy
-wdc  --without_dns_cache                       Do not use DNS cache (example for /etc/hosts records)
-wa   --without_availability                    Do not use target availability check
-tg   --target                  <ip or host>    Use this target when * is in domain
-nr   --not-redirect                            Do not follow redirects
-s    --silent                                  Do not show statistics in realtime
-er   --errors                                  Show all errors
-C    --cache                                   Cache each request response to temp file
-v    --version                                 Show script version
-h    --help                                    Show this help message
-j    --json                                    Output in JSON format
```

## Dependencies
```
ptlibs
appdirs
treelib
filelock
```



## License

Copyright (c) 2024 Penterep Security s.r.o.

ptwebdiscover is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

ptwebdiscover is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with ptwebdiscover. If not, see https://www.gnu.org/licenses/.

## Warning

You are only allowed to run the tool against the websites which
you have been given permission to pentest. We do not accept any
responsibility for any damage/harm that this application causes to your
computer, or your network. Penterep is not responsible for any illegal
or malicious use of this code. Be Ethical!
