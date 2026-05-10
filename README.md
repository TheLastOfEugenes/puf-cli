
```
                                                                      
                        ▄▄▄▄                       ▄▄▄▄         ██    
                       ██▀▀▀                       ▀▀██         ▀▀    
 ██▄███▄   ██    ██  ███████              ▄█████▄    ██       ████    
 ██▀  ▀██  ██    ██    ██                ██▀    ▀    ██         ██    
 ██    ██  ██    ██    ██       █████    ██          ██         ██    
 ███▄▄██▀  ██▄▄▄███    ██                ▀██▄▄▄▄█    ██▄▄▄   ▄▄▄██▄▄▄ 
 ██ ▀▀▀     ▀▀▀▀ ▀▀    ▀▀                  ▀▀▀▀▀      ▀▀▀▀   ▀▀▀▀▀▀▀▀ 
 ██                                                                   
                                                                      
```

# Presentation

**Pretty Useful Filter-cli** is a command line interface tool designed to start and read scans fast without missing anything.

The main goal of **puf-cli** is to provide a bunch of quick commands to start scans on a target, read the results very easily, store them in a place where it won't bother you and, on top of that, provide a filtering option that will allow you to not miss anything anymore.

# Installation

You can simply clone it with github
```
git clone https://github.com/TheLastOfEugenes/puf-cli.git
python3 -m pip install -e .
```

Or, for the exegol users, a quick command to add it to your image
```
echo "wget -qO- https://github.com/TheLastOfEugenes/puf-cli/archive/refs/tags/v1.0.tar.gz | tar -xz -C /opt/ && mv /opt/puf-cli-1.0 /opt/puf-cli & python3 -m pip install -e /opt/puf-cli" >> $HOME/.exegol/my-resources/setup/load_user_setup.sh
```

# Features

## Scans

The scans started on each target have been defined as the following:
```
# nmap
nmap -sCV -T4 -p- -v -oX {outfile} {target}

# files fuzzing
wordlist = /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt
ffuf -mc all -u {target}/FUZZ -w {wordlist} -o {outfile} -of json

# dirs fuzzing
wordlist = /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt
ffuf -mc all -u {target}/FUZZ -w {wordlist} -o {outfile} -of json

# subdomains fuzzing
wordlist = /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
ffuf -mc all -u {target} -H "Host: FUZZ.{hostname}" -w {wordlist} -o {outfile} -of json
```

These can be changed by using the `puf.conf` file (more on that lower in the readme).

The commands used to start each scans are the following:
```
run <target> files
run <target> dirs
run <target> subs
run <target> nmap
```

You can also start a "bundle", a collection of scans in a row. The default available bundles are
- path (files and dirs)
- web (files, dirs and subs)
- service (files, dirs, subs and nmap)
There will be the possibility of adding your own bundle, this work is in progress.

Those can be started with
```
run <target> path
run <target> web
run <target> service
```

![pufcli_run](https://raw.githubusercontent.com/TheLastOfEugenes/pufcli/master/resources/pufcli_run.png)

## Results display

As said before the App has as a goal to allow nice display of the results. For doing so, some rules have been set. When displaying files or dirs scans' results, it will be presented in a table of - by default - 250 rows.

The results are shown with the `show` command as such:
```
show <target> <kind>
```
with kind being the kind of scan, i.e.
```
show <target> nmap
show <target> files
...
```

For the subdomains scans' results, the same has been done but the url is not presented, instead is shown the host, which gives us the real url targeted.

![pufcli_show_all](https://raw.githubusercontent.com/TheLastOfEugenes/pufcli/master/resources/pufcli_show_all.png)

Finally, the nmap scan is fairly simple, all results are displayed in a nice tab too.

![pufcli_nmap](https://raw.githubusercontent.com/TheLastOfEugenes/pufcli/master/resources/pufcli_nmap.png)

For each of these scans, a simple color system has been added to make the output more clean.

### Relaunch

Each ffuf result display come with a relaunch system. What it means is essentially that when a scan is done and you have displayed the result, a column will show you a unique id per row, you can reuse this id to start a scan on this url. For example here:

![pufcli_row](https://raw.githubusercontent.com/TheLastOfEugenes/pufcli/master/resources/pufcli_row.png)

A url has been found with the rowid r1, you can then restart the scan on this id using the command
```
run r1 <scan>
```

### all

An option has been added to the display: `all`, this option allows one to display all types of results for the specified target.
```
show <target> all
```

### last

The last scanned target and last performed scan are stored so you can access it very easily:
```
show last <kind>
```
or
```
show last last
```

In itself it is not a big addition but it can be combined with `all` as well.
```
show last all
```

## Filter

As foresaid, the filter is one of, if not THE, best options of this tool. Usually, any tool designed for fuzzing has a built-in filter, somethign that allows you to quickly select the positive results in a list. Although most of those are very good filters, it sometimes happens that they miss one or two results in the name of cleanliness. This tool has a different goal.

Because missing a result can be a very important mistake and make you miss some services and because no tool can be as good at filtering following your idea as you are, the idea is to create a modulable filter. The filter has some basic options, it groups the results by size and, if one of those groups happens to be too big, it just yields it, removing it from the final result. On top of that, whenever you apply the filter, you can specify some option to disable this smart filtering, exclude status codes, cord counts or lengths. This - as a start - should allow you to correctly filter most of the scans you perform.

The scans performed by this app are designed to keep every result in order for you to be able to filter it according to your will, making the probability of you missing something very low.

As any other feature it comes with commands.
```
filter <target> <file>
```
This command gives you a `custom filtered <file>` file.

Whenever you start a scan, the filtering of the result is automatically added, which means you can start a scan and obtain the result as `filtered <file>` without having to filter it on top.

### show

When using `all` with the show command, it searches, for each file:
- if it has a `custom filtered` version
- if not, if it has a `filtered` version
- if not it reverts back to the normal version
and displays the first version found.

![[Pasted image 20260510153241.png]]

## Configuration

This is not at all the last option of this tool but it is worth mentionning. This tool has a config file stored ad `puf.conf` that allows the user to define a bunch of commands and files to use for the scans, this allows one to rewrite it and adapt the tool to one's preferences.

A command has been defined to allow modifying or adding commands: `scan`.
