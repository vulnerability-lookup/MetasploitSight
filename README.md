# MetasploitSight

A client designed to retrieve vulnerability-related information from the modules available in Metasploit.
It monitors changes to the file [db/modules_metadata_base.json](https://github.com/rapid7/metasploit-framework/tree/master/db).

The collected data is then transmitted to the
[Vulnerability-Lookup](https://github.com/vulnerability-lookup/vulnerability-lookup) API  as sightings.


## Installation

[pipx](https://github.com/pypa/pipx) is an easy way to install and run Python applications in isolated environments.

```bash
$ pipx install MetasploitSight
$ export METASPLOITSIGHT_CONFIG=~/.MetasploitSight/conf.py
$ git clone https://github.com/rapid7/metasploit-framework/ metasploit-repository
```

The configuration for MetasploitSight should be defined in a Python file (e.g., ``~/.MetasploitSight/conf.py``).
You must then set an environment variable (``METASPLOITSIGHT_CONFIG``) with the full path to this file.


## Usage

Run the client:

```
$ MetasploitSight
```

Starts the MetasploitSight client. It fetches updates from the official Metasploit repository and
checks db/modules_metadata_base.json for changes.


Show available commands and options:

```
$ MetasploitSight --help
```


## License

[MetasploitSight](https://github.com/vulnerability-lookup/MetasploitSight) is licensed under
[GNU General Public License version 3](https://www.gnu.org/licenses/gpl-3.0.html)

~~~
Copyright (c) 2025 Computer Incident Response Center Luxembourg (CIRCL)
Copyright (C) 2025 Cédric Bonhomme - https://github.com/cedricbonhomme
~~~
