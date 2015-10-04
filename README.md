Host Enricher
===============

A script that takes a host id (currently only IP, future also URL) and queries different open source information providers.

The raw output is currently saved and visual output is done via the console.

For example Passive DNS and detected URLs are merged between the different providers and sorted to date.

# Supported sources

* IBM X-Force Exchange
* Shodan
* SANS
* VirusTotal
* Cymon

# Usage

Copy the default config file to config.cfg and add your different API keys.

Call the script from the commandline and give the host info as the argument.

```
host_enricher.py 8.8.8.8
```

# Sample output

See for an example of the output in the file *sample_output.txt*