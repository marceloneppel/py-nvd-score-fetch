# py-nvd-score-fetch

Script to fetch the NVD description and score from a list of CVEs.

## Usage

Create a file named `cve.txt` with a list of CVEs (one per line). The file format is the following:

```
CVE-2021-3995
CVE-2024-25629
```

Then run the script through `python3 main.py`.

A file called `cve.csv` will be created to store the results.
