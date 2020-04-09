# HostSimilarity Thesis Implementation

This code base contains the implementation for the HostSimilarity Thesis.

## Requirements

### Python Packages:

* numpy
* pandas
* tldextract
* matplotlib
* tqdm
* seaborn
* dython
* pydotplus
* scikit\_learn

A *requirements.txt* file can be found in the main directory for convenience.

### Datasets Paths:

* "data\_processing/datasets/**malware\_host\_scan.json**"
* "data\_processing/datasets/**all\_domains\_links.csv"**

The data sets should be requested from Palo Alto Network, as further explained here:
[https://www.researchgate.net/publication/332555725\_Machine\_Learning\_in\_Cyber-Security\_-Problems\_Challenges\_and\_Data\_Sets](https://www.researchgate.net/publication/332555725_Machine_Learning_in_Cyber-Security_-Problems_Challenges_and_Data_Sets)

## Run

For processing the two datasets into the final dataset, run:
`python3 data_processing/main.py`

For obtaining the similarity learning results, run:
`python3 learning/main.py`

The results will be found under: *results/hs\_results* directory