# -*- coding: utf-8 -*-
import collections
import json
import pandas as pd
from pandas.io.json import json_normalize
# from tqdm import tqdm
from ipaddress import ip_address
from tldextract import extract
import re
import confusion_matrix
import os
import csv

def DumpToFile(d, f_path, columns=[]):
    _, file_extension = os.path.splitext(f_path)

    if file_extension == ".csv":
        try:
            with open(f_path, 'w', errors="surrogateescape") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=columns)
                writer.writeheader()
                for data in d:
                    writer.writerow(data)
        except IOError:
            print("I/O error")
    else:
        with open(f_path, 'w') as fout:
            json.dump(d, fout, indent=4)

def ConvertNumToStrings(d):
    new_d = d.copy()
    for k, v in d.items():
        if isinstance(v, dict):
            new_d[k] = ConvertNumToStrings(v)
        elif isinstance(v, float) or isinstance(v, int):
            new_d[k] = str(v)
    return new_d


def FixVulns(d):
    new_d = d.copy()
    if "vulns" in d:
        if d["vulns"] != None:
            new_d["vulns"] = [k for k, v in d["vulns"].items()]
    return new_d


def ExtractRootDomain(url):
    tsd, td, tsu = extract(url)  # prints abc, hostname, com
    return td + '.' + tsu


def ReverseDict(d):
    new_d = {}

    for k, dom in d.items():
        for i in dom:
            if i not in new_d:
                new_d[i] = []
            new_d[i] += [k]
    return new_d

def safe_str(obj):
    try: return str(obj)
    except UnicodeEncodeError:
        return obj.encode('ascii', 'ignore').decode('ascii')
    return ""

def FindGoogleAnalytics(data):
    data = safe_str(data)
    if data.find("UA-") != -1:
        index = data.find("UA-") + len("UA-")
        nextb = data[index:].find("-")
        if index + nextb <= len(data):
            f = data[index:index + nextb + 2]
            if re.compile(r'\d+(?:,\d*)?').match(f):
                return "UA-{}".format(f)
    return None

def FindNewRelic(data):
    #data = str(data)
    #if data.find(r"\"licenseKey\":\\")
    return

def LoadAndFixHSSet(columns=[]):
    fd = open(os.path.join("datasets", "malware_host_scan.json"), "r")

    all_lines = fd.readlines()

    list_of_dicts = [collections.OrderedDict(sorted(json.loads(d).items())) for d in all_lines]

    new_list_of_dicts = []
    for d in list_of_dicts:
        new_list_of_dicts += [ConvertNumToStrings(FixVulns(d))]

    hs_df = json_normalize(new_list_of_dicts)

    new_hs_df = hs_df[columns]

    if "GoogleID" in columns:
        new_hs_df['GoogleID'] = new_hs_df['http.html'].apply(FindGoogleAnalytics)

    return new_hs_df


def LoadAndFixDomainsSet(domains_to_root=True):
    domains_df = pd.read_csv(os.path.join("datasets", 'all_domains_links.csv'))

    # Copy only the A rows to a new dataframe
    new_domains_df = domains_df.loc[domains_df.type == 'A'].copy().reset_index()[["sha256", "domain", "benign", "response"]]

    if domains_to_root:
        # Turn all Domains -> Root Domains
        new_domains_df = new_domains_df.groupby(["domain", "response"]).size().reset_index(name='counts').sort_values(by='counts',
                                                                                                              ascending=False)
    else:
        new_domains_df = new_domains_df[new_domains_df["benign"] == 0]

    new_domains_df['domain_fix'] = new_domains_df['domain'].apply(ExtractRootDomain)

    return new_domains_df

def GetUniqueByCols(tmp_df, cols):
    # Capture the unique root domains and their IPs
    fixed_domains_df = tmp_df.groupby(cols).size().reset_index(name='counts').sort_values(by='counts', ascending=False)

    return fixed_domains_df

def GetDomainsAndIPsJsons(df):
    # Save the unique root domains and their IPs into a dictionary
    DomainsToIpsDict = dict(df.groupby("domain_fix")['response'].apply(list))

    DomainsToIpsSortedDict = collections.OrderedDict(sorted(DomainsToIpsDict.items()))

    DumpToFile(DomainsToIpsSortedDict, "DomainsToIps.json")

    IpsToDomainsDict = ReverseDict(DomainsToIpsDict)

    IpsToDomainsSortedDict = collections.OrderedDict(sorted(IpsToDomainsDict.items()))

    DumpToFile(IpsToDomainsSortedDict, "IpsToDomains.json")

    return DomainsToIpsSortedDict, IpsToDomainsSortedDict


def Distance(ip1, ip2):
    return abs(int(ip_address(ip1)) - int(ip_address(ip2)))


def NegativePairs(hosts_df, neg_count, join_column):
    df = hosts_df.copy()

    df_1 = df.copy().add_prefix("ip1_")
    df_2 = df.copy().add_prefix("ip2_")

    pairs = []
    ret_df = pd.DataFrame(pairs)

    while len(ret_df) < neg_count:
        print("Reached here with {} need {}".format(len(ret_df), neg_count))

        rand_df1 = df_1.sample(frac=1).reset_index(drop=True)
        rand_df2 = df_2.sample(frac=1).reset_index(drop=True)

        pairs_df = pd.concat([rand_df1, rand_df2], axis=1)
        pairs_df = pairs_df[pairs_df['ip1_ip_str'] != pairs_df['ip2_ip_str']]
        pairs_df['distance'] = pairs_df.apply(lambda x: Distance(x['ip1_ip_str'], x['ip2_ip_str']), axis=1)
        pairs_df[join_column] = "GENERATED"
        pairs_df['ip1'] = pairs_df['ip1_ip_str']
        pairs_df['ip2'] = pairs_df['ip2_ip_str']

        ret_df = ret_df.append(pairs_df.sample(n=min(len(pairs_df), neg_count)), sort=False)
        ret_df = ret_df.drop_duplicates(subset=["ip1", "ip2", "ip1_port", "ip2_port"])

    ret_df["related"] = 'false'

    print("Curr {}, Need {}".format(len(ret_df), neg_count))
    return ret_df.sample(n=neg_count).reset_index(drop=True)

def GetRandomPairs(positive_df, ratio=10):
    pairs = []
    pairs_count = len(positive_df) * ratio

    rand_df1 = positive_df.sample(frac=1).reset_index(drop=True)
    rand_df2 = positive_df.sample(frac=1).reset_index(drop=True)
    rand_df1['ip2'] = rand_df2['ip1']

    ret_df = pd.DataFrame(pairs, columns=['ip1', 'ip2', 'distance', 'related'])

    ret_df = ret_df.append(rand_df1.sample(n=min(len(rand_df1), pairs_count)), sort=False)

    while len(ret_df) < pairs_count:
        print("Reached here with {} need {}".format(len(ret_df), pairs_count))
        rand_df1 = ret_df.sample(frac=1).reset_index(drop=True)
        rand_df2 = ret_df.sample(frac=1).reset_index(drop=True)

        rand_df1['ip2'] = rand_df2['ip1']

        rand_df1 = rand_df1[rand_df1['ip1'] != rand_df1['ip2']]
        rand_df1['distance'] = rand_df1.apply(lambda x: Distance(x['ip1'], x['ip2']), axis=1)

        ret_df = ret_df.append(rand_df1, sort=False)
        ret_df = ret_df.drop_duplicates()

    ret_df["related"] = 'false'

    print("Curr {}, Need {}".format(len(ret_df), pairs_count))
    return ret_df.sample(n=pairs_count).reset_index(drop=True)


def GetPositivePairs(DomainsToIpsSortedDict):
    pairs = {}
    for k, ip_list in DomainsToIpsSortedDict.items():
        pairs.update(
            {str(sorted([ip1, ip2])): [ip1, ip2, Distance(ip1, ip2), "true"] for ip1 in ip_list for ip2 in ip_list if
             ip1 != ip2})

    pairs_df = pd.DataFrame(list(pairs.values()), columns=['ip1', 'ip2', 'distance', 'related'])

    return pairs_df

def SetupPredCols(df, col1_pre, col2_pre, fields, new_pre):
    if isinstance(fields, str):
        field = fields
        print("-- Applying on {} --".format(field))
        df.loc[df["{}_{}".format(col1_pre, field)] != df["{}_{}".format(col2_pre, field)], "is_{}_{}".format(new_pre, field)] = False
        df.loc[df["{}_{}".format(col1_pre, field)] == df["{}_{}".format(col2_pre, field)], "is_{}_{}".format(new_pre, field)] = True

    elif isinstance(fields, list):
        for field in fields:
            SetupPredCols(df, col1_pre, col2_pre, field, new_pre)
    elif isinstance(fields, tuple):
        field = fields
        print("-- Applying on {} --".format(field))
        df.loc[df["{}_{}".format(col1_pre, field)] != df["{}_{}".format(col2_pre, field)], "is_{}_{}".format(new_pre,
                                                                                                             field)] = False
        df.loc[df["{}_{}".format(col1_pre, field)] == df["{}_{}".format(col2_pre, field)], "is_{}_{}".format(new_pre,
                                                                                                             field)] = True

    else:
        raise Exception("Invalid fields parameter")


def Confuse(df, concept, prefix):
    DoCM = lambda x, y: confusion_matrix.ConfusionMatrix(df[[x, y]], df.groupby([x, y]).size().reset_index(name="count"),
                                                         x, y, 'count')

    classes = {}

    for col in df.columns:
        if col.startswith(prefix):
            classes[col] = DoCM(col, concept)
    return classes

def GetDF(filename):
    with open(filename) as f:
       return pd.DataFrame(json.load(f)).T

def GetVersion():
    return "v1.4"
