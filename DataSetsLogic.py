from Utils import *

import os
import pprint

class DSLogic(object):
    def __init__(self, cols=[]):
        self.cols = cols
        self.ds = None
        return

    def does_exist(self, filepath):
        if os.path.exists(filepath):
            return True
        return False

    def create(self):
        pass

    def load(self, filepath):
        _, file_extension = os.path.splitext(filepath)
        if file_extension == ".csv":
            self.ds = pd.read_csv(filepath)
        else:
            self.ds = GetDF(filepath)
        pass

    def drop(self, cols):
        if self.ds is not None:
            self.ds = self.ds.drop(columns=cols)

    def drop_duplicates(self):
        self.ds = self.ds.iloc[self.ds.astype(str).drop_duplicates().index]

    def save(self, filepath):
        DumpToFile(self.ds.to_dict('index'), filepath, self.ds.columns)

    def get(self):
        pass

class HostsDS(DSLogic):
    def __init__(self, cols, df=None):
        if df is None:
            super(HostsDS, self).__init__(cols)
        else:
            self.ds = df

    def load(self, filepath):
        super(HostsDS, self).load(filepath)

    def create(self):
        if self.ds is not None:
            print("Overriding Hosts Dataset with data.")
        self.ds = LoadAndFixHSSet(self.cols)
        print("Malware host scans set loaded.")

    def transform(self):
        def PutNaNAndMakeList(x):
            ret = list(filter(lambda a: a != None and a != [], x.tolist()))
            ret.sort()
            if len(ret) > 0:
                return ret
            return None

        ret_ds = self.ds.copy()

        # replace NaN with None
        ret_ds = ret_ds.replace({pd.np.nan: None})

        # Aggregate rows with the same IP (their fields will be list)
        ret_ds = ret_ds.groupby(["ip_str"]).agg(lambda x: PutNaNAndMakeList(x))

        return HostsDS(self.cols, df=ret_ds)

    def add_features(self):
        self.ds["port_product_version"] = self.ds.apply(
            lambda x: "{}_{}_{}".format(x["port"], x["product"], x["version"]) if pd.notnull(
                x["product"]) and pd.notnull(
                x["version"]) else None, axis=1)
        self.ds["port_product"] = self.ds.apply(
            lambda x: "{}_{}".format(x["port"], x["product"]) if pd.notnull(x["product"]) else None, axis=1)
        self.ds["common_port"] = self.ds.apply(
            lambda x: x["port"] if pd.notnull(x["port"]) and int(x["port"]) <= 1023 else None, axis=1)
        self.ds["not_wellknown_port"] = self.ds.apply(
            lambda x: x["port"] if pd.notnull(x["port"]) and int(x["port"]) > 1023 else None, axis=1)
        self.ds["not_registered_port"] = self.ds.apply(
            lambda x: x["port"] if pd.notnull(x["port"]) and int(x["port"]) > 49151 else None, axis=1)
        self.ds["common_port_transport"] = self.ds.apply(
            lambda x: "{}_{}".format(x["common_port"], x["transport"]) if pd.notnull(x["common_port"]) and pd.notnull(
                x["transport"]) else None, axis=1)
        self.ds["not_wellknown_port_transport"] = self.ds.apply(
            lambda x: "{}_{}".format(x["not_wellknown_port"], x["transport"]) if pd.notnull(
                x["not_wellknown_port"]) and pd.notnull(x["transport"]) else None, axis=1)
        self.ds["not_registered_port_transport"] = self.ds.apply(
            lambda x: "{}_{}".format(x["not_registered_port"], x["transport"]) if pd.notnull(
                x["not_registered_port"]) and pd.notnull(x["transport"]) else None, axis=1)

    def save(self, filepath="fixed_hostsimilarity.json"):
        super(HostsDS, self).save(filepath)
        print("Saved the fixed malware host scan dataset to a JSON file.")

class DomainsDS(DSLogic):
    def __init__(self, cols):
        super(DomainsDS, self).__init__(cols)
        self.isRootDomainType = True

    def SetSha256(self):
        self.isRootDomainType = False

    def load(self, filepath="domains.json"):
        super(DomainsDS, self).load(filepath)

    def create(self):
        if self.ds is not None:
            print("Overriding Hosts Dataset with data.")
        self.ds = GetUniqueByCols(LoadAndFixDomainsSet(self.isRootDomainType), self.cols)
        print("Domains set loaded.")

    def save(self, filepath="domains.json"):
        super(DomainsDS, self).save(filepath)
        print("Saved the domains dataset to a json file.")

class PositiveNegativeDS(DSLogic):
    def __init__(self, cols):
        super(PositiveNegativeDS, self).__init__(cols)
        self.orig_ds = None

    def load(self, filepath="IPsPairingDistance.json"):
        super(PositiveNegativeDS, self).load(filepath)

    @staticmethod
    def __get_positive_pairs__(domains_ds, join_column):
        df = domains_ds.ds.copy()

        pos_neg_df = df.merge(df, left_on=join_column, right_on=join_column)

        pos_neg_df = pos_neg_df[pos_neg_df.response_x != pos_neg_df.response_y].reset_index(drop=True)

        pos_neg_df["pairs"] = pos_neg_df.apply(lambda x: "%s_%s" % tuple(sorted([x["response_x"], x["response_y"]])),
                                               axis=1)

        pos_neg_df = pos_neg_df.drop_duplicates(subset="pairs", keep="last")

        pos_neg_df = pos_neg_df.drop(columns=["pairs", "counts_x", "counts_y"])

        pos_neg_df = pos_neg_df.rename(
            columns={"response_x": "ip1", "response_y": "ip2", join_column: "domain"}).reset_index(drop=True)

        pos_neg_df["distance"] = pos_neg_df.apply(lambda x: Distance(x["ip1"], x["ip2"]), axis=1)

        pos_neg_df["related"] = "true"

        return pos_neg_df.sort_values(["distance"], ascending=True).reset_index(drop=True)

    @staticmethod
    def __get_positive_pairs_deprecated__(domains_ds):
        DomainsToIpsDict, IpsToDomainsDict = GetDomainsAndIPsJsons(domains_ds.ds)
        print("Domains to IPs and IPs to Domain dictionaries created.")

        pairs_df = GetPositivePairs(DomainsToIpsDict)
        print("Got positive pairs from the Domains to Ips dictionary.")

        return pairs_df

    def create(self, domains_ds=None, deprecated=False, join_column=None):
        if domains_ds is None:
            raise Exception("Must have a domains data set for positive/negative pairing.")
        if self.ds is not None:
            print("Overriding Hosts Dataset with data.")

        if deprecated and join_column is not None:
            raise Exception("Deprecated version doesn't support a join column")
        elif deprecated:
            pairs_df = self.__get_positive_pairs_deprecated__(domains_ds)
        elif join_column is not None:
            pairs_df = self.__get_positive_pairs__(domains_ds, join_column)
        else:
            raise Exception("Error: You must specify a column to join upon.")

        # Get random pairs without duplicates.
        # * Some pairs will also be positive. We will remove them later.
        random_df = GetRandomPairs(pairs_df, ratio=5)
        print("Generated {} random pairs from {} positive pairs.".format(len(random_df), len(pairs_df)))

        # Append the random pairs to the positive pairs
        new_df = pairs_df.append(random_df).reset_index(drop=True)
        print("Random + Positive = {}".format(len(new_df)))

        # Remove the negative pairs if they exist as positive.
        # (The First pairs will be positive due to the previous line!)
        self.ds = new_df.groupby(['ip1', 'ip2']).first().reset_index().sort_values(by="distance")

        len_positive = len(self.ds[self.ds["related"] == "true"])
        len_negative = len(self.ds[self.ds["related"] == "false"])

        print("Negative = {}, Positive = {}".format(len_negative, len_positive))

        if len_positive != len(pairs_df):
            raise Exception("Error: Something went wrong with the creation of the Pos_Neg_DS!")


    def save(self, filepath="IPsPairingDistance.json"):
        super(PositiveNegativeDS, self).save(filepath)
        print("Saved the combined dataset to a json file.")


class MergedDS(DSLogic):
    def __init__(self, cols):
        super(MergedDS, self).__init__(cols)

    def load(self, filepath="final.json"):
        super(MergedDS, self).load(filepath)

    def save(self, filepath="final1.json"):
        super(MergedDS, self).save(filepath)
        print("Saving the merged data set to a file.")

    def create(self):
        pass

    def merge(self, pos_neg_df, hosts_df):
        if self.ds is not None:
            print("Overriding Hosts Dataset with data.")

        merged_df1 = pos_neg_df.merge(hosts_df, left_on='ip1', right_on='ip_str')
        merged_df1["pair"] = merged_df1.apply(lambda x: "{}_{}".format(str(x['ip1']), str(x['ip2'])), axis=1)
        merged_df1 = merged_df1.add_prefix("ip1_")

        merged_df2 = pos_neg_df.merge(hosts_df, left_on='ip2', right_on='ip_str')
        merged_df2["pair"] = merged_df2.apply(lambda x: "{}_{}".format(x['ip1'], x['ip2']), axis=1)
        merged_df2 = merged_df2.add_prefix("ip2_")

        self.ds = merged_df1.merge(merged_df2, left_on='ip1_pair', right_on='ip2_pair')

        Join = lambda a, b: list(set().union(a, b))

        lsl = self.ds[self.ds["ip1_related"] == "true"][["ip1_ip1", "ip1_ip2"]].astype(
            str).drop_duplicates().sort_values(["ip1_ip1", "ip1_ip2"])

        tst = self.ds[self.ds["ip2_related"] == "true"][["ip2_ip1", "ip2_ip2"]].astype(
            str).drop_duplicates().sort_values(["ip2_ip1", "ip2_ip2"])

        if len(lsl) != len(tst):
            raise Exception("ERROR!! SOMETHING WENT REALLY BAD WITH THE MERGE!!")

        tst = self.ds[self.ds["ip2_related"] == "false"][["ip2_ip1", "ip2_ip2"]].astype(
            str).drop_duplicates().sort_values(["ip2_ip1", "ip2_ip2"])

        a = list(lsl.groupby(["ip1_ip1"]).sum().reset_index()["ip1_ip1"])
        b = list(lsl.groupby(["ip1_ip2"]).sum().reset_index()["ip1_ip2"])

        c = list(tst.groupby(["ip2_ip1"]).sum().reset_index()["ip2_ip1"])
        d = list(tst.groupby(["ip2_ip2"]).sum().reset_index()["ip2_ip2"])

        print("Total Unique Positives: {} && Total Unique Negatives {}".format(len(Join(a, b)), len(Join(c, d))))
        print("W/ Hosts Total Unique Positives: {} && Total Unique Negatives {}".format(len(lsl), len(tst)))


    def transform(self, is_equal_cols):
        SetupPredCols(self.ds, "ip1", "ip2", is_equal_cols, "equal")

        self.ds['is_close'] = False
        self.ds.loc[self.ds['ip1_distance'] <= 65535, "is_close"] = True

        self.ds["is_very_close"] = False
        self.ds.loc[self.ds['ip1_distance'] <= 256, "is_very_close"] = True

        self.ds["related"] = False
        self.ds.loc[self.ds['ip1_related'] == "true", "related"] = True

        self.ds["pair"] = self.ds["ip1_pair"]

    def run_cm(self, filepath):
        pp = pprint.PrettyPrinter(indent=4)
        classes = Confuse(self.ds, "related", "is_")

        with open(filepath, "w") as fd:
            for k, v in classes.items():
                result = v.summarize(digits=5, enable_mutual_info=True)

                print("== {} ==\n".format(k))
                pp.pprint(result)
                print("\n\n".format(k))

                fd.write("== {} ==\n".format(k))
                fd.write(pp.pformat(result))
                fd.write("== {} ==\n\n\n".format(k))

class Logic(object):
    def __init__(self):
        self.ds_map = {}

    def get_ds_by_instance(self, ds_id, ds, filepath):
        if ds_id in self.ds_map:
            return self.ds_map[ds_id]

        if ds.does_exist(filepath):
            ds.load(filepath)
            print("Loaded {} from file {}".format(ds_id, filepath))
        else:
            ds.create()
            print("Creating {}".format(ds_id))

        self.ds_map[ds_id] = ds
        return self.ds_map[ds_id]

    def get_ds(self, ds_id, ds_class, filepath, cols=[]):
        if ds_id in self.ds_map:
            return self.ds_map[ds_id]

        ds = ds_class(cols)

        if ds.does_exist(filepath):
            ds.load(filepath)
            print("Loaded {} from file {}".format(ds_id, filepath))
        else:
            ds.create()
            print("Creating {}".format(ds_id))

        self.ds_map[ds_id] = ds
        return self.ds_map[ds_id]

    def get_pos_neg_from_domains(self, domains_ds, new_id, new_ds_class, filepath, join_column=None):
        if new_id in self.ds_map:
            return self.ds_map[new_id]

        ds = new_ds_class([])

        if ds.does_exist(filepath):
            ds.load(filepath)
            print("Loaded {} from file {}".format(new_id, filepath))
        else:
            ds.create(domains_ds, join_column=join_column)
            print("Creating {}".format(new_id))

        self.ds_map[new_id] = ds

        return self.ds_map[new_id]

    def save_ds(self, id, filepath):
        self.ds_map[id].save(filepath)

    def get_merged_ds(self, ds_id, first_ds, seconds_ds, filepath):
        ds = MergedDS([])

        if ds.does_exist(filepath):
            ds.load(filepath)
            print("Loaded {} from file {}".format(ds_id, filepath))
        else:
            ds.merge(first_ds.ds, seconds_ds.ds)
            print("Merging into {}".format(ds_id))

        self.ds_map[ds_id] = ds

        return self.ds_map[ds_id]
