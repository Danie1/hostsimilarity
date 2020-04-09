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
        self.ds['GoogleID'] = self.ds['http.html'].apply(FindGoogleAnalytics)

        def append_fields(x, field_list):
            values = []
            # Check not null
            for f in field_list:
                try:
                    if isinstance(x[f], list):
                        values += "_".join(x[f])
                    elif not pd.notnull(x[f]):
                        values += "-.-"
                    elif isinstance(x[f], str):
                        values += x[f]
                    elif isinstance(x[f], int):
                        values += str(x[f])
                    else:
                        raise ValueError("Error: Which value is this?")
                except ValueError as e:
                    print(str(e))
                    print(values)
                    for n_f in field_list:
                        print(x[n_f])
                    values += "-.-"

            return "_".join(values)

        self.ds["feature_group_a"] = self.ds.apply(lambda x: append_fields(x, ["port",
                                                                               "transport",
                                                                               "product",
                                                                               "version",
                                                                               "tags",
                                                                               "location.country_name",
                                                                               "asn",
                                                                               "isp",
                                                                               "org"]), axis=1)

        self.ds["cpe_port_transport_product_version"] = self.ds.apply(lambda x: append_fields(x, ["cpe",
                                                                                                "port",
                                                                                              "transport",
                                                                                              "product",
                                                                                              "version"]), axis=1)

        self.ds["port_transport_product_version"] = self.ds.apply(lambda x: append_fields(x, ["port",
                                                                                              "transport",
                                                                                              "product",
                                                                                              "version"]), axis=1)

        self.ds["cn_asn_org_isp"] = self.ds.apply(lambda x: append_fields(x, ["location.country_name",
                                                                              "asn",
                                                                              "org",
                                                                              "isp"]), axis=1)

        self.ds["cn_port_transport_asn_org_isp"] = self.ds.apply(lambda x: append_fields(x, ["port",
                                                                                              "location.country_name",
                                                                                              "transport",
                                                                                              "asn",
                                                                                              "org",
                                                                                              "isp"]), axis=1)
        self.ds["cpe_port_product"] = self.ds.apply(lambda x: append_fields(x, ["cpe",
                                                                                "port",
                                                                                "product"]), axis=1)

        self.ds["cpe_port_product_version"] = self.ds.apply(lambda x: append_fields(x, ["cpe",
                                                                                "port",
                                                                                "product",
                                                                                "version"]), axis=1)

        self.ds["port_product_version"] = self.ds.apply(lambda x: append_fields(x, ["port",
                                                                                "product",
                                                                                "version"]), axis=1)
        self.ds["port_product"] = self.ds.apply(lambda x: append_fields(x, ["port",
                                                                                "product"]), axis=1)

        self.ds["common_port"] = self.ds.apply(
            lambda x: x["port"] if pd.notnull(x["port"]) and int(x["port"]) <= 1023 else None, axis=1)
        self.ds["not_wellknown_port"] = self.ds.apply(
            lambda x: x["port"] if pd.notnull(x["port"]) and int(x["port"]) > 1023 else None, axis=1)
        self.ds["not_registered_port"] = self.ds.apply(
            lambda x: x["port"] if pd.notnull(x["port"]) and int(x["port"]) > 49151 else None, axis=1)

        self.ds["common_port_transport"] = self.ds.apply(lambda x: append_fields(x, ["common_port",
                                                                                     "transport"]), axis=1)
        self.ds["not_wellknown_port_transport"] = self.ds.apply(lambda x: append_fields(x, ["not_wellknown_port",
                                                                                            "transport"]), axis=1)
        self.ds["not_registered_port_transport"] = self.ds.apply(lambda x: append_fields(x, ["not_registered_port",
                                                                                            "transport"]), axis=1)
        self.ds["asn_org_isp"] = self.ds.apply(lambda x: append_fields(x, ["asn", "org", "isp"]), axis=1)
        self.ds["chain_fingerprint_serial_expires"] = self.ds.apply(lambda x: append_fields(x, ["ssl.chain",
                                                                                                "ssl.cert.fingerprint.sha256",
                                                                                                "ssl.cert.serial",
                                                                                                "ssl.cert.expires"]), axis=1)

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

        pos_neg_df = pos_neg_df.drop_duplicates(subset=["pairs", join_column], keep="last")

        pos_neg_df = pos_neg_df.drop(columns=["pairs", "counts_x", "counts_y"])

        pos_neg_df = pos_neg_df.rename(
            columns={"response_x": "ip1", "response_y": "ip2"}).reset_index(drop=True)

        pos_neg_df["distance"] = pos_neg_df.apply(lambda x: Distance(x["ip1"], x["ip2"]), axis=1)

        pos_neg_df["related"] = "true"

        d = pos_neg_df.groupby([join_column]).size().reset_index(name="count").sort_values(['count'], ascending=False)
        d["unique"] = d[join_column].apply(lambda x: len(set(list(pos_neg_df[pos_neg_df[join_column] == x]["ip1"]) + list(pos_neg_df[pos_neg_df[join_column] == x]["ip2"]))))

        print("Number of unique IPs: {}".format(d["unique"]))
        print("Number of interesting groups: {}".format(len(d[d["count"] > 1])))
        print("Number of valid groups: {}".format(len(d[d["count"] > 0])))
        print("{} biggest groups {}".format(5, d.head(5)))
        print("Number of positive pairs: {}".format(len(pos_neg_df)))

        return pos_neg_df.sort_values(["distance"], ascending=True).reset_index(drop=True)

    @staticmethod
    def __get_positive_pairs_deprecated__(domains_ds):
        DomainsToIpsDict, IpsToDomainsDict = GetDomainsAndIPsJsons(domains_ds.ds)
        print("Domains to IPs and IPs to Domain dictionaries created.")

        pairs_df = GetPositivePairs(DomainsToIpsDict)
        print("Got positive pairs from the Domains to Ips dictionary.")

        return pairs_df

    def create(self, hosts_ds=None, domains_ds=None, deprecated=False, join_column=None):
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
        if hosts_ds is None:
            random_df = GetRandomPairs(pairs_df, ratio=5)
        else:
            print("Getting the negative pairs with the new method.")
            ips_list = pairs_df["ip1"].tolist() + pairs_df["ip2"].tolist()
            ips_list = set(ips_list)
            filtered_hosts_df = hosts_ds.ds[~hosts_ds.ds['ip_str'].isin(ips_list)]
            print("Hosts Set Unique IPs: {} || Domains Set Unique IPs {} || H not in D: {}".format(hosts_ds.ds['ip_str'].nunique(), 
                                                                                                   len(ips_list), 
                                                                                                   filtered_hosts_df['ip_str'].nunique()))
            random_df = NegativePairs(filtered_hosts_df, len(pairs_df) * 5, join_column)

            # Keep only the relevant columns
            random_df = random_df[["related", join_column, "ip1", "ip2", "distance"]]

        print("Generated {} random pairs from {} positive pairs.".format(len(random_df), len(pairs_df)))

        # Append the random pairs to the positive pairs
        new_df = pairs_df.append(random_df, sort=False).reset_index(drop=True)

        # Remove the negative pairs if they exist as positive.
        # (The First pairs will be positive due to the previous line!)
        tmp_df = new_df.groupby(['ip1', 'ip2']).first().reset_index().sort_values(by="distance")

        # Append the negative pairs which are not duplicates of the positive to the positives
        self.ds = pairs_df.append(tmp_df[tmp_df["related"] == "false"], sort=False).reset_index(drop=True)

        print("Random + Positive = {}".format(len(self.ds)))

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
        merged_df1["pair"] = merged_df1.apply(lambda x: "{}_{}".format(x['ip1'], x['ip2']), axis=1)
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

        print("Total Unique Positives IPs: {} && Total Unique Negatives IPs {}".format(len(Join(a, b)), len(Join(c, d))))
        print("W/ Hosts Total Unique Positive Pairs: {} && Total Unique Negative Pairs: {}".format(len(lsl), len(tst)))

    def transform_alt(self, is_equal_cols, values=None):
        def setup(df, col1_pre, col2_pre, fields, new_pre, values=None):
            if values is None:
                values = [0, 0.5, 1]

            if isinstance(fields, str):
                field = fields
                print("-- Applying on {} --".format(field))

                error = False
                if "{}_{}".format(col1_pre, field) not in df.columns:
                    print("Error ip1_: {}".format("{}_{}".format(col1_pre, field)))
                    error = True
                if "{}_{}".format(col2_pre, field) not in df.columns:
                    print("Error ip2_: {}".format("{}_{}".format(col2_pre, field)))
                    error = True

                if error:
                    return

                df.loc[
                    df["{}_{}".format(col1_pre, field)] != df["{}_{}".format(col2_pre, field)], "is_{}_{}".format(new_pre,
                                                                                                                  field)] = values[0]
                df.loc[
                    pd.isnull(df["{}_{}".format(col1_pre, field)]) & pd.isnull(df["{}_{}".format(col2_pre, field)]), "is_{}_{}".format(new_pre,
                                                                                                                  field)] = values[1]
                df.loc[
                    df["{}_{}".format(col1_pre, field)] == df["{}_{}".format(col2_pre, field)], "is_{}_{}".format(new_pre, field)] = values[2]
            elif isinstance(fields, list):
                for field in fields:
                    setup(df, col1_pre, col2_pre, field, new_pre, values)
            else:
                raise Exception("Invalid fields parameter")

        setup(self.ds, "ip1", "ip2", is_equal_cols, "equal", values)

        self.ds['is_close'] = False
        self.ds.loc[self.ds['ip1_distance'] <= 65535, "is_close"] = True

        self.ds["is_very_close"] = False
        self.ds.loc[self.ds['ip1_distance'] <= 256, "is_very_close"] = True

        self.ds["related"] = False
        self.ds.loc[self.ds['ip1_related'] == "true", "related"] = True

        self.ds["pair"] = self.ds["ip1_pair"]

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

                #fd.write(str(list(["Feature Name"] + list(result.keys()))))
                fd.write(str(list([k] + list(result.values()))))
                fd.write("\n")

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

    def get_pos_neg_from_domains(self, domains_ds, new_id, new_ds_class, filepath, hosts_ds=None, join_column=None):
        if new_id in self.ds_map:
            return self.ds_map[new_id]

        ds = new_ds_class([])

        if ds.does_exist(filepath):
            ds.load(filepath)
            print("Loaded {} from file {}".format(new_id, filepath))
        else:
            ds.create(hosts_ds, domains_ds, join_column=join_column)
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
