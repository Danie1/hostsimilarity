#!/usr/bin/env python3
from DataSetsLogic import *


def save_pos_pairs_data(pos_neg_ds, join_column, f_path):
    pos_groups_df = pos_neg_ds.ds[pos_neg_ds.ds["related"] == "true"].groupby([join_column]).size().reset_index(name="count").sort_values(
        ['count'], ascending=False)
    pos_groups_df["unique"] = pos_groups_df[join_column].apply(lambda x: len(set(list(
        pos_neg_ds.ds[pos_neg_ds.ds["related"] == "true"][pos_neg_ds.ds[pos_neg_ds.ds["related"] == "true"][join_column] == x]["ip1"]) + list(
        pos_neg_ds.ds[pos_neg_ds.ds["related"] == "true"][pos_neg_ds.ds[pos_neg_ds.ds["related"] == "true"][join_column] == x]["ip2"]))))

    pos_groups_df.to_csv(os.path.join(f_path), index=False)


def root_domain_logic(workspace_dir, hosts_cols, is_equal_cols, root_domain_cols, new_grouping=True):
    l = Logic()

    hosts_ds = l.get_ds("hosts1", HostsDS, os.path.join(workspace_dir, "hosts1.json"), hosts_cols)
    hosts_ds.add_features()

    domains_ds = l.get_ds("domains1", DomainsDS, os.path.join(workspace_dir, "domains1.json"), root_domain_cols)

    grouping = None
    prefix = "old"

    if new_grouping:
        grouping = hosts_ds
        prefix = "new"

    pos_neg_ds = l.get_pos_neg_from_domains(domains_ds, "pos_neg1", PositiveNegativeDS,
                                            os.path.join(workspace_dir, "pos_neg1.json"), grouping, join_column="domain_fix")

    save_pos_pairs_data(pos_neg_ds, join_column="domain_fix", f_path=os.path.join(workspace_dir, "{}_pos_groups_TLD.csv".format(prefix)))

    # Multiple IPs (rows) will be aggregated to one row per IP. All other fields will be in lists.
    new_hosts_ds = hosts_ds.transform()

    def Perform(_l, _workspace_dir, _pos_neg_ds, _new_hosts_ds, _is_equal_cols, values, _prefix):
        # Get the newly merged ds after the transformation
        new_merged_ds = _l.get_merged_ds("{}_merged".format(_prefix),
                                         _pos_neg_ds,
                                         _new_hosts_ds,
                                         os.path.join(_workspace_dir, "{}_{}".format(_prefix, "tld_ds.json")))

        new_merged_ds.ds = new_merged_ds.ds[new_merged_ds.ds["ip1_ip1"] != new_merged_ds.ds["ip2_ip2"]]
        new_merged_ds.transform_alt(_is_equal_cols, values)

        #new_merged_ds.run_cm(os.path.join(_workspace_dir, "{}_{}".format(_prefix, "tld_cm.txt")))

        cols_to_save = ["related", "ip1_ip1", "ip1_ip2", "pair", "is_very_close", "is_close"]
        cols_to_save.extend(["{}_{}".format("is_equal", i) for i in _is_equal_cols])

        tosave_df = pd.DataFrame(new_merged_ds.ds, columns=cols_to_save)
        tosave_df.to_csv(os.path.join(_workspace_dir, "{}_{}".format(_prefix, "tld_is_equal.csv")), index=False)

    print ("==> Starting TLD {} NULL operation".format(prefix))
    Perform(l,
            workspace_dir,
            pos_neg_ds,
            new_hosts_ds,
            is_equal_cols,
            values=[0, 0.5, 1],
            _prefix="{}_{}".format(prefix, "NULL"))

    print ("==> Starting TLD {} NO-NULL operation".format(prefix))
    Perform(l,
            workspace_dir,
            pos_neg_ds,
            new_hosts_ds,
            is_equal_cols,
            values=[0, 0, 1],
            _prefix="{}_{}".format(prefix, "NO_NULL"))


def sha256logic(workspace_dir, hosts_cols, is_equal_cols, md5_domain_cols, new_grouping=True):
    l = Logic()

    hosts_ds = l.get_ds("hosts2", HostsDS, os.path.join(workspace_dir, "hosts2.json"), hosts_cols)
    hosts_ds.add_features()

    domains_ds = DomainsDS(md5_domain_cols)
    domains_ds.SetSha256()
    domains_ds = l.get_ds_by_instance("domains2", domains_ds, os.path.join(workspace_dir, "domains2.json"))

    grouping = None
    prefix = "old"

    if new_grouping:
        grouping = hosts_ds
        prefix = "new"

    pos_neg_ds = l.get_pos_neg_from_domains(domains_ds, "pos_neg2", PositiveNegativeDS,
                                            os.path.join(workspace_dir, "pos_neg2.json"), grouping, join_column="sha256")

    save_pos_pairs_data(pos_neg_ds, join_column="sha256",
                        f_path=os.path.join(workspace_dir, "{}_pos_groups_MAL.csv".format(prefix)))

    # Multiple IPs (rows) will be aggregated to one row per IP. All other fields will be in lists.
    new_hosts_ds = hosts_ds.transform()

    def Perform(_l, _workspace_dir, _pos_neg_ds, _new_hosts_ds, _is_equal_cols, values, _prefix):
        # Get the newly merged ds after the transformation
        new_merged_ds1 = l.get_merged_ds("{}_merged".format(_prefix), _pos_neg_ds, _new_hosts_ds,
                                         os.path.join(_workspace_dir, "{}_{}".format(_prefix, "sha_ds.json")))
        new_merged_ds1.ds = new_merged_ds1.ds[new_merged_ds1.ds["ip1_ip1"] != new_merged_ds1.ds["ip2_ip2"]]

        new_merged_ds1.transform_alt(_is_equal_cols, values)

        #new_merged_ds1.run_cm(os.path.join(_workspace_dir, "{}_{}".format(_prefix, "sha_cm.txt")))

        # merged_ds.save(os.path.join(workspace_dir, "merged_ds3.json"))
        #new_merged_ds1.save(os.path.join(workspace_dir, "merged_ds4.json"))
        cols_to_save = ["related", "ip1_ip1", "ip1_ip2", "pair", "is_very_close", "is_close"]
        cols_to_save.extend(["{}_{}".format("is_equal", i) for i in _is_equal_cols])
        #cols_to_save.extend(is_equal_cols)

        tosave_df = pd.DataFrame(new_merged_ds1.ds, columns=cols_to_save)
        tosave_df.to_csv(os.path.join(_workspace_dir, "{}_{}".format(_prefix, "sha_is_equal.csv")), index=False)

    print("==> Starting SHA {} NULL operation".format(prefix))
    Perform(l,
            workspace_dir,
            pos_neg_ds,
            new_hosts_ds,
            is_equal_cols,
            values=[0, 0.5, 1],
            _prefix="{}_{}".format(prefix, "NULL"))

    print("==> Starting SHA {} NO-NULL operation".format(prefix))
    Perform(l,
            workspace_dir,
            pos_neg_ds,
            new_hosts_ds,
            is_equal_cols,
            values=[0, 0, 1],
            _prefix="{}_{}".format(prefix, "NO_NULL"))
def main():
    WORKSPACE_DIR = "hs_results_20"

    hosts_cols = ['asn', 'domains', 'product', 'ip', 'ip_str', 'http.html_hash', 'location.country_name',
         'location.latitude', 'location.longitude', 'org', 'os', 'port', 'opts.vulns', 'info', 'cpe', 'transport', "opts.raw",
         'isp', 'version', 'hostnames', 'http.redirects', 'http.html', "link", "http.robots_hash", "http.title", "tags",
         'ssl.cert.fingerprint.sha256', 'ssl.cert.serial', 'ssl.chain', 'ssl.dhparams.public_key', 'ssl.cert.expires', "ftp.features_hash"]

    is_equal_cols = ["GoogleID", "common_port", "not_wellknown_port", "not_registered_port", "common_port_transport",
                     "not_wellknown_port_transport",  "not_registered_port_transport", "port_product_version",
                     "port_product", "os", "version", "product", "asn", "org", "link", "http.robots_hash", "http.title",
                     "http.html_hash", "location.country_name", "port", "cpe", 'isp', "tags", "ftp.features_hash",
                     'transport', "info", "opts.vulns", 'ssl.cert.fingerprint.sha256', "opts.raw",
                     'ssl.cert.serial', 'ssl.chain', 'ssl.dhparams.public_key', "port_transport_product_version",
                     'ssl.cert.expires', "asn_org_isp", "chain_fingerprint_serial_expires", "feature_group_a",
                     "cn_port_transport_asn_org_isp", "cpe_port_product_version", "cn_asn_org_isp", "cpe_port_transport_product_version"]

    root_domain_cols = ["domain_fix", "response"]

    md5_domain_cols = ["sha256", "domain_fix", "response"]

    if not os.path.exists(WORKSPACE_DIR):
        os.mkdir(WORKSPACE_DIR, 777)

    #print("=> Starting with TLD New")
    #root_domain_logic(WORKSPACE_DIR, hosts_cols, is_equal_cols, root_domain_cols, new_grouping=True)

    #print("=> Starting with TLD Old")
    #root_domain_logic(WORKSPACE_DIR, hosts_cols, is_equal_cols, root_domain_cols, new_grouping=False)

    print("=> Starting with SHA New")
    sha256logic(WORKSPACE_DIR, hosts_cols, is_equal_cols, md5_domain_cols, new_grouping=True)

    print("=> Starting with SHA Old")
    sha256logic(WORKSPACE_DIR, hosts_cols, is_equal_cols, md5_domain_cols, new_grouping=False)

    print("== Finished ==")

    return


if __name__ == "__main__":
    main()
