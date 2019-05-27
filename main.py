from DataSetsLogic import *


def root_domain_logic(workspace_dir, hosts_cols, is_equal_cols, root_domain_cols):
    l = Logic()

    hosts_ds = l.get_ds("hosts1", HostsDS, os.path.join(workspace_dir, "hosts1.json"), hosts_cols)
    hosts_ds.add_features()

    domains_ds = l.get_ds("domains1", DomainsDS, os.path.join(workspace_dir, "domains1.json"), root_domain_cols)

    pos_neg_ds = l.get_pos_neg_from_domains(domains_ds, "pos_neg1", PositiveNegativeDS,
                                            os.path.join(workspace_dir, "pos_neg1.json"), join_column="domain_fix")

    hosts_ds.save(os.path.join(workspace_dir, "hosts1.json"))
    domains_ds.save(os.path.join(workspace_dir, "domains1.json"))
    pos_neg_ds.save(os.path.join(workspace_dir, "pos_neg1.json"))

    merged_ds = l.get_merged_ds("merged", pos_neg_ds, hosts_ds, os.path.join(workspace_dir, "merged_ds1.json"))
    merged_ds.ds = merged_ds.ds[merged_ds.ds["ip1_ip1"] != merged_ds.ds["ip2_ip2"]]

    print("{} items in merged data set before transformation".format(len(merged_ds.ds)))
    # Add is_equal_... columns for feature testing
    merged_ds.transform(is_equal_cols)
    print("{} items in merged data set after transformation".format(len(merged_ds.ds)))

    merged_ds.run_cm(os.path.join(workspace_dir, "final_results1.txt"))

    # Multiple IPs (rows) will be aggregated to one row per IP. All other fields will be in lists.
    new_hosts_ds = hosts_ds.transform()

    # Get the newly merged ds after the transformation
    new_merged_ds = l.get_merged_ds("merged", pos_neg_ds, new_hosts_ds, os.path.join(workspace_dir, "merged_ds2.json"))
    new_merged_ds.ds = new_merged_ds.ds[new_merged_ds.ds["ip1_ip1"] != new_merged_ds.ds["ip2_ip2"]]

    new_merged_ds.transform(is_equal_cols)

    new_merged_ds.run_cm(os.path.join(workspace_dir, "final_results2.txt"))

    # merged_ds.save(os.path.join(workspace_dir, "merged_ds1.json"))
    # new_merged_ds.save(os.path.join(workspace_dir, "merged_ds2.json"))


def sha256logic(workspace_dir, hosts_cols, is_equal_cols, md5_domain_cols):
    l = Logic()

    hosts_ds = l.get_ds("hosts2", HostsDS, os.path.join(workspace_dir, "hosts2.json"), hosts_cols)
    hosts_ds.add_features()

    domains_ds = DomainsDS(md5_domain_cols)
    domains_ds.SetSha256()
    domains_ds = l.get_ds_by_instance("domains2", domains_ds, os.path.join(workspace_dir, "domains2.json"))

    pos_neg_ds = l.get_pos_neg_from_domains(domains_ds, "pos_neg2", PositiveNegativeDS,
                                            os.path.join(workspace_dir, "pos_neg2.json"), join_column="sha256")

    hosts_ds.save(os.path.join(workspace_dir, "hosts2.json"))
    domains_ds.save(os.path.join(workspace_dir, "domains2.json"))
    pos_neg_ds.save(os.path.join(workspace_dir, "pos_neg2.json"))

    merged_ds1 = l.get_merged_ds("merged", pos_neg_ds, hosts_ds, os.path.join(workspace_dir, "merged_ds3.json"))
    merged_ds1.ds = merged_ds1.ds[merged_ds1.ds["ip1_ip1"] != merged_ds1.ds["ip2_ip2"]]

    print("{} items in merged data set before transformation".format(len(merged_ds1.ds)))
    # Add is_equal_... columns for feature testing
    merged_ds1.transform(is_equal_cols)
    print("{} items in merged data set after transformation".format(len(merged_ds1.ds)))

    merged_ds1.run_cm(os.path.join(workspace_dir, "final_results3.txt"))

    # Multiple IPs (rows) will be aggregated to one row per IP. All other fields will be in lists.
    new_hosts_ds1 = hosts_ds.transform()

    # Get the newly merged ds after the transformation
    new_merged_ds1 = l.get_merged_ds("merged", pos_neg_ds, new_hosts_ds1,
                                     os.path.join(workspace_dir, "merged_ds4.json"))
    new_merged_ds1.ds = new_merged_ds1.ds[new_merged_ds1.ds["ip1_ip1"] != new_merged_ds1.ds["ip2_ip2"]]

    new_merged_ds1.transform(is_equal_cols)

    new_merged_ds1.run_cm(os.path.join(workspace_dir, "final_results4.txt"))

    # merged_ds.save(os.path.join(workspace_dir, "merged_ds3.json"))
    # new_merged_ds.save(os.path.join(workspace_dir, "merged_ds4.json"))


def main():
    WORKSPACE_DIR = "hostsimilarity_results"

    hosts_cols = ['asn', 'domains', 'product', 'ip', 'ip_str', 'http.html_hash', 'location.country_name',
         'location.latitude', 'location.longitude', 'org', 'os', 'port', 'opts.vulns', 'info', 'cpe', 'transport',
         'isp', 'version', 'hostnames', 'http.redirects', 'http.html',
         'ssl.cert.fingerprint.sha256', 'ssl.cert.serial', 'ssl.chain', 'ssl.dhparams.public_key', 'ssl.cert.expires']

    is_equal_cols = ["common_port", "not_wellknown_port", "not_registered_port", "common_port_transport",
                     "not_wellknown_port_transport",  "not_registered_port_transport", "port_product_version",
                     "port_product", "os", "version", "product", "asn", "org",
                     "http.html_hash", "location.country_name", "port", "cpe", 'isp',
                     'transport', "info", "opts.vulns", 'ssl.cert.fingerprint.sha256',
                     'ssl.cert.serial', 'ssl.chain', 'ssl.dhparams.public_key',
                     'ssl.cert.expires']

    root_domain_cols = ["domain_fix", "response"]

    md5_domain_cols = ["sha256", "domain_fix", "response"]

    if not os.path.exists(WORKSPACE_DIR):
        os.mkdir(WORKSPACE_DIR, 777)

    root_domain_logic(WORKSPACE_DIR, hosts_cols, is_equal_cols, root_domain_cols)

    sha256logic(WORKSPACE_DIR, hosts_cols, is_equal_cols, md5_domain_cols)

    print("== Finished ==")

if __name__ == "__main__":
    main()
