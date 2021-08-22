# DNS Analysis Scripts

1. Create CSV files: `dns_map_qname_to_ip_*.sh`
  * Input: pcap file or directory where pcap_fiels are 
  * Output: csv file: (epoch, hostname, ipaddress_list)
  * `$ bash dns_map_qname_to_ip_directory.sh ~/mnt/anonflow/dns/capture_04142021T0000/ dns.csv`
1. Using CSV file, create dictionary: `qname_ip_map.py`
  * Input: csv file from above
  * Output: pickled dictionary of { ip : (set_of_names, set_of_epochs) }
  * `$ python3 qname_ip_map.py -i dns.csv -o ip_qname_map`
1. Augment dictionary with SSL.
  * `$ bash get_hostname_from_sslhandshake.sh <directory_where_pcap_files_is> <output_name>`
  * `$ python3 ip_to_qname_csv_augment.py -i ip_qname_map.p -o augment_ip_qname_map`
1. `ip_to_qname_csv_analysis.py`
  * Input: tshark csv files, above pickled dictionary
  * Output: Count bytes and number of packets per hostname.
  * `$ python3 ip_to_qname_csv_augment.py -i ip_qname_map.p -o augment_ip_qname_map`
