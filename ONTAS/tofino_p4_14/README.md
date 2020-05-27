# ONTAS: Flexible and Scalable Online Network Traffic Anonymization System
This is the ONTAS source code for Tofino. It is implemented with P4-14. 

## Use Python3 script to create table entries (simple_switch_CLI style)
- Install requests package: `$ pip3 install requests`
- Generates rule lines: `$ python3 policy_parser.py -c example_config.txt -o ./table_rules.txt`
