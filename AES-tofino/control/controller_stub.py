import sys
import os
sys.path.append(os.path.expandvars('$SDE/install/lib/python2.7/site-packages/tofino/'))

from bfrt_grpc import client

GRPC_CLIENT=client.ClientInterface(grpc_addr="localhost:50052", client_id=0,device_id=0, is_master=True)
bfrt_info=GRPC_CLIENT.bfrt_info_get(p4_name=None)
GRPC_CLIENT.bind_pipeline_config(p4_name=bfrt_info.p4_name)

def table_add(table_name, match_key_names_list, match_key_values_list, action_name, action_data_names_list, action_data_values_list):
    # simply a wrapper
    t=bfrt_info.table_dict[table_name]
    
    def table_add_gen_kd(table_name, match_key_names_list, match_key_values_list, action_name, action_data_names_list, action_data_values_list):
        # prepare to add a single match-action table rule
        t=bfrt_info.table_dict[table_name]

        # prepare KeyTuple
        KeyTuple_list=[]
        for keyName, keyValue in zip(match_key_names_list,match_key_values_list):
            KeyTuple_list.append(client.KeyTuple(name=keyName, value=keyValue))
        tKey=t.make_key(KeyTuple_list)

        DataTuple_List=[]
        for dataName, dataValue in zip(action_data_names_list,action_data_values_list):
            DataTuple_List.append(client.DataTuple(name=dataName,val=dataValue))
        tData=t.make_data(DataTuple_List, action_name=action_name)
        return tKey, tData
    
    tKey,tData=table_add_gen_kd(table_name, match_key_names_list, match_key_values_list, action_name, action_data_names_list, action_data_values_list)
    
    return t.entry_add(target=client.Target(), key_list=[tKey], data_list=[tData])
    
def reset():
    GRPC_CLIENT.clear_all_tables()

def close():
    GRPC_CLIENT.__del__()