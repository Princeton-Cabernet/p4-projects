import sys
from toolbox import *

    
if len(sys.argv)<2 or parse_key(sys.argv[1])==None:
    sys.stderr.write("Install AES-128 key into Scrambled Lookup Tables in the P4 data plane program.")
    sys.stderr.write("Usage: python %s AES_KEY_HEX \n"%sys.argv[0])
    sys.stderr.write("Example: python %s 0x10002000300040005000600070008000 \n"%sys.argv[0])
    sys.exit(-1)
    
import controller_stub
if controller_stub.bfrt_info.p4_name!='aes_oneround':
    sys.stderr.write("P4 program mismatch: driver reports currently running '%s' \n"% controller_stub.bfrt_info.p4_name)
    controller_stub.close()
    sys.exit(-1)
        
key=parse_key(sys.argv[1])

expanded_key=expand_key(key)

LUTs,FinalXORvect=generate_LUT(expanded_key)

def add_everything():
    table_add=controller_stub.table_add

    sys.stderr.write("#** Using key = %s \n"%(hex(key)))
    sys.stderr.write("#** Installing recirculation rules... \n")
    #recirc table
    for rndNum in range(1,10):
        curr_round=rndNum-1
        table_add(table_name='SwitchIngress.tb_recirc_decision', match_key_names_list=['hdr.aes_meta.curr_round'], match_key_values_list=[curr_round], action_name='incr_and_recirc', action_data_names_list=['next_round'], action_data_values_list=[curr_round+1]) 

    last_round=9
    fields_list=['s%d%d' %(i,j) for i in range(4) for j in range(4)]
    values_list=[FinalXORvect[i][j] for i in range(4) for j in range(4)]

    table_add(table_name='SwitchIngress.tb_recirc_decision', match_key_names_list=['hdr.aes_meta.curr_round'], match_key_values_list=[last_round], action_name='do_not_recirc_final_xor', action_data_names_list=fields_list, action_data_values_list=values_list)

    sys.stderr.write("#** Installing lookup table rules... \n")

    for rndNum in range(1,10+1):
        curr_round=rndNum-1    
        luts=LUTs[rndNum]
        def printRules(lutR,lutC,  inputR, inputC):
            r,c=inputR, inputC
            tname="SwitchIngress.tb_lookup_%d_%d_t"%(r,c)
            aname="write_v_%d_%d_a"%(r,c)
            kname="hdr.aes.s%d%d"%(r,c)

            LUT=luts[lutR][lutC]
            for s_match,v_val in LUT.dump():
                table_add(table_name=tname, match_key_names_list=[kname,'hdr.aes_meta.curr_round'], match_key_values_list=[s_match,curr_round], action_name=aname, action_data_names_list=['v'], action_data_values_list=[v_val])

        #nvect0
        printRules(0,0  ,  0,0)
        printRules(0,1  ,  1,1)
        printRules(0,2  ,  2,2)
        printRules(0,3  ,  3,3)
        #nvect1
        printRules(1,0  ,  1,0)
        printRules(1,1  ,  2,1)
        printRules(1,2  ,  3,2)
        printRules(1,3  ,  0,3)
        #nvect2
        printRules(2,0  ,  2,0)
        printRules(2,1  ,  3,1)
        printRules(2,2  ,  0,2)
        printRules(2,3  ,  1,3)
        #nvect3
        printRules(3,0  ,  3,0)
        printRules(3,1  ,  0,1)
        printRules(3,2  ,  1,2)
        printRules(3,3  ,  2,3)


    sys.stderr.write("#** Done! \n")
    
try:
    add_everything()
except:
    raise
finally:
    controller_stub.close()