import os
import json
import sys
import operator
import re
tools = ['slither']
root = os.path.realpath(os.path.join(os.path.dirname(__file__),''))
contracts_data={}
# vulnerabilities_mapping_mythril={
#     'Unprotected Selfdestruct':"access_control",
#     'External Call To User-Supplied Address':"reentrancy",
#     'Unprotected Ether Withdrawal':"access_control",
#     'Dependence on predictable environment variable':"Other",
#     'Delegatecall to user-supplied address':"access_control",
#     'Multiple Calls in a Single Transaction':'Ignore',
#     'State access after external call':"reentrancy",
#     'Write to an arbitrary storage location':"Other",
#     'Unchecked return value from external call.':"unchecked_low_level_calls",
#     'Integer Arithmetic Bugs':"arithmetic",
#     'Dependence on tx.origin':"access_control",
#     'Exception State':"Other"
# }
vulnerabilities_mapping_slither={
   'tx-origin': "access_control",
   'low-level-calls':'unchecked_low_calls',
   'unused-state':"Ignore",
   'naming-convention':"Ignore",
   'arbitrary-send':"access_control",
   'reentrancy-eth':"reentrancy",
   'incorrect-equality':"Other",
   'constant-function':"Ignore",
   'uninitialized-state':"Other",
   'uninitialized-local':"Other",
   'erc20-interface':"Ignore",
   'shadowing-local':"Ignore",
   'locked-ether':"Other",
   'reentrancy-benign':"reentrancy",
   'external-function':"Ignore",
   'solc-version':"Ignore",
   'assembly':"Ignore",
   'controlled-delegatecall':"access_control",
   'calls-loop':'denial_service',
   'shadowing-builtin':"Ignore",
   'timestamp':'time_manipulation',
   'unused-return':'unchecked_low_calls',
   'erc20-indexed':"Ignore",
   'constable-states':"Ignore",
   'reentrancy-no-eth':"reentrancy",
   'uninitialized-storage':"Other",
   'suicidal':"access_control",
   'shadowing-state':"Ignore",
   'deprecated-standards':"Other"
}

with open(os.path.join(root,'vulnerabilities.json')) as fd:
    data = json.load(fd)
    for file in data:
        contracts_data[file['name'].replace('.sol', '')] = file
count_vulnerabilities = {}
for contract in contracts_data:
    for vuln in contracts_data[contract]['vulnerabilities']:
        if 'denial_of_service' == vuln['category']:
            vuln['category'] = 'denial_service'
        elif 'unchecked_low_level_calls' == vuln['category']:
            vuln['category'] = 'unchecked_low_calls'
        elif 'other' == vuln['category']:
            vuln['category'] = 'Other'
        if vuln['category'] not in count_vulnerabilities:
            count_vulnerabilities[vuln['category']] = 0
        count_vulnerabilities[vuln['category']] += 1
# categories = sorted(list(set(vulnerabilities_mapping_mythril.values())))
# categories.remove('Ignore')
vulnerabilities=set()
correct={}
actual={}
for tool in tools:
    path_tool_result = os.path.abspath(os.path.join(root,'results',tool))
    for contract in os.listdir(path_tool_result):
        path_contract = os.path.join(path_tool_result, contract)
        path_result = os.path.join(path_contract, 'result.json')
        if not os.path.isdir(path_contract):
            continue
        if not os.path.exists(path_result):
            continue
        with open(path_result, 'r', encoding='utf-8') as fd:
            data = None
            try:
                data = json.load(fd)
            except Exception as a:
                continue
            if data['findings'] is None:
                continue
            for finding in data['findings']:
                if finding is None:
                    continue
                if not 'line' in finding:
                    continue
                line=finding['line']
                vulncat=finding['name'].strip().split(' (')[0]
                vulnerabilities.add(vulncat)
                # if tool=='mythril':
                #     vulnerabilities_mapping=vulnerabilities_mapping_mythril
                # else:
                #     vulnerabilities_mapping=vulnerabilities_mapping_slither

                # for vuln in contracts_data[contract.split('.sol')[0]]['vulnerabilities']:
                #     if vuln['lines'][0]==line and vuln['category']==vulnerabilities_mapping[vulncat]:
                #         if vulnerabilities_mapping[vulncat] not in correct:
                #             correct[vulnerabilities_mapping[vulncat]]=1
                #         else:
                #             correct[vulnerabilities_mapping[vulncat]]+=1

# for contract in contracts_data:
#     for vuln in contracts_data[contract]['vulnerabilities']:
#         if vuln['category'] not in actual:
#             actual[vuln['category']]=1
#         else:
#             actual[vuln['category']]+=1
# print(correct)
# print(actual)
# print(correct/sum(actual.values()))
print(vulnerabilities)
print(len(vulnerabilities))











