# To add a new cell, type '#%%'
# To add a new markdown cell, type '#%% [markdown]'
#%% Change working directory from the workspace root to the ipynb file location. Turn this addition off with the DataScience.changeDirOnImportExport setting
# ms-python.python added
import os
try:
	os.chdir(os.path.join(os.getcwd(), 'authenticated_ciphers/FoM'))
	print(os.getcwd())
except:
	pass
#%% [markdown]
# # License
# University of Luxembourg
# Laboratory of Algorithmics, Cryptology and Security (LACS)
# 
# FELICS - Fair Evaluation of Lightweight Cryptographic Systems
# 
# Copyright (C) 2015-2019 University of Luxembourg
# 
# Author: Luan Cardoso (2019)
# 
# This file is part of FELICS.
# 
# FELICS is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
# 
# FELICS is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.
#%% [markdown]
# # Figure of Merit
# 
# Script for generating the "Figure of Metric" report for FELICS AEAD module.
# 
# ## The metric
# 
# To aid in the classifications of the evaluated ciphers, FELICS introduces the _Figure-of-Metric_ (FOM), that can be used to rank the analyzed ciphers. For each implementation $i$ and platform $d$, a performance indicator $p_{i_d}$ that aggregates the metrics from $M = \{$ execution time, RAM consumption, code size $\}$ as
#     $$
#         p_{i,d} = \sum_{m \in M}    w_m \frac{v_{i,d,m}}{\min_i(v_{i,d,m})}
#     $$
#     where $v_{i,d,m}$ is the value of the metric $m$ for the implementation $i$ on the platform $p$; and $w_m$ is the relative weight for the metric $m$, with $w_m = 1$ by default for all platforms.
#     Then, for each cipher and the selected set of best implementations $i_{AVR}$, $i_{MSP}$, and $i_{ARM}$ (one for each platform) the FOM is calculated as the average performance indicator across the three platforms:
#     $$
#         \text{FOM}(i_{AVR}, i_{MSP}, i_{ARM}) = \frac{p_{i_{AVR}}, p_{i_{MSP}}, p_{i_{ARM}}}{3}
#     $$
#     

#%%
#imports
from pandas import read_csv
import pandas as pd
from glob import glob
from pprint import pprint
import os
#for pretty stuff
from IPython.display import display

pd.set_option('display.max_columns', None)  # or 1000
pd.set_option('display.max_rows', None)  # or 1000

#%% [markdown]
# ## get the name of the ciphers from  the info file
# Look for the file info.csv, and return a list with the names of the ciphers in there.

#%%
def getCipherNames(path='../results'):
    try:
        dataFrame=read_csv(path+'/info.csv')
    except FileNotFoundError as error:
        print(error)
        raise NameError('MissingInfoFile')
        
    ciphers = set(dataFrame['Cipher'])

    return list(ciphers)


#%%
#display(getCipherNames())
#display(read_csv('../results/info.csv'))

#%% [markdown]
# ## Load Scenarios
#         
# This function should receive a number, and a path, and return a list with the results for the 3 architectures as dataframes.

#%%
def loadScenarios(scenario, path='../results', ignoreIdentityCipher=True):
    assert (type(scenario) == int) and (scenario >= 0)
    
    try:
        ARM = read_csv(path + '/ARM_scenario' + str(scenario) + '.csv', skiprows=2)
        AVR = read_csv(path + '/AVR_scenario' + str(scenario) + '.csv', skiprows=2)
        MSP = read_csv(path + '/MSP_scenario' + str(scenario) + '.csv', skiprows=2)
    except FileNotFoundError as error:
        print(error)
        raise NameError('MissingScenarioFile')
    
    if ignoreIdentityCipher:
        ARM = ARM[ARM['Cipher'] != 'IdentityCipher']
        AVR = AVR[AVR['Cipher'] != 'IdentityCipher']
        MSP = MSP[MSP['Cipher'] != 'IdentityCipher']
    return {'AVR':AVR, 'MSP':MSP, 'ARM':ARM}

#%% [markdown]
# ## Find out how many scenarios there are
# 
# Use glob to get a good enough list of scenarios on the folder

#%%
def getScenarios(path='../results'):
    files = glob(path+'/*scenario*.csv') #Only CSV files matter for this script.
    scenarios = [file[-5] for file in files]
    return(sorted(set(scenarios)))

print(getScenarios())

#%% [markdown]
# ## Calculate FOM of a single scenario.
# 

#%%
def mergeArchScenarios(sc):
    '''
    Merge dataframes for a single scenario, filtering unecessary data, renaming collums, and calculating FoM
    sc is a dictionary with the dataframes of a given scenario on the three platforms. 
        indexes are 'AVR', 'ARM', 'MSP'
    '''
    #filter the collums and rename
    cols=['Cipher', 'Block Size (bits)', 'Key Size (bits)',  'Nonce Size (bits)',
        'State Size (bits)', 'Tag Size (bits)', 'Version', 'Options',
        'Total (bytes)', 'Total (bytes).1', 'totalExec', 'pid']
    
    AVR = sc['AVR'].filter(items = cols)
    AVR = AVR.rename(index=str, columns={'Total (bytes)':'AVR Code', 'Total (bytes).1':'AVR RAM',
                                         'totalExec':'AVR Time', 'pid':'AVR pid'})
    
    MSP = sc['MSP'].filter(items = cols)
    MSP = MSP.rename(index=str, columns={'Total (bytes)':'MSP Code', 'Total (bytes).1':'MSP RAM',
                                         'totalExec':'MSP Time', 'pid':'MSP pid'})
    
    ARM = sc['ARM'].filter(items = cols)
    ARM = ARM.rename(index=str, columns={'Total (bytes)':'ARM Code', 'Total (bytes).1':'ARM RAM',
                                     'totalExec':'ARM Time', 'pid':'ARM pid'})
    
    #results = pd.concat([AVR, MSP, ARM], axis=1) #Todo: improve here change for merge
    keys=['Cipher', 'Block Size (bits)', 'Key Size (bits)', 'Nonce Size (bits)', 'State Size (bits)',
          'Tag Size (bits)','Version', 'Options']
    results = pd.merge(AVR, MSP, how='outer', on=keys)
    results = pd.merge(results, ARM, how='outer', on=keys)
    #Calculate FOM
    results = results.assign(FoM = lambda x: (x['AVR pid'] + x['MSP pid'] + x['ARM pid']) / 3)
    #filter out pid
    results = results.drop(['AVR pid', 'MSP pid', 'ARM pid', 'Version', 'Options'], axis=1)
    
    #display(results)
    
    return results

def FoM(scenario=1, path='../results', eW=1, rW=1, cW=1):
    '''
        eW = weight for Execution time
        rW = weight for Ram Consuption
        cW = weight for Code size
    '''
    if (type(scenario) == str): scenario = int(scenario)
        
    sc = loadScenarios(scenario, path)
    ciphers = getCipherNames(path)
    for plat in ['AVR', 'MSP', 'ARM']:
        #There needs a new colum, with the total execution time, since this data is not
        #generated by default by felics.
        sc[plat] = sc[plat].assign(totalExec = lambda x: x['Initialize (cycles)']+
                                    x['PAD (cycles)']+x['PPD (cycles)']+x['Finalize (cycles)']+
                                    x['TG (cycles)']+x['PCD (cycles)']+x['TV (cycles)'])
        
        #get the smallest values in the columns
        minCode = sc[plat].min()['Total (bytes)']
        minRam = sc[plat].min()['Total (bytes).1']
        minExec = sc[plat].min()['totalExec']
        
        #calculate the pid for each
        sc[plat] = sc[plat].assign(pid = lambda x: ((x['Total (bytes)'] / minCode) * cW) + 
                                   ((x['Total (bytes).1'] / minRam) * rW) + 
                                   ((x['totalExec'] / minExec) * eW))
        #print('\n', plat)
        #display(sc[plat])
        
    
    #Create dataFrame with the results for each platform:
    #Cipher; Block Size (bits); Key Size (bits); Nonce Size (bits); State Size (bits); Tag Size (bits)
    # AVRCode, AVRRam, AVRTime, AVRpid
    # MSPCode, MSPRam, MSPTime, MSPpid
    # ARMCode, ARMRam, ARMTime, ARMpid
    # FOM (calculated from PID)
    
    result = mergeArchScenarios(sc)
    return result

#%% [markdown]
# ### resumeFOM
# Given a FOM dataframe, from `FoM()`, return a resumed dataframe, with only the best of each implementation listed.
# 

#%%
def resumeFoM(fom, sortby='FoM'):
    #get ciphers by name
    ciphers = list(set(fom['Cipher']))
    
    #initialize empty dataframe with same columns
    best = pd.DataFrame(columns=list(fom))
    
    #get the best instance for each cipher
    for cipher in ciphers:
        df = fom[fom['Cipher'] == cipher]
        best = best.append(df.loc[df['FoM'].idxmin()])
    
    return (best.sort_values(sortby))

#%% [markdown]
# # Automagically generate the FOM tables for all the Scenarios
# Then, save those to all the necessary formats
# 
# 

#%%
def latexFix(scenario, sf='', resize=True):
    caption = """Results for Scenario %s. For each plataform and each cipher, the               best implementation results are reported. The smaller the Figure-              of-metric, the better is the implementation of a cipher.  Time is               reported in Cycles, Code size and RAM usage are reported in bytes.               The cipher parameters are reported in bits, where $B$ is block size,               $K$ is key size, $N$ is nonce size, $S$ is the state size, and $T$ is the tag size."""%(scenario)
    with open('FoM_Scenario_'+scenario+sf+'.tex', 'r') as file: tex = file.readlines()
    
    with open('FoM_Scenario_'+scenario+sf+'.tex', 'w') as file:
        file.write('% Please add the following required packages to your document preamble:\n')
        file.write('% \\usepackage{booktabs}\n')
        file.write('% \\usepackage{multirow}\n')
        if resize: file.write('% \\usepackage{graphicx}\n')
        file.write('% This table is automatically generated. Do not edit! \n\n')
        file.write('\\begin{table}[htb]\n')
        file.write('\\caption{%s} \n'%(caption))
        file.write('\\label{%s} \n'%('tab:FoM:Sc'+scenario+sf))
        if resize: file.write('\\resizebox{\\textwidth}{!}{% \n')
        file.write('\\begin{tabular}{@{}cccccc|ccc|ccc|ccc|c@{}} \n')
        file.write('\\toprule \n')
        file.write(' \\multicolumn{6}{c|}{\\textbf{Cipher}} & \\multicolumn{3}{c|}{\\textbf{AVR}} & \\multicolumn{3}{c|}{\\textbf{MSP}} & \\multicolumn{3}{c|}{\\textbf{ARM}} & \\multirow{2}{*}{\\textbf{FOM}} \\\\ \n')
        file.write('& $B$ & $K$ & $N$ & $S$ & $T$ & \\begin{tabular}[c]{@{}c@{}}Code\\\\ (B)\\end{tabular} & \\begin{tabular}[c]{@{}c@{}}RAM\\\\ (B)\\end{tabular} & \\begin{tabular}[c]{@{}c@{}}Time\\\\ (cyc.)\\end{tabular} & \\begin{tabular}[c]{@{}c@{}}Code\\\\ (B)\\end{tabular} & \\begin{tabular}[c]{@{}c@{}}RAM\\\\ (B)\\end{tabular} & \\begin{tabular}[c]{@{}c@{}}Time\\\\ (cyc.)\\end{tabular} & \\begin{tabular}[c]{@{}c@{}}Code\\\\ (B)\\end{tabular} & \\begin{tabular}[c]{@{}c@{}}RAM\\\\ (B)\\end{tabular} & \\begin{tabular}[c]{@{}c@{}}Time\\\\ (cyc.)\\end{tabular} &  \\\\ \n')
        file.write('\\midrule \n')
        
        for line in tex[4:-2]: 
            tmp = line.split('&', 1)
            tmp[0]= '\\multicolumn{1}{l}{' + tmp[0].strip() + '} & '
            #print(''.join(tmp)+'\n')
            file.write(''.join(tmp)+'\n')
        
        file.write('\\bottomrule \n')
        file.write('\\end{tabular} %\n')
        if resize: file.write('} \n')
        file.write('\\end{table} \n')


#%%
def saveMediaWiki(fom, fName, scenario, index=False):
    header = """=Scenario %s=
A description of scenario %s can be found [[FELICS_AEAD|here]].

{| class="wikitable sortable" style="margin: auto;"
|+ Results for scenario %s. For each cipher, an optimal implementation on each architecture is selected. 
|-
! scope="col" colspan="6" rowspan="2"| Cipher info
! scope="col" colspan="9" rowspan="1"| Results
! scope="col" colspan="1" rowspan="3"| FOM
|-
! scope="col" colspan="3" style="text-align: center;" | AVR
! scope="col" colspan="3" style="text-align: center;" | MSP
! scope="col" colspan="3" style="text-align: center;" | ARM
|-
! scope="col" style="text-align: center;" | Cipher
! scope="col" style="text-align: center;" | B
! scope="col" style="text-align: center;" | K
! scope="col" style="text-align: center;" | N
! scope="col" style="text-align: center;" | S
! scope="col" style="text-align: center;" | T
! scope="col" style="text-align: center;" | Code
(B)
! scope="col" style="text-align: center;" | RAM
(B)
! scope="col" style="text-align: center;" | Time
(cyc.)
! scope="col" style="text-align: center;" | Code
(B)
! scope="col" style="text-align: center;" | RAM
(B)
! scope="col" style="text-align: center;" | Time
(cyc.)
! scope="col" style="text-align: center;" | Code
(B)
! scope="col" style="text-align: center;" | RAM
(B)
! scope="col" style="text-align: center;" | Time
(cyc.)"""%(scenario,scenario,scenario)
    
    csv = fom.to_csv(index=False).split('\n')
    with open(fName, 'w') as mk:
        #write header
        mk.write(header)
        
        #write table lines
        for line in csv[1:-1]:
            mk.write('\n|- \n')
            mk.write('| '+line.replace(',', '\n|'))
            
        mk.write('\n|}')


#%%
def saveFoMDataFrame(fom, scenario, sf=''):
    fom = fom.round({'FoM':1})
    fom.to_csv('FoM_Scenario_'+scenario+sf+'.csv', index=False)
    fom.to_latex('FoM_Scenario_'+scenario+sf+'.tex', index=False)
    latexFix(scenario, sf)
    with open('FoM_Scenario_'+scenario+sf+'.txt', 'w') as f:
        f.write(fom.to_string(index=False, justify='center'))
    fom.to_html('FoM_Scenario_'+scenario+sf+'.html', index=False, justify='center')
    saveMediaWiki(fom, 'FoM_Scenario_'+scenario+sf+'.mwk', scenario, index=False)
    
    
def generateFoMTables(path='../results', eW=1, rW=1, cW=1, disp=False):
    scenarios = getScenarios()
    resumedScenarios = []
    for scenario in scenarios:
        fom = FoM(scenario)
        saveFoMDataFrame(fom, scenario)
        resumed = resumeFoM(fom)
        resumedScenarios.append(resumed)
        if disp:
            print('Scenario '+scenario+':')
            display(resumed.round({'FoM':1})) #on collumn fon, round to one decimal place
        saveFoMDataFrame(resumed, scenario, '_resumed')
    return resumedScenarios


#%%
def cleanup():
    os.system('mkdir -p FoM') #Create new folder, but does not err if folder already exists.
    os.system('mv FoM_Scenario_* FoM/')


#%% [markdown]
# These following functions are used to merge the scenarios for IPv6 and WLoPAN into an
# even more resumed table. Usefull for articles where the space is limited.

#%%
#TODO: Continue coding from here
def mergeTables(resumedScenarios):
    ''' Merge the IPv6 and WLOPAN scenarios into a single table, then save outputs'''
    #Merge scenarios 123
    print(resumedScenarios[1])
    #Merge scenarios 456


checkMergeTables = True

try:
    resumedScenarios = generateFoMTables(disp=False)
    if checkMergeTables: mergeTables(resumedScenarios)
except:
    print("Unexpected error:", sys.exc_info()[0])
finally:
    cleanup()


#%%



