from scapy.all import rdpcap
import numpy as np
from sampling_task import to_src_dst, packets

# import the dataset, may take a few minutes
#packets = rdpcap('../botnet-capture-20110810-neris.pcap')

def hash_elem(hash_fns, elem):
    return list(map(lambda h: h(elem), hash_fns))

def cm_add(cd_table, hash_fns, elem):
    ''' Adds an element to the Count-Min table. '''
    helem = hash_elem(hash_fns, elem)
    for i in range(np.shape(cd_table)[0]):
        cd_table[i, helem[i]] = cd_table[i, helem[i]] + 1

    return cd_table

def cm_add_all(cd_table, hash_fns, elems):
    ''' Adds a list of elements to the Count-Min table. '''

    for e in elems:
        cd_table = cm_add(cd_table, hash_fns, e)

    return cd_table

def cm_count(cd_table, hash_fns, elem):
    ''' Counts the occurrence of the elem in the Count-Min table. '''
    helem = hash_elem(hash_fns, elem)
    counts = map(lambda he, cd: cd[he], helem, cd_table)
    return min(counts)

def gen_hash_fns(height=10, width=50):
    ''' Generates a list of hash functions. '''
    return list(map(lambda i: lambda elem: hash(str(i) + elem)%width, range(height)))

def gen_cd_table(height=10, width=50):
    ''' Generates the Count-Min table. '''
    return np.zeros((height, width))

src_dsts = to_src_dst(packets)

# Jaccard similarity can be computed by having the sizes of each of the sets as well as their overlap
# list of unique sources and destinations and the amount of times they appear in the dataset
unique_srcs = np.unique(src_dsts[:,0], return_counts=True)
unique_dsts = np.unique(src_dsts[:,1], return_counts=True)

# list of unique source/destination pairs and the amount of times they appear in the dataset
unique_pairs = np.unique(src_dsts, return_counts=True, axis=0)

# real stuff
srcdsts = list(map(lambda sd: ' '.join(sd), src_dsts))

hash_fns = gen_hash_fns()
cd_table = gen_cd_table()

# This contains the final table, just feed it to cm_count to get the results back
cm = cm_add_all(cd_table, hash_fns, srcdsts)
# cm_count example
count = cm_count(cm, hash_fns, '08:00:27:b5:b7:19 00:1e:49:db:19:c3')
