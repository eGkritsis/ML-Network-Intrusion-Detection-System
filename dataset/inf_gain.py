import pandas as pd
from sklearn.feature_selection import mutual_info_classif, SelectKBest
from sklearn.preprocessing import OrdinalEncoder

# Load the training and test datasets
train_set = pd.read_csv(r'D:\AUEB\Projects\Network-Traffic-Analyzer\dataset\UNSW_NB15_training-set.csv')
test_set = pd.read_csv(r'D:\AUEB\Projects\Network-Traffic-Analyzer\dataset\UNSW_NB15_testing-set.csv')

# Drop the "id" and "label" column from the training dataset
train_set = train_set.drop(["id", "label"], axis=1)

# Drop the "id" and "label" column from the test dataset
test_set = test_set.drop(["id", "label"], axis=1)

# Combine the training and test sets for ordinal encoding
combined_set = pd.concat([train_set, test_set], axis=0)

# Apply ordinal encoding to categorical features
ordinal_encoder = OrdinalEncoder()
categorical_features = ['proto', 'service', 'state']

# Create a mapping dictionary for inverse transformation
mapping_dict = {}

for feature in categorical_features:
    # Fit ordinal encoder on combined training and test sets
    ordinal_encoder.fit(combined_set[[feature]])
    
    # Transform training set using the fitted ordinal encoder
    train_set[feature] = ordinal_encoder.transform(train_set[[feature]])
    
    # Transform test set using the fitted ordinal encoder
    test_set[feature] = ordinal_encoder.transform(test_set[[feature]])
    
    # Create a mapping dictionary for inverse transformation
    mapping_dict[feature] = dict(zip(ordinal_encoder.transform(combined_set[[feature]]).flatten(), combined_set[feature]))

# Separate features and labels
x_train = train_set.drop("attack_cat", axis=1) # Drop the label column from the training dataset
y_train = train_set["attack_cat"] # Target variable for training the data 

x_test = test_set.drop("attack_cat", axis=1) 
y_test = test_set["attack_cat"]

# Calculate the information gain for each feature
info_gain = mutual_info_classif(x_train, y_train)

# Create a DataFrame to store the feature names and their information gain
feature_info_gain = pd.DataFrame({'Feature': x_train.columns, 'Information Gain': info_gain})

# Sort the DataFrame in descending order of information gain
feature_info_gain = feature_info_gain.sort_values(by='Information Gain', ascending=False)

# Print the feature names and their corresponding information gain
with pd.option_context('display.max_rows', None, 'display.max_columns', None):
    print(feature_info_gain)

'''  
 -- LABEL --

Feature  Information Gain
3               sbytes          0.459995
23               smean          0.354998
8                sload          0.345505
4               dbytes          0.291660
28        ct_state_ttl          0.278727
5                 rate          0.262955
0                  dur          0.253860
24               dmean          0.251902
7                 dttl          0.245329
13              dinpkt          0.237544
6                 sttl          0.220926
9                dload          0.214759
2                dpkts          0.207370
21              synack          0.206337
20              tcprtt          0.205593
12              sinpkt          0.199559
31    ct_dst_sport_ltm          0.186098
22              ackdat          0.185368
187          state_INT          0.164540
14                sjit          0.162365
1                spkts          0.153224
15                djit          0.147013
30    ct_src_dport_ltm          0.119063
11               dloss          0.117364
10               sloss          0.116123
37          ct_srv_dst          0.114991
150          proto_tcp          0.098697
16                swin          0.096383
27          ct_srv_src          0.093887
17               stcpb          0.093347
18               dtcpb          0.082511
172        service_dns          0.077994
19                dwin          0.074920
32      ct_dst_src_ltm          0.065825
29          ct_dst_ltm          0.059295
170          service_-          0.058340
36          ct_src_ltm          0.057370
186          state_FIN          0.055018
185          state_CON          0.053219
26   response_body_len          0.041760
156          proto_udp          0.040482
157         proto_unas          0.027230
188          state_REQ          0.012199
38     is_sm_ips_ports          0.009106
45           proto_arp          0.007800
35    ct_flw_http_mthd          0.007201
121      proto_pri-enc          0.005462
115          proto_nvp          0.003654
66       proto_etherip          0.003601
127          proto_rdp          0.003471
125          proto_pvp          0.003450
41     proto_aes-sp3-d          0.003357
183          state_ACC          0.003249
89          proto_ippc          0.003215
113       proto_netblt          0.003151
78          proto_idrp          0.003145
165          proto_wsn          0.003117
53   proto_compaq-peer          0.003102
160         proto_visa          0.003052
46         proto_ax.25          0.002950
116         proto_ospf          0.002937
50           proto_cbt          0.002911
114   proto_nsfnet-igp          0.002900
126          proto_qnx          0.002768
58           proto_dcn          0.002756
145          proto_st2          0.002749
88         proto_ipnip          0.002631
177       service_pop3          0.002573
153      proto_trunk-1          0.002568
72           proto_hmp          0.002545
129          proto_rvd          0.002423
74          proto_iatp          0.002396
77     proto_idpr-cmtp          0.002391
82            proto_il          0.002310
144          proto_srp          0.002276
92       proto_ipv6-no          0.002229
141          proto_snp          0.002216
79          proto_ifmp          0.002208
49    proto_br-sat-mon          0.002193
34          ct_ftp_cmd          0.002163
61           proto_dgp          0.002148
98        proto_iso-ip          0.002018
124          proto_pup          0.002007
140          proto_smp          0.002005
56          proto_crtp          0.001976
63         proto_eigrp          0.001959
118          proto_pim          0.001874
154      proto_trunk-2          0.001737
83            proto_ip          0.001640
39           proto_3pc          0.001574
181        service_ssh          0.001509
109       proto_mobile          0.001497
164       proto_wb-mon          0.001477
40           proto_a/n          0.001472
175       service_http          0.001468
174   service_ftp-data          0.001438
70          proto_gmtp          0.001382
134         proto_sctp          0.001364
103       proto_leaf-1          0.001349
86          proto_ipip          0.001348
43         proto_argus          0.001340
171       service_dhcp          0.001322
173        service_ftp          0.001313
162         proto_vrrp          0.001227
128         proto_rsvp          0.001204
161         proto_vmtp          0.001159
71           proto_gre          0.001115
146          proto_stp          0.000995
52         proto_chaos          0.000905
182        service_ssl          0.000890
169         proto_zero          0.000873
65         proto_encap          0.000861
179       service_smtp          0.000831
75            proto_ib          0.000773
135         proto_sdrp          0.000762
155          proto_ttp          0.000757
142   proto_sprite-rpc          0.000693
166         proto_xnet          0.000674
111          proto_mux          0.000589
137          proto_sep          0.000564
57         proto_crudp          0.000538
108         proto_micp          0.000520
133         proto_scps          0.000500
42           proto_any          0.000344
107         proto_mhrp          0.000318
105    proto_merit-inp          0.000310
147       proto_sun-nd          0.000285
189          state_RST          0.000283
149          proto_tcf          0.000267
62           proto_egp          0.000206
90          proto_ipv6          0.000116
122          proto_prm          0.000058
159        proto_vines          0.000055
176        service_irc          0.000015
68          proto_fire          0.000000
84        proto_ipcomp          0.000000
25         trans_depth          0.000000
163     proto_wb-expak          0.000000
81           proto_igp          0.000000
80          proto_igmp          0.000000
76          proto_idpr          0.000000
167      proto_xns-idp          0.000000
168          proto_xtp          0.000000
73        proto_i-nlsp          0.000000
33        is_ftp_login          0.000000
69           proto_ggp          0.000000
44          proto_aris          0.000000
47       proto_bbn-rcc          0.000000
64         proto_emcon          0.000000
85          proto_ipcv          0.000000
60           proto_ddx          0.000000
59           proto_ddp          0.000000
178     service_radius          0.000000
55          proto_cpnx          0.000000
180       service_snmp          0.000000
54          proto_cphb          0.000000
51          proto_cftp          0.000000
48           proto_bna          0.000000
184          state_CLO          0.000000
67            proto_fc          0.000000
123          proto_ptp          0.000000
87          proto_iplt          0.000000
104       proto_leaf-2          0.000000
130    proto_sat-expak          0.000000
131      proto_sat-mon          0.000000
132     proto_sccopmce          0.000000
120         proto_pnni          0.000000
119         proto_pipe          0.000000
117          proto_pgm          0.000000
136  proto_secure-vmtp          0.000000
112         proto_narp          0.000000
138         proto_skip          0.000000
139           proto_sm          0.000000
110          proto_mtp          0.000000
106      proto_mfe-nsp          0.000000
143          proto_sps          0.000000
158          proto_uti          0.000000
102         proto_larp          0.000000
101         proto_l2tp          0.000000
100    proto_kryptolan          0.000000
99       proto_iso-tp4          0.000000
148        proto_swipe          0.000000
97          proto_isis          0.000000
151         proto_tlsp          0.000000
152         proto_tp++          0.000000
96          proto_irtp          0.000000
94    proto_ipv6-route          0.000000
93     proto_ipv6-opts          0.000000
91     proto_ipv6-frag          0.000000
95      proto_ipx-n-ip          0.000000

'''


'''
-- ATTACK_CAT --

Feature  Information Gain
3               sbytes          0.977571
23               smean          0.815041
8                sload          0.791737
4               dbytes          0.508961
24               dmean          0.449149
31    ct_dst_sport_ltm          0.442432
5                 rate          0.441881
0                  dur          0.431237
28        ct_state_ttl          0.407612
13              dinpkt          0.397638
172        service_dns          0.397018
9                dload          0.394203
2                dpkts          0.378131
30    ct_src_dport_ltm          0.377947
37          ct_srv_dst          0.376035
12              sinpkt          0.374788
7                 dttl          0.371574
21              synack          0.349746
20              tcprtt          0.349744
27          ct_srv_src          0.341791
14                sjit          0.325542
22              ackdat          0.324457
1                spkts          0.319922
32      ct_dst_src_ltm          0.313982
15                djit          0.309188
6                 sttl          0.306086
156          proto_udp          0.297448
29          ct_dst_ltm          0.292797
187          state_INT          0.286933
11               dloss          0.286464
10               sloss          0.272572
36          ct_src_ltm          0.253494
170          service_-          0.249593
17               stcpb          0.224712
16                swin          0.222127
18               dtcpb          0.220160
150          proto_tcp          0.217935
19                dwin          0.202646
186          state_FIN          0.182656
157         proto_unas          0.061236
26   response_body_len          0.059144
185          state_CON          0.055576
175       service_http          0.034962
35    ct_flw_http_mthd          0.033646
25         trans_depth          0.029627
179       service_smtp          0.018024
188          state_REQ          0.012232
38     is_sm_ips_ports          0.012188
45           proto_arp          0.010567
174   service_ftp-data          0.009695
177       service_pop3          0.008953
34          ct_ftp_cmd          0.007996
116         proto_ospf          0.007153
173        service_ftp          0.006924
100    proto_kryptolan          0.006539
99       proto_iso-tp4          0.005193
62           proto_egp          0.005022
33        is_ftp_login          0.004750
134         proto_sctp          0.003869
43         proto_argus          0.003563
163     proto_wb-expak          0.003559
128         proto_rsvp          0.003410
54          proto_cphb          0.003386
138         proto_skip          0.003333
137          proto_sep          0.003181
111          proto_mux          0.003133
152         proto_tp++          0.002966
153      proto_trunk-1          0.002836
47       proto_bbn-rcc          0.002815
118          proto_pim          0.002787
147       proto_sun-nd          0.002493
46         proto_ax.25          0.002467
87          proto_iplt          0.002451
98        proto_iso-ip          0.002443
139           proto_sm          0.002441
158          proto_uti          0.002348
160         proto_visa          0.002321
81           proto_igp          0.002317
42           proto_any          0.002308
167      proto_xns-idp          0.002274
39           proto_3pc          0.002249
65         proto_encap          0.002237
110          proto_mtp          0.002156
82            proto_il          0.002110
140          proto_smp          0.002011
78          proto_idrp          0.002011
109       proto_mobile          0.001968
84        proto_ipcomp          0.001954
107         proto_mhrp          0.001916
97          proto_isis          0.001797
68          proto_fire          0.001726
96          proto_irtp          0.001692
66       proto_etherip          0.001673
142   proto_sprite-rpc          0.001665
161         proto_vmtp          0.001587
88         proto_ipnip          0.001563
67            proto_fc          0.001543
181        service_ssh          0.001475
178     service_radius          0.001454
164       proto_wb-mon          0.001407
69           proto_ggp          0.001395
92       proto_ipv6-no          0.001370
169         proto_zero          0.001320
106      proto_mfe-nsp          0.001228
71           proto_gre          0.001202
77     proto_idpr-cmtp          0.001167
125          proto_pvp          0.001124
74          proto_iatp          0.001112
144          proto_srp          0.001112
123          proto_ptp          0.001077
101         proto_l2tp          0.001059
114   proto_nsfnet-igp          0.001056
94    proto_ipv6-route          0.001016
70          proto_gmtp          0.000989
120         proto_pnni          0.000899
57         proto_crudp          0.000864
182        service_ssl          0.000845
113       proto_netblt          0.000844
108         proto_micp          0.000754
124          proto_pup          0.000743
63         proto_eigrp          0.000668
154      proto_trunk-2          0.000647
76          proto_idpr          0.000601
72           proto_hmp          0.000589
136  proto_secure-vmtp          0.000577
58           proto_dcn          0.000526
59           proto_ddp          0.000515
95      proto_ipx-n-ip          0.000456
41     proto_aes-sp3-d          0.000449
132     proto_sccopmce          0.000413
183          state_ACC          0.000410
79          proto_ifmp          0.000362
73        proto_i-nlsp          0.000362
171       service_dhcp          0.000307
44          proto_aris          0.000113
155          proto_ttp          0.000059
75            proto_ib          0.000000
64         proto_emcon          0.000000
168          proto_xtp          0.000000
127          proto_rdp          0.000000
166         proto_xnet          0.000000
165          proto_wsn          0.000000
60           proto_ddx          0.000000
80          proto_igmp          0.000000
162         proto_vrrp          0.000000
61           proto_dgp          0.000000
55          proto_cpnx          0.000000
56          proto_crtp          0.000000
85          proto_ipcv          0.000000
176        service_irc          0.000000
53   proto_compaq-peer          0.000000
52         proto_chaos          0.000000
51          proto_cftp          0.000000
180       service_snmp          0.000000
50           proto_cbt          0.000000
49    proto_br-sat-mon          0.000000
184          state_CLO          0.000000
48           proto_bna          0.000000
40           proto_a/n          0.000000
83            proto_ip          0.000000
159        proto_vines          0.000000
129          proto_rvd          0.000000
143          proto_sps          0.000000
130    proto_sat-expak          0.000000
131      proto_sat-mon          0.000000
133         proto_scps          0.000000
126          proto_qnx          0.000000
135         proto_sdrp          0.000000
122          proto_prm          0.000000
121      proto_pri-enc          0.000000
119         proto_pipe          0.000000
117          proto_pgm          0.000000
115          proto_nvp          0.000000
141          proto_snp          0.000000
112         proto_narp          0.000000
105    proto_merit-inp          0.000000
86          proto_ipip          0.000000
145          proto_st2          0.000000
146          proto_stp          0.000000
104       proto_leaf-2          0.000000
148        proto_swipe          0.000000
149          proto_tcf          0.000000
103       proto_leaf-1          0.000000
151         proto_tlsp          0.000000
102         proto_larp          0.000000
93     proto_ipv6-opts          0.000000
91     proto_ipv6-frag          0.000000
90          proto_ipv6          0.000000
89          proto_ippc          0.000000
189          state_RST          0.000000

'''