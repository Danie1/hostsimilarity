#!/usr/bin/env python3
# coding: utf-8

from sklearn import tree
import pandas as pd
from sklearn.tree import DecisionTreeClassifier # Import Decision Tree Classifier
from sklearn.naive_bayes import GaussianNB
from sklearn.naive_bayes import CategoricalNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import AdaBoostClassifier
from sklearn.cluster import KMeans
from sklearn import svm
from sklearn.neural_network import MLPClassifier
from sklearn.linear_model import SGDClassifier
from sklearn.ensemble import VotingClassifier

from sklearn.model_selection import train_test_split # Import train_test_split function
from sklearn import metrics #Import scikit-learn metrics module for accuracy calculation
from sklearn.metrics import average_precision_score
from sklearn.metrics import precision_recall_curve
from sklearn.metrics import precision_recall_fscore_support
from sklearn.metrics import cohen_kappa_score
from sklearn.metrics import auc
from sklearn.calibration import CalibratedClassifierCV
import matplotlib.pyplot as plt
from inspect import signature
from sklearn.feature_selection import mutual_info_classif
import os
from sklearn.tree import export_graphviz
from sklearn.externals.six import StringIO  
from IPython.display import Image  
import pydotplus
import pprint
from collections import Counter
import tqdm
import datetime
import numpy as np
import seaborn as sns
from dython import nominal
import sys

sys.path.insert(1, "data_processing")

from Utils import *

WORKSPACE_DIR = os.path.join("results", "hs_results")

dir_paths = [WORKSPACE_DIR]

features_cols_list = ['is_very_close', 'is_close', 'is_equal_GoogleID', 'is_equal_common_port', 
                      'is_equal_not_wellknown_port', 'is_equal_not_registered_port', 'is_equal_common_port_transport', 
                      'is_equal_not_wellknown_port_transport', 'is_equal_not_registered_port_transport', 
                      'is_equal_port_product_version', 'is_equal_port_product', 'is_equal_os', 'is_equal_version', 
                      'is_equal_product', 'is_equal_asn', 'is_equal_org', 'is_equal_http.html_hash', 
                      'is_equal_location.country_name', 'is_equal_port', 'is_equal_cpe', 'is_equal_isp', 
                      'is_equal_transport', 'is_equal_info', 'is_equal_opts.vulns', 
                      'is_equal_ssl.cert.fingerprint.sha256', 'is_equal_ssl.cert.serial', 'is_equal_ssl.chain', 
                      'is_equal_ssl.dhparams.public_key', 'is_equal_ssl.cert.expires', "is_equal_asn_org_isp", 
                      "is_equal_chain_fingerprint_serial_expires", "is_equal_cn_port_transport_asn_org_isp", "is_equal_cpe_port_product_version",
                      "is_equal_cpe_port_transport_product_version", "is_equal_cn_asn_org_isp", "is_equal_feature_group_a"]

corr_to_remove = ['is_equal_product', 'is_equal_ssl.cert.fingerprint.sha256', 'is_equal_ssl.cert.serial', 
                  'is_equal_ssl.chain', 'is_equal_ssl.cert.expires', 
                  'is_equal_version', "is_equal_not_registered_port_transport", 'is_equal_not_registered_port',
                  "is_equal_ssl.dhparams.public_key", "is_equal_opts.vulns", "is_equal_cn_asn_org_isp", "is_equal_port_transport_product_version",
                  "is_equal_cpe_port_transport_product_version", 'is_equal_not_wellknown_port_transport', "is_equal_port_product_version"]

corr_to_remove += ["is_equal_cpe_port_product_version",  "is_equal_cn_port_transport_asn_org_isp", "is_equal_asn_org_isp", "is_equal_port_product", "is_equal_common_port_transport"]

corr_to_remove += ['is_equal_asn', 'is_equal_org', 'is_equal_isp', 'is_equal_location.country_name', "is_equal_port", 'is_equal_transport',]

remove_per_scenario = {"tld": ["is_equal_chain_fingerprint_serial_expires"], "sha":[]}

to_remove = ["related", "ip1_ip1", "ip1_ip2", "pair", "Unnamed: 0"]

def CreateTree(clf, treename):
        dot_data = StringIO()
        export_graphviz(clf, 
                        out_file=dot_data,  
                        filled=True, 
                        rounded=True,
                        special_characters=True,
                        class_names=['Negative','Positive'])
        graph = pydotplus.graph_from_dot_data(dot_data.getvalue())

        graph.write_png(os.path.join(dir_path,'{}_tree.png'.format(treename)))
        #Image(graph.create_png())
        print("Created: {}_tree.png".format(treename))
        
def GetCM(df, x, y):
    return confusion_matrix.ConfusionMatrix(df[[x, y]], 
                                            df.groupby([x, y]).size().reset_index(name="count"),
                                            x, 
                                            y, 
                                            'count')

def ConvertToBoolDF(df, scenario, scenario_type):
    pima_bool = df.copy()
    #special_col = "is_equal_port_product" if scenario == "tld" else "is_equal_http.html_hash"
    for f in features_cols_list:
        pima_bool[f] = pima_bool[f].apply(lambda x: 0 if x == 0.5 else x)

    pima_bool.to_csv(os.path.join(dir_path, "{}_{}_is_equal_bool.csv".format(scenario_type, scenario)), index=False)
    return pima_bool

def ReturnMetrics(y_test, y_pred, y_score):
    acc = metrics.accuracy_score(y_test, y_pred)
   
    if y_score is not None:
        average_precision = average_precision_score(y_test, y_score[:, 1])
    else:
        average_precision = None
    
    auc_val = 0
    fpr, tpr, thresholds = metrics.roc_curve(y_test, y_pred, pos_label=1)
    auc_val = metrics.auc(fpr, tpr)
    
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred,  average='weighted')
    
    return {"Precision":precision, "Recall": recall, "F1": f1, "Accuracy":acc, "AP": average_precision, "AUC": auc_val}

def PrintMetrics(y_pred, results):
    print("Accuracy: {}".format(results["Accuracy"]))
    
    if results["AP"] is not None:
        print('Average precision-recall score: {0:0.2f}'.format(results["AP"]))
    print("Area Under Curve (AUC): {}".format(results["AUC"]))
    print("Precision: {}, Recall: {}, F1: {}".format(results["Precision"], results["Recall"], results["F1"]))
    
    print("Cohen's Kappa: {}".format(cohen_kappa_score(y_test, y_pred)))

def PerformSVC(X_train, y_train, X_test, y_test, feature_list):
    #classifier = svm.SVC(gamma='scale', kernel='linear', class_weight='balanced', C=1.0, random_state=0) #, probability=True)
    classifier = svm.LinearSVC()
    classifier = CalibratedClassifierCV(classifier)
    classifier.fit(X_train, y_train)
    y_pred = classifier.predict(X_test)
    y_score = classifier.predict_proba(X_test)
    
    return classifier, y_pred, ReturnMetrics(y_test, y_pred, y_score)

def PerformVoting(X_train, y_train, X_test, y_test, feature_list, clf1, clf2, clf3, clf4, clf5):
    classifier = VotingClassifier(estimators=[('lr', clf1), ('rf', clf2), ('gnb', clf3)], voting='hard')
    classifier.fit(X_train, y_train)
    y_pred = classifier.predict(X_test)
    y_score = classifier.predict_proba(X_test)
    
    return classifier, y_pred, ReturnMetrics(y_test, y_pred, y_score)

def PerformMLP(X_train, y_train, X_test, y_test, feature_list):
    classifier = MLPClassifier(solver='lbfgs', alpha=1e-5, hidden_layer_sizes=(5, 2), random_state=1)
    classifier.fit(X_train, y_train)
    y_pred = classifier.predict(X_test)
    y_score = classifier.predict_proba(X_test)
    
    return classifier, y_pred, ReturnMetrics(y_test, y_pred, y_score)
    
def PerformSGDClassifier(X_train, y_train, X_test, y_test, feature_list):
    classifier = SGDClassifier(max_iter=1000, tol=1e-3)
    #classifier = svm.LinearSVC()
    classifier.fit(X_train, y_train)
    y_pred = classifier.predict(X_test)
    y_score = None
    
    return classifier, y_pred, ReturnMetrics(y_test, y_pred, y_score)

def PerformKMeans(X_train, y_train, X_test, y_test, feature_list):
    classifier = KMeans(n_clusters=3)
    classifier.fit(X_train)
    y_pred = classifier.predict(X_test)
    y_score = None
    
    return classifier, y_pred, ReturnMetrics(y_test, y_pred, y_score)

def PerformAdaBoost(X_train, y_train, X_test, y_test, feature_list):
    classifier = AdaBoostClassifier(n_estimators=100, random_state=0)
    classifier.fit(X_train, y_train)
    y_pred = classifier.predict(X_test)
    y_score = classifier.predict_proba(X_test)
    
    return classifier, y_pred, ReturnMetrics(y_test, y_pred, y_score)

def PerformKNN(X_train, y_train, X_test, y_test, feature_list):
    classifier = KNeighborsClassifier(n_neighbors=2)
    classifier.fit(X_train, y_train)
    y_pred = classifier.predict(X_test)
    y_score = classifier.predict_proba(X_test)
    
    return classifier, y_pred, ReturnMetrics(y_test, y_pred, y_score)

def PerformGB(X_train, y_train, X_test, y_test, feature_list):
    classifier = GaussianNB()
    res = classifier.fit(X_train, y_train)
    y_pred = classifier.predict(X_test)
    y_score = classifier.predict_proba(X_test)
        
    return classifier, y_pred, ReturnMetrics(y_test, y_pred, y_score)

def PerformCategoricalNB(X_train, y_train, X_test, y_test, feature_list):
    classifier = CategoricalNB()
    res = classifier.fit(X_train, y_train)
    y_pred = classifier.predict(X_test)
    y_score = classifier.predict_proba(X_test)
        
    return classifier, y_pred, ReturnMetrics(y_test, y_pred, y_score)
    
def PerformDT(X_train, y_train, X_test, y_test, feature_list):
    # Create Decision Tree classifer object
    #print("Max-Depth: {}".format(len(feature_list)))
    classifier = DecisionTreeClassifier(criterion="entropy", max_depth=len(feature_list))

    # Train Decision Tree Classifer
    classifier = classifier.fit(X_train,y_train)

    from sklearn.tree._tree import TREE_LEAF

    def prune_index(inner_tree, index, threshold):
        if inner_tree.value[index].min() < threshold:
            # turn node into a leaf by "unlinking" its children
            inner_tree.children_left[index] = TREE_LEAF
            inner_tree.children_right[index] = TREE_LEAF
        # if there are children, visit them as well
        if inner_tree.children_left[index] != TREE_LEAF:
            prune_index(inner_tree, inner_tree.children_left[index], threshold)
            prune_index(inner_tree, inner_tree.children_right[index], threshold)

    #print(sum(dt.tree_.children_left < 0))
    # start pruning from the root
    prune_index(classifier.tree_, 0, len(feature_list))
    #sum(classifier.tree_.children_left < 0)

    #Predict the response for test dataset
    y_pred = classifier.predict(X_test)
    y_score = classifier.predict_proba(X_test)
        
    return classifier, y_pred, ReturnMetrics(y_test, y_pred, y_score)
    
    
def PerformStump(feature, df):
    X = df[[feature]] # Features
    y = df["related"] # Target variable

    X_train, X_test, y_train, y_test = train_test_split(X, y, train_size=0.70, test_size=0.30) # 70% training and 30% test

    
    # Create Decision Tree classifer object
    clf = DecisionTreeClassifier(criterion="entropy", max_depth=2)

    # Train Decision Tree Classifer
    clf = clf.fit(X_train,y_train)

    from sklearn.tree._tree import TREE_LEAF

    dt = clf

    def prune_index(inner_tree, index, threshold):
        if inner_tree.value[index].min() < threshold:
            # turn node into a leaf by "unlinking" its children
            inner_tree.children_left[index] = TREE_LEAF
            inner_tree.children_right[index] = TREE_LEAF
        # if there are shildren, visit them as well
        if inner_tree.children_left[index] != TREE_LEAF:
            prune_index(inner_tree, inner_tree.children_left[index], threshold)
            prune_index(inner_tree, inner_tree.children_right[index], threshold)

    #print(sum(dt.tree_.children_left < 0))
    # start pruning from the root
    prune_index(dt.tree_, 0, 5)
    sum(dt.tree_.children_left < 0)

    #Predict the response for test dataset
    y_pred = clf.predict(X_test)
    
    accuracy = metrics.accuracy_score(y_test, y_pred)
    average_precision = 0
    average_precision = average_precision_score(y_test, y_pred)
    
    auc_val = 0
    fpr, tpr, thresholds = metrics.roc_curve(y_test, y_pred, pos_label=1)
    auc_val = metrics.auc(fpr, tpr)

    return {"accuracy": accuracy, "ap": average_precision, "auc":auc_val}

effective_cols = {}
all_df = {}
feature_stumps = {}
cm_table = {}
summ_table = {}
more_summ_table = {}

def AddToMoreSummaryTable(scenario, dict_val):
    if "scenario" not in summ_table:
        more_summ_table["scenario"] = []
    more_summ_table["scenario"] += [scenario]
    
    for k,v in dict_val.items():
        if k not in more_summ_table:
            more_summ_table[k] = []
            
        more_summ_table[k] += [v]

def AddToSummaryTable(scenario, dict_val):
    if "scenario" not in summ_table:
        summ_table["scenario"] = []
    summ_table["scenario"] += [scenario]
    
    for k,v in dict_val.items():
        if k not in summ_table:
            summ_table[k] = []
            
        summ_table[k] += [v]
        
def AddToCMTable(scenario, dict_val):
    if "scenario" not in cm_table:
        cm_table["scenario"] = []
    cm_table["scenario"] += [scenario]
    
    for k,v in dict_val.items():
        if k not in cm_table:
            cm_table[k] = []
            
        cm_table[k] += [v]

def run_cm(df, filepath):
    final_res = {}
    
    def AddToFeatureCMTable(feature, dict_val):
        if "Feature" not in final_res:
            final_res["Feature"] = []
        final_res["Feature"] += [feature]

        for k,v in dict_val.items():
            if k not in final_res:
                final_res[k] = []

            final_res[k] += [v]

    classes = Confuse(df, "related", "is_")
    
    feature_cm_table = {}
    for k, v in tqdm.tqdm(classes.items()):
        result = v.summarize(digits=5, enable_mutual_info=True)
        AddToFeatureCMTable(k, result)
        
    tmp_df = pd.DataFrame(final_res)
    tmp_df.to_csv(filepath, index=False)
        
classifiers = {"Naive Bayes" : {"clf" : PerformGB, "cm_enable" : False},
               "AdaBoost" : {"clf" : PerformAdaBoost, "cm_enable" : False},
               "MLP" : {"clf" : PerformMLP, "cm_enable" : False},
               "SVM" : {"clf" : PerformSVC, "cm_enable" : False},
               "Decision Tree" : {"clf" : PerformDT, "cm_enable" : True}}

#classifiers = {"Decision Tree" : {"clf" : PerformDT, "cm_enable" : True}}

def Classify(key, X_train, y_train, X_test , y_test, feature_cols):
    clf_table = {}
    
    def AddToCLFTable(scenario, dict_val):
        if "scenario" not in clf_table:
            clf_table["scenario"] = []
        clf_table["scenario"] += [scenario]

        for k,v in dict_val.items():
            if k not in clf_table:
                clf_table[k] = []

            clf_table[k] += [v]
    
    for k,v in classifiers.items():
        print("Started processing classifier [{}]".format(k))
        clf, y_pred, results = v["clf"](X_train, y_train, X_test , y_test, feature_cols)
        PrintMetrics(y_pred, results)
        print("Finished processing classifier [{}]".format(k))
        
        AddToCLFTable(k, results)
        
        if v["cm_enable"]:
            df_cm = pd.DataFrame({"related":y_test, "pred":y_pred})
            cm = GetCM(df_cm, "pred", "related").summarize(digits=5, enable_mutual_info=True)
            AddToCMTable(key, cm)
    
    return pd.DataFrame(clf_table)
        
# load dataset
for dir_path in dir_paths: # old and new negatives
    for scenario in ["tld", "sha"]: # tld and sha            
        for scenario_type in ["new_NULL", "new_NO_NULL", "old_NULL", "old_NO_NULL"]:
            
            print("\n---\nStarting {} - {} - {} - [{}]".format(dir_path, scenario_type, scenario, str(datetime.datetime.now())))

            df = pd.read_csv(os.path.join(dir_path, "{}_{}_is_equal.csv".format(scenario_type, scenario)))
            k = "{}_{}".format(scenario_type, scenario)
            feature_cols = [x for x in df.columns if x not in to_remove and x not in corr_to_remove and x not in remove_per_scenario[scenario]]
            effective_cols[k] = feature_cols
            all_df[k] = df
            df["is_very_close"] = df["is_very_close"].apply(lambda x: 1 if x else 0)
            df["is_close"] = df["is_close"].apply(lambda x: 1 if x else 0)
            df[feature_cols + ["related"]].to_csv(os.path.join(dir_path, "{}_{}_is_equal_final.csv".format(scenario_type, scenario)), index=False)

            X = df[feature_cols] # Features
            y = df["related"] # Target variable
            
            X_train, X_test, y_train, y_test = train_test_split(X, y, train_size=0.70, test_size=0.30) # 70% training and 30% test

            res = Classify(k, X_train, y_train, X_test , y_test, feature_cols)
            res.to_csv(os.path.join(dir_path, "{}_classifiers.csv".format(k)), index=False)
            #run_cm(df[feature_cols + ["related"]], os.path.join(dir_path, "{}_cm.csv".format(k)))
            
            f_values = {}
            if "scenario" not in feature_stumps:
                feature_stumps["scenario"] = []
            feature_stumps["scenario"] += [k]

            for f in feature_cols:
                if "{}_acc".format(f) not in feature_stumps:
                    # Make none the values in features that are not in other scenarios
                    feature_stumps["{}_acc".format(f)] = [None] * (len(feature_stumps["scenario"]) - 1)
                    feature_stumps["{}_ap".format(f)] = [None] * (len(feature_stumps["scenario"]) - 1)
                    feature_stumps["{}_auc".format(f)] = [None] * (len(feature_stumps["scenario"]) - 1)

                acc = 0
                ap = 0
                auc = 0
                d = PerformStump(f, df)
                acc = d["accuracy"]
                ap = d["ap"]
                auc = d["auc"]
                feature_stumps["{}_acc".format(f)] += [acc]
                feature_stumps["{}_ap".format(f)] += [ap]
                feature_stumps["{}_auc".format(f)] += [auc]

            for f in feature_cols:
                if len(feature_stumps["{}_acc".format(f)]) < len(feature_stumps["scenario"]):
                    diff = len(feature_stumps["scenario"]) - len(feature_stumps[f])
                    print("=> Added {} to feature {}".format(diff, f))
                    feature_stumps["{}_acc".format(f)] += [None] * diff
                    feature_stumps["{}_ap".format(f)] += [None] * diff
                    feature_stumps["{}_auc".format(f)] += [None] * diff

summary_acc_df = pd.DataFrame(feature_stumps)
#print(summary_acc_df)
summary_acc_df.to_csv(os.path.join(dir_path, "accuracy_feature_stumps.csv"), index=False)

all_cm_df = pd.DataFrame(cm_table)
#print(all_cm_df)
all_cm_df.to_csv(os.path.join(dir_path, "cm_table.csv"), index=False)

summ_df = pd.DataFrame(summ_table)
#print(summ_df)
summ_df.to_csv(os.path.join(dir_path, "summary_table.csv"), index=False)

more_summ_df = pd.DataFrame(more_summ_table)
#print(summ_df)
more_summ_df.to_csv(os.path.join(dir_path, "more_summary_table.csv"), index=False)


# In[6]

def round_values(val):
    new_val = round(val, 2)
    
    if new_val == 0:
        return 0
    return new_val

for k,v in all_df.items():
    print("<=== {} ===>".format(k))
    data = v[effective_cols[k]]
    data.columns = [c.replace("is_equal_", "") for c in data.columns]
    
    if k.find("NO_NULL") != -1 and False:
        import pandas as pd
        from sklearn.metrics import confusion_matrix
        a,b,c,d = confusion_matrix(data['http.html_hash'], data['http.title']).ravel()

        from math import sqrt
        top = (a*d) - (b*c)
        bottom = sqrt((a+b) * (c+d) * (a+c) * (b+d))

        print(top/bottom)
        
    corr_df = nominal.associations(data, nominal_columns="all", theil_u=True, return_results=True, plot=False)
    
    #get correlations of each features in dataset
    #corrmat = data.corr()
    #top_corr_features = corrmat.index
    plt.figure(figsize=(len(data.columns),len(data.columns)))
    #plot heat map
    sns.set(font_scale=2)
    
    #corr_df = data[top_corr_features].corr()
    
    corr_df = corr_df.applymap(round_values)

    g=sns.heatmap(corr_df,annot=True,cmap="RdYlGn",annot_kws={"size": 15})
    fig = g.get_figure()
    fig.tight_layout()
    fig.savefig(os.path.join(dir_path, "{}_corr_heatmap.png".format(k)))