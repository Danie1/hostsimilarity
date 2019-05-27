# TODO - rounding of number
# TOTO - take care of zero tp, fp, etc.
import numpy as np
from sklearn.feature_selection import mutual_info_classif

class ConfusionMatrix(object):
    def __init__(self
                    , orig_df
                    , df
                    , classifier='classifier'
                    , concept='concept'
                    , count='count'):
        """
        :param orig_df: The full original data frame that consists of the classifier and concept
        :param df: A data frame of the confusion matrix, grouped by classifier and concept and number of items in count
        :param classifier: Field of classifier
        :param concept: Field of concept
        :param count: Field of items number
        """
        self.orig_df = orig_df
        self.df = df
        self.classifier = classifier
        self.concept = concept
        self.count = count

    def items(self):
        return self.df[self.count].sum()

    def true_positives(self):
        rc = 0
        if len(self.df[(self.df[self.concept] == True) & (self.df[self.classifier] == True)]) > 0:
            rc = self.df[(self.df[self.concept] == True) & (self.df[self.classifier] == True)].iloc[0][self.count]
        return rc

    def false_positives(self):
        rc = 0
        if len(self.df[(self.df[self.concept] == False) & (self.df[self.classifier] == True)]) > 0:
            rc = self.df[(self.df[self.concept] == False) & (self.df[self.classifier] == True)].iloc[0][self.count]
        return rc


    def false_negatives(self):
        rc = 0
        if len(self.df[(self.df[self.concept] == True) & (self.df[self.classifier] == False)]) > 0:
            rc = self.df[(self.df[self.concept] == True) & (self.df[self.classifier] == False)].iloc[0][self.count]
        return rc

    def true_negatives(self):
        rc = 0
        if len(self.df[(self.df[self.concept] == False) & (self.df[self.classifier] == False)]) > 0:
            rc = self.df[(self.df[self.concept] == False) & (self.df[self.classifier] == False)].iloc[0][self.count]
        return rc

    def accuracy(self):
        return (1.0*self.true_positives() +self.true_negatives())/self.items()

    def items_of_value(self
                   , value=True):
        return 1.0*self.df[(self.df[self.concept] == value)][self.count].sum()

    def items_rate(self
                   , value=True):
        return 1.0*self.items_of_value(value)/self.items()

    def positive_rate(self):
        return self.items_rate()

    def hits_of_value(self
                   , value=True):
        return 1.0*self.df[(self.df[self.classifier] == value)][self.count].sum()

    def classifier_rate(self
                   , value=True):
        return 1.0*self.hits_of_value(value)/self.items()

    def hit_rate(self):
        return self.classifier_rate()

    def recall(self):
        return 1.0*self.true_positives()/self.items_of_value()

    def precision(self):
        return 1.0*self.true_positives()/self.hits_of_value()

    def false_positive_rate(self):
        """
        FPR
        :return: 
        """
        return 1.0*self.false_positives()/self.hits_of_value(value=False)

    def precision_lift(self):
        return self.precision()/self.positive_rate() - 1

    def mutual_information(self):
        return mutual_info_classif(self.orig_df[[self.classifier]], self.orig_df[self.concept].astype('bool'))

    def summarize(self, digits=4, enable_mutual_info=False):
        ret = "disabled"
        if enable_mutual_info:
            ret = self.mutual_information()

        return {
            'items': self.items()
            , 'accuracy': np.round(self.accuracy(), digits)
            , 'true_positives': self.true_positives()
            , 'false_positives': self.false_positives()
            , 'false_negatives': self.false_negatives()
            , 'true_negatives': self.true_negatives()
            , 'positive_rate': np.round(self.positive_rate(), digits)
            , 'hit_rate': np.round(self.hit_rate(), digits)
            , 'recall': np.round(self.recall(), digits)
            , 'precision': np.round(self.precision(), digits)
            , 'false_positive_rate': np.round(self.false_positive_rate(), digits)
            , 'precision_lift': np.round(self.precision_lift(), digits)
            , 'mutual_information': ret
        }
