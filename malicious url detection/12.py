import numpy as np
import pandas as pd
from urllib.parse import urlparse
from tld import get_tld
import os.path
import re
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

url_list=pd.read_csv('malicious_phish.csv')