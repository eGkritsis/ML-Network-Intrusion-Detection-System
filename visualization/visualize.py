import numpy as np
import matplotlib.pyplot as plt

def plot_attack_categories(attack_categories):
    unique_categories, counts = np.unique(attack_categories, return_counts=True)

    plt.figure(figsize=(10, 6))
    plt.bar(unique_categories, counts)
    plt.title('Attack Categories')
    plt.xlabel('Attack Category')
    plt.ylabel('Count')
    plt.xticks(rotation=45)
    plt.show()
