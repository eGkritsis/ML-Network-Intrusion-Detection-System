import matplotlib.pyplot as plt


def plot_anomaly_score(anomaly_scores):
    plt.hist(anomaly_scores, bins='auto', alpha=0.7, rwidth=0.85)
    plt.xlabel('Anomaly Score')
    plt.ylabel('Frequency')
    plt.title('Anomaly Score Distribution')
    plt.show()

def time_series_anomaly_plot(timestamps, anomaly_scores):
    plt.plot(timestamps, anomaly_scores)
    plt.xlabel('Timestamp')
    plt.ylabel('Anomaly Score')
    plt.title('Time Series Anomaly Plot')
    plt.xticks(rotation=45)
    plt.show()

