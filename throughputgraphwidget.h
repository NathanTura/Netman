#ifndef THROUGHPUTGRAPHWIDGET_H
#define THROUGHPUTGRAPHWIDGET_H

#include <QWidget>
#include <QVector>

class ThroughputGraphWidget : public QWidget
{
    Q_OBJECT

public:
    explicit ThroughputGraphWidget(QWidget *parent = nullptr);

    void addSample(double downMbps, double upMbps);
    void clear();

protected:
    void paintEvent(QPaintEvent *event) override;

private:
    static constexpr int MAX_SAMPLES = 30;
    QVector<double> mDownHistory;
    QVector<double> mUpHistory;
    double mMaxScale{10.0};
    bool mIsInitialSeed{true};
};

#endif // THROUGHPUTGRAPHWIDGET_H
