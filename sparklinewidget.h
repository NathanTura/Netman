#ifndef SPARKLINEWIDGET_H
#define SPARKLINEWIDGET_H

#include <QWidget>
#include <QVector>
#include <QColor>

class SparklineWidget : public QWidget
{
    Q_OBJECT
public:
    explicit SparklineWidget(QWidget *parent = nullptr);

    void setColor(const QColor &lineColor, const QColor &fillColor);
    void addValue(double val);
    void setValues(const QVector<double> &values);

protected:
    void paintEvent(QPaintEvent *event) override;

private:
    QVector<double> mValues;
    QColor mLineColor{QColor("#10b981")};
    QColor mFillColor{QColor(16, 185, 129, 35)};
    static constexpr int MAX_POINTS = 20;
};

#endif // SPARKLINEWIDGET_H
