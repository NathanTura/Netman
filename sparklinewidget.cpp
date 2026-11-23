#include "sparklinewidget.h"
#include <QPainter>
#include <QPainterPath>
#include <QLinearGradient>
#include <algorithm>

SparklineWidget::SparklineWidget(QWidget *parent)
    : QWidget(parent)
{
    setMinimumSize(90, 42);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    // Initial gentle wave data matching reference
    mValues = {12, 14, 11, 15, 13, 16, 18, 14, 17, 19, 16, 20};
}

void SparklineWidget::setColor(const QColor &lineColor, const QColor &fillColor)
{
    mLineColor = lineColor;
    mFillColor = fillColor;
    update();
}

void SparklineWidget::addValue(double val)
{
    mValues.append(val);
    while (mValues.size() > MAX_POINTS) {
        mValues.removeFirst();
    }
    update();
}

void SparklineWidget::setValues(const QVector<double> &values)
{
    mValues = values;
    update();
}

void SparklineWidget::paintEvent(QPaintEvent *)
{
    if (mValues.size() < 2) return;

    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);

    const int w = width();
    const int h = height();
    const int padY = 6;
    const int padX = 4;
    const int plotW = w - padX * 2;
    const int plotH = h - padY * 2;

    if (plotW <= 5 || plotH <= 5) return;

    double minVal = *std::min_element(mValues.begin(), mValues.end());
    double maxVal = *std::max_element(mValues.begin(), mValues.end());
    if (qFuzzyCompare(minVal, maxVal)) {
        minVal -= 1.0;
        maxVal += 1.0;
    }

    QVector<QPointF> points;
    points.reserve(mValues.size());
    for (int i = 0; i < mValues.size(); ++i) {
        double x = padX + (static_cast<double>(i) / (mValues.size() - 1)) * plotW;
        double norm = (mValues[i] - minVal) / (maxVal - minVal);
        double y = padY + (1.0 - norm) * plotH;
        points.append(QPointF(x, y));
    }

    // Build smooth cubic bezier curve
    QPainterPath linePath;
    linePath.moveTo(points[0]);

    for (int i = 0; i < points.size() - 1; ++i) {
        QPointF p0 = (i > 0) ? points[i - 1] : points[i];
        QPointF p1 = points[i];
        QPointF p2 = points[i + 1];
        QPointF p3 = (i + 2 < points.size()) ? points[i + 2] : p2;

        QPointF c1 = p1 + (p2 - p0) * 0.2;
        QPointF c2 = p2 - (p3 - p1) * 0.2;

        linePath.cubicTo(c1, c2, p2);
    }

    // Draw gradient fill
    QPainterPath fillPath = linePath;
    fillPath.lineTo(padX + plotW, h);
    fillPath.lineTo(padX, h);
    fillPath.closeSubpath();

    QLinearGradient grad(0, padY, 0, h);
    grad.setColorAt(0.0, mFillColor);
    grad.setColorAt(1.0, QColor(mFillColor.red(), mFillColor.green(), mFillColor.blue(), 2));
    p.fillPath(fillPath, grad);

    // Draw smooth line
    p.setPen(QPen(mLineColor, 2, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    p.drawPath(linePath);
}
