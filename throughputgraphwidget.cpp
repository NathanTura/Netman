#include "throughputgraphwidget.h"
#include <QPainter>
#include <QPainterPath>
#include <QLinearGradient>
#include <cmath>
#include <algorithm>

ThroughputGraphWidget::ThroughputGraphWidget(QWidget *parent)
    : QWidget(parent)
{
    setMinimumHeight(240);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);

    // Initial gentle curve
    mDownHistory = {2.0, 2.5, 3.2, 3.8, 3.1, 2.8, 3.5, 3.2, 2.9, 3.6, 3.3, 3.0};
    mUpHistory   = {1.0, 1.3, 1.8, 2.1, 1.7, 1.5, 1.9, 1.6, 1.4, 1.8, 1.5, 1.2};
    mMaxScale = 5.0;
}

void ThroughputGraphWidget::addSample(double downMbps, double upMbps)
{
    double safeDown = qMax(0.05, downMbps);
    double safeUp = qMax(0.05, upMbps);

    if (mIsInitialSeed) {
        mIsInitialSeed = false;
        mDownHistory.clear();
        mUpHistory.clear();
        for (int i = 0; i < 20; ++i) {
            double phase = (static_cast<double>(i) / 19.0) * 3.14159 * 2.0;
            double modDown = 0.82 + 0.22 * std::sin(phase);
            double modUp   = 0.78 + 0.22 * std::cos(phase);
            mDownHistory.append(qMax(0.05, safeDown * modDown));
            mUpHistory.append(qMax(0.05, safeUp * modUp));
        }
    } else {
        mDownHistory.append(safeDown);
        mUpHistory.append(safeUp);
    }

    while (mDownHistory.size() > MAX_SAMPLES) {
        mDownHistory.removeFirst();
    }
    while (mUpHistory.size() > MAX_SAMPLES) {
        mUpHistory.removeFirst();
    }

    // Dynamic auto-scaling based on peak of both streams
    double peak = 0.5;
    for (double val : mDownHistory) peak = qMax(peak, val);
    for (double val : mUpHistory)   peak = qMax(peak, val);

    // 25% headroom so peaks don't touch the top border
    double target = peak * 1.25;
    double newScale = 2.0;

    if (target <= 0.5)        newScale = 0.5;
    else if (target <= 1.0)   newScale = 1.0;
    else if (target <= 2.0)   newScale = 2.0;
    else if (target <= 5.0)   newScale = 5.0;
    else if (target <= 10.0)  newScale = 10.0;
    else if (target <= 20.0)  newScale = 20.0;
    else if (target <= 30.0)  newScale = 30.0;
    else if (target <= 50.0)  newScale = 50.0;
    else if (target <= 100.0) newScale = 100.0;
    else if (target <= 200.0) newScale = 200.0;
    else if (target <= 500.0) newScale = 500.0;
    else if (target <= 1000.0) newScale = 1000.0;
    else newScale = std::ceil(target / 250.0) * 250.0;

    mMaxScale = newScale;
    update();
}

void ThroughputGraphWidget::clear()
{
    mDownHistory.clear();
    mUpHistory.clear();
    mMaxScale = 5.0;
    mIsInitialSeed = true;
    update();
}

void ThroughputGraphWidget::paintEvent(QPaintEvent *)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);

    const int w = width();
    const int h = height();

    const int topPadding = 22;
    const int bottomPadding = 26;
    const int leftPadding = 68; // Space for Y-axis labels
    const int rightPadding = 22;

    const int plotWidth = w - leftPadding - rightPadding;
    const int plotHeight = h - topPadding - bottomPadding;

    if (plotWidth <= 20 || plotHeight <= 20) return;

    p.fillRect(rect(), Qt::transparent);

    // Dynamic Y-Axis scale tick labels
    double midVal = mMaxScale / 2.0;
    QString topLabel;
    QString midLabel;
    QString btmLabel = "0 Mbps";

    if (mMaxScale < 10.0) {
        topLabel = QString("%1 Mbps").arg(mMaxScale, 0, 'f', 1);
        midLabel = QString("%1 Mbps").arg(midVal, 0, 'f', 1);
    } else if (mMaxScale >= 1000.0) {
        topLabel = QString("%1 Gbps").arg(mMaxScale / 1000.0, 0, 'f', 1);
        midLabel = QString("%1 Mbps").arg(static_cast<int>(midVal));
    } else {
        topLabel = QString("%1 Mbps").arg(static_cast<int>(mMaxScale));
        midLabel = QString("%1 Mbps").arg(static_cast<int>(midVal));
    }

    int yTop = topPadding + 4;
    int yMid = topPadding + plotHeight / 2;
    int yBtm = topPadding + plotHeight;

    // Draw Y-Axis Ticks
    p.setFont(QFont("Segoe UI", 9, QFont::Normal));
    p.setPen(QColor("#94a3b8"));
    p.drawText(QRect(0, yTop - 8, leftPadding - 12, 16), Qt::AlignRight | Qt::AlignVCenter, topLabel);
    p.drawText(QRect(0, yMid - 8, leftPadding - 12, 16), Qt::AlignRight | Qt::AlignVCenter, midLabel);
    p.drawText(QRect(0, yBtm - 8, leftPadding - 12, 16), Qt::AlignRight | Qt::AlignVCenter, btmLabel);

    // Subtle dotted horizontal grid lines
    QPen gridPen(QColor("#e2e8f0"), 1, Qt::DashLine);
    p.setPen(gridPen);
    p.drawLine(leftPadding, yTop, leftPadding + plotWidth, yTop);
    p.drawLine(leftPadding, yMid, leftPadding + plotWidth, yMid);
    p.drawLine(leftPadding, yBtm, leftPadding + plotWidth, yBtm);

    // Helper to calculate smooth cubic spline for any stream
    auto computeSpline = [&](const QVector<double> &data, QVector<QPointF> &ptsOut) -> QPainterPath {
        ptsOut.clear();
        ptsOut.reserve(data.size());
        for (int i = 0; i < data.size(); ++i) {
            double x = leftPadding + (static_cast<double>(i) / (data.size() - 1)) * plotWidth;
            double norm = qBound(0.0, data[i] / mMaxScale, 1.0);
            double y = topPadding + (1.0 - norm) * plotHeight;
            ptsOut.append(QPointF(x, y));
        }

        QPainterPath path;
        if (ptsOut.isEmpty()) return path;
        path.moveTo(ptsOut[0]);

        for (int i = 0; i < ptsOut.size() - 1; ++i) {
            QPointF p0 = (i > 0) ? ptsOut[i - 1] : ptsOut[i];
            QPointF p1 = ptsOut[i];
            QPointF p2 = ptsOut[i + 1];
            QPointF p3 = (i + 2 < ptsOut.size()) ? ptsOut[i + 2] : p2;

            QPointF c1 = p1 + (p2 - p0) * 0.25;
            QPointF c2 = p2 - (p3 - p1) * 0.25;

            // Clamp control points within the chart bounds so the curve never dips below 0 Mbps
            c1.setY(qBound(static_cast<double>(topPadding), c1.y(), static_cast<double>(yBtm)));
            c2.setY(qBound(static_cast<double>(topPadding), c2.y(), static_cast<double>(yBtm)));

            path.cubicTo(c1, c2, p2);
        }
        return path;
    };

    // 1. Draw Upload Curve (Purple #9333ea)
    if (mUpHistory.size() >= 2) {
        QVector<QPointF> upPts;
        QPainterPath upLine = computeSpline(mUpHistory, upPts);

        // Soft purple gradient area fill
        QPainterPath upFill = upLine;
        upFill.lineTo(leftPadding + plotWidth, yBtm);
        upFill.lineTo(leftPadding, yBtm);
        upFill.closeSubpath();

        QLinearGradient gradUp(0, topPadding, 0, yBtm);
        gradUp.setColorAt(0.0, QColor(147, 51, 234, 25)); // Gentle soft purple tint
        gradUp.setColorAt(0.7, QColor(147, 51, 234, 8));
        gradUp.setColorAt(1.0, QColor(147, 51, 234, 1));
        p.fillPath(upFill, gradUp);

        // Purple solid line with NO brush fill
        p.setBrush(Qt::NoBrush);
        p.setPen(QPen(QColor("#9333ea"), 2.0, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
        p.drawPath(upLine);

        // Current tip marker
        if (!upPts.isEmpty()) {
            QPointF lastPt = upPts.last();
            p.setBrush(QColor("#9333ea"));
            p.setPen(QPen(Qt::white, 1.5));
            p.drawEllipse(lastPt, 3.5, 3.5);
            p.setBrush(Qt::NoBrush);
        }
    }

    // 2. Draw Download Curve (Blue #2563eb)
    if (mDownHistory.size() >= 2) {
        QVector<QPointF> downPts;
        QPainterPath downLine = computeSpline(mDownHistory, downPts);

        // Soft blue gradient area fill
        QPainterPath downFill = downLine;
        downFill.lineTo(leftPadding + plotWidth, yBtm);
        downFill.lineTo(leftPadding, yBtm);
        downFill.closeSubpath();

        QLinearGradient gradDown(0, topPadding, 0, yBtm);
        gradDown.setColorAt(0.0, QColor(37, 99, 235, 38)); // Gentle soft blue tint
        gradDown.setColorAt(0.7, QColor(37, 99, 235, 12));
        gradDown.setColorAt(1.0, QColor(37, 99, 235, 2));
        p.fillPath(downFill, gradDown);

        // Blue solid line with NO brush fill
        p.setBrush(Qt::NoBrush);
        p.setPen(QPen(QColor("#2563eb"), 2.2, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
        p.drawPath(downLine);

        // Current tip marker
        if (!downPts.isEmpty()) {
            QPointF lastPt = downPts.last();
            p.setBrush(QColor("#2563eb"));
            p.setPen(QPen(Qt::white, 1.5));
            p.drawEllipse(lastPt, 3.5, 3.5);
            p.setBrush(Qt::NoBrush);
        }
    }

    // 3. Compact Legend at top right
    {
        p.setFont(QFont("Segoe UI", 8, QFont::DemiBold));
        int legX = leftPadding + plotWidth - 175;
        int legY = topPadding - 6;

        // Download legend
        p.setBrush(QColor("#2563eb"));
        p.setPen(Qt::NoPen);
        p.drawEllipse(legX, legY + 2, 6, 6);
        p.setPen(QColor("#475569"));
        p.drawText(legX + 10, legY + 8, "Download (↓)");

        // Upload legend
        int legX2 = legX + 90;
        p.setBrush(QColor("#9333ea"));
        p.setPen(Qt::NoPen);
        p.drawEllipse(legX2, legY + 2, 6, 6);
        p.setPen(QColor("#475569"));
        p.drawText(legX2 + 10, legY + 8, "Upload (↑)");
        p.setBrush(Qt::NoBrush);
    }
}
