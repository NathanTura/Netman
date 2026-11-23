#include "mainwindow.h"

#include <QApplication>
#include <QTimer>
#include <QPixmap>
#include <QStringList>
#include <QStackedWidget>
#include <QPushButton>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.show();

    QStringList args = a.arguments();

    int tabIdx = args.indexOf("--tab");
    if (tabIdx != -1 && tabIdx + 1 < args.size()) {
        int page = args.at(tabIdx + 1).toInt();
        QStackedWidget *st = w.findChild<QStackedWidget*>("stackedWidget");
        if (st && page >= 0 && page < st->count()) {
            st->setCurrentIndex(page);
        }
        if (page == 1) {
            QPushButton *btn = w.findChild<QPushButton*>("btnNavPackets");
            if (btn) btn->setChecked(true);
        }
    }

    int idx = args.indexOf("--screenshot");
    if (idx != -1 && idx + 1 < args.size()) {
        QString outPath = args.at(idx + 1);
        QTimer::singleShot(2000, [&w, outPath]() {
            QPixmap pix = w.grab();
            pix.save(outPath, "PNG");
            QApplication::quit();
        });
    }

    return QApplication::exec();
}


