#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <functional>

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private:
    Ui::MainWindow *ui;

    void processClickButton(std::function<QString(const QString&,const QString&)> func);

private slots:
    void on_pushButtonEncrypt_clicked();
    void on_pushButtonDecipher_clicked();
};
#endif // MAINWINDOW_H
