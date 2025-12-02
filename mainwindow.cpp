#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include "./crypto.h"

#include <QDebug>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::processClickButton(std::function<QString(const QString&)> func) {
    QString input = ui->textEditMessage->toPlainText();
    ui->textEditResult->setText(func(input));
}

void MainWindow::on_pushButtonEncrypt_clicked()
{
    processClickButton(Crypto::encrypt);
}


void MainWindow::on_pushButtonDecipher_clicked()
{
    processClickButton(Crypto::decrypt);
}

void MainWindow::on_pushButtonGenerateKey_clicked()
{
    QString publicKey {Crypto::generatePublicKey()};
    ui->textEditKey->setPlainText(publicKey);
}

