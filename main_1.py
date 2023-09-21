# Import Libraries
import OpenSSL
import os
import time
import argparse
from PDFNetPython3.PDFNetPython import *
from typing import Tuple


def createKeyPair(type, bits):
    """
    создаем публичный/закрытый ключ
    """
    pkey = OpenSSL.crypto.PKey()
    pkey.generate_key(type, bits)
    return pkey


def create_self_signed_cert(pKey):
    # Создаем самоподписанный сертификат
    cert = OpenSSL.crypto.X509()
    # Имя
    cert.get_subject().CN = "Mansur Kindarov"
    # серийный номер
    cert.set_serial_number(int(time.time() * 10))
    # не перед
    cert.gmtime_adj_notBefore(0)  # не перед
    # не после
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    # Определить проблему
    cert.set_issuer((cert.get_subject()))
    cert.set_pubkey(pKey)
    cert.sign(pKey, 'md5')  # или cert.sign(pKey, 'sha256')
    return cert


def load():
    """генерируем сертификат"""
    summary = {}
    summary['OpenSSL Version'] = OpenSSL.__version__
    # генерируем приватный ключ
    key = createKeyPair(OpenSSL.crypto.TYPE_RSA, 1024)
    # PEM закодирован
    with open('.\project\private_key.pem', 'wb') as pk:
        pk_str = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
        pk.write(pk_str)
        summary['Private Key'] = pk_str
    # завершили генерацию приватного ключа
    # Создание самоподписанного сертификата клиента
    cert = create_self_signed_cert(pKey=key)
    with open('.\project\certificate.cer', 'wb') as cer:
        cer_str = OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_PEM, cert)
        cer.write(cer_str)
        summary['Self Signed Certificate'] = cer_str
    # завершили Создание самоподписанного сертификата клиента
    # генерируем публичный код
    with open('.\project\public_key.pem', 'wb') as pub_key:
        pub_key_str = OpenSSL.crypto.dump_publickey(
            OpenSSL.crypto.FILETYPE_PEM, cert.get_pubkey())
        # print("Public key = ",pub_key_str)
        pub_key.write(pub_key_str)
        summary['Public Key'] = pub_key_str
    # Завершили создание публичного ключа
    # Возьмем закрытый ключ и сертификат и объединим их в файл PKCS12.
    # Генерация файла-контейнера закрытого ключа и сертификата
    p12 = OpenSSL.crypto.PKCS12()
    p12.set_privatekey(key)
    p12.set_certificate(cert)
    open('.\project\container.pfx', 'wb').write(p12.export())
    print("## Initialization Summary ##################################################")
    print("\n".join("{}:{}".format(i, j) for i, j in summary.items()))
    print("############################################################################")
    return True


def sign_file(input_file: str, signatureID: str, x_coordinate: int,
              y_coordinate: int, pages: Tuple = None, output_file: str = None
              ):
    """подписываем пдф-файл"""
    if not output_file:
        output_file = (os.path.splitext(input_file)[0]) + "_signed.pdf"
    # инициализируем библиотеку
    PDFNet.Initialize("demo:1654296411308:7b91e4e603000000008fb5a6f65be29bb84ce4a22e9264ec51acb86909")
    doc = PDFDoc(input_file)
    # создаем поле для подписи
    sigField = SignatureWidget.Create(doc, Rect(
        x_coordinate, y_coordinate, x_coordinate + 100, y_coordinate + 50), signatureID)
    for page in range(1, (doc.GetPageCount() + 1)):
        # Если требуется для определенных страниц
        if pages:
            if str(page) not in pages:
                continue
        pg = doc.GetPage(page)
        # Создаем текстовое поле для подписи и отправляем его на страницу.
        pg.AnnotPushBack(sigField)
    # Изображение подписи
    sign_filename = os.path.dirname(
        os.path.abspath(__file__)) + "\project\signature.jpg"
    # Самоподписанный сертификат
    pk_filename = os.path.dirname(
        os.path.abspath(__file__)) + "\project\container.pfx"
    # Получаем поле подписи.
    approval_field = doc.GetField(signatureID)
    approval_signature_digsig_field = DigitalSignatureField(approval_field)
    # Добавим внешний вид в поле подписи.
    img = Image.Create(doc.GetSDFDoc(), sign_filename)
    found_approval_signature_widget = SignatureWidget(
        approval_field.GetSDFObj())
    found_approval_signature_widget.CreateSignatureAppearance(img)
    #Подготовим подпись и обработчик подписи для подписания
    approval_signature_digsig_field.SignOnNextSave(pk_filename, '')
    # Подписание будет выполнено во время следующей операции добавочного сохранения.
    doc.Save(output_file, SDFDoc.e_incremental)
    # Разработаем резюме процесса
    summary = {
        "Input File": input_file, "Signature ID": signatureID,
        "Output File": output_file, "Signature File": sign_filename,
        "Certificate File": pk_filename
    }
    print("## Summary ########################################################")
    print("\n".join("{}:{}".format(i, j) for i, j in summary.items()))
    print("###################################################################")
    return True


def sign_folder(**kwargs):
    input_folder = kwargs.get('input_folder')
    signatureID = kwargs.get('signatureID')
    pages = kwargs.get('pages')
    x_coordinate = int(kwargs.get('x_coordinate'))
    y_coordinate = int(kwargs.get('y_coordinate'))
    recursive = kwargs.get('recursive')
    for foldername, dirs, filenames in os.walk(input_folder):
        for filename in filenames:
            if not filename.endswith('.pdf'):
                continue
            inp_pdf_file = os.path.join(foldername, filename)
            print("Processing file =", inp_pdf_file)
            sign_file(input_file=inp_pdf_file, signatureID=signatureID, x_coordinate=x_coordinate,
                      y_coordinate=y_coordinate, pages=pages, output_file=None)
        if not recursive:
            break


def is_valid_path(path):
    if not path:
        raise ValueError(f"Invalid Path")
    if os.path.isfile(path):
        return path
    elif os.path.isdir(path):
        return path
    else:
        raise ValueError(f"Invalid Path {path}")


def parse_args():
    parser = argparse.ArgumentParser(description="Available Options")
    parser.add_argument('-l', '--load', dest='load', action="store_true",
                        help="Load the required configurations and create the certificate")
    parser.add_argument('-i', '--input_path', dest='input_path', type=is_valid_path,
                        help="Enter the path of the file or the folder to process")
    parser.add_argument('-s', '--signatureID', dest='signatureID',
                        type=str, help="Enter the ID of the signature")
    parser.add_argument('-p', '--pages', dest='pages', type=tuple,
                        help="Enter the pages to consider e.g.: [1,3]")
    parser.add_argument('-x', '--x_coordinate', dest='x_coordinate',
                        type=int, help="Enter the x coordinate.")
    parser.add_argument('-y', '--y_coordinate', dest='y_coordinate',
                        type=int, help="Enter the y coordinate.")
    path = parser.parse_known_args()[0].input_path
    if path and os.path.isfile(path):
        parser.add_argument('-o', '--output_file', dest='output_file',
                            type=str, help="Enter a valid output file")
    if path and os.path.isdir(path):
        parser.add_argument('-r', '--recursive', dest='recursive', default=False, type=lambda x: (
                str(x).lower() in ['true', '1', 'yes']), help="Process Recursively or Non-Recursively")
    args = vars(parser.parse_args())
    print("## Command Arguments #################################################")
    print("\n".join("{}:{}".format(i, j) for i, j in args.items()))
    print("######################################################################")
    return args


if __name__ == '__main__':
    args = parse_args()
    if args['load'] == True:
        load()
    else:
        if os.path.isfile(args['input_path']):
            sign_file(
                input_file=args['input_path'], signatureID=args['signatureID'],
                x_coordinate=int(args['x_coordinate']), y_coordinate=int(args['y_coordinate']),
                pages=args['pages'], output_file=args['output_file']
            )
        elif os.path.isdir(args['input_path']):
            sign_folder(
                input_folder=args['input_path'], signatureID=args['signatureID'],
                x_coordinate=int(args['x_coordinate']), y_coordinate=int(args['y_coordinate']),
                pages=args['pages'], recursive=args['recursive']
            )
