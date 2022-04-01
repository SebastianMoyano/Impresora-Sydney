#!/usr/bin/env python
# -*- coding: utf-8 -*-
# import required modulesimport os

#import configparser
from doctest import COMPARISON_FLAGS
import poplib, os
from email.parser import Parser
import time
from os import path
import smtplib, ssl
import subprocess
#from typing import ParamSpecArgs
# pop3 server domain.
pop3_server_domain = 'pop.gmail.com'
# pop3 server connection object.
pop3_server_conn = None
'''
This method will connect to the global pop3 server 
and login with the provided user email and password.
'''
def sendEmail(receiver_email,message):

    port = 465  # For SSL
    smtp_server = "smtp.gmail.com"
    sender_email = "impresoraspython@sydneycollege.cl"  # Enter your address
    password = 'Pehuen1070'
    message = 'Subject: No responder \n\n' + message
    print(receiver_email)

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, message)

def avaliable(printer):
    
    l = os.popen('lpq -P "'+printer+'"').read()
    l=l[:-1].split('\n')
    for lines in l:
        if 'preparada' in lines:
            return 1
    return 0
    #lpq -P "Ink-Tank-310" check if printer is available


def creacionImpresora():
    dic = {}
    if path.isfile('impresoras'):
        with open('impresoras','r') as file: 
            impresora = ''
            lines = file.readlines()
            for line in lines:
                todo = line.split(';')
                dic[todo[0]]=todo[1].replace("\n","")

        return dic
    else:
        l = os.popen("lpstat -a | cut -f1 -d ' '").read()
        l=l[:-1].split('\n')
        for x in range(len(l)):
            print(str(x)+'. '+l[x])
        impresora = input("Ingresar numero: ")
        correo = input("Ingresar correo correspondiente: ")
        with open('impresoras','w') as file:
            file.write(correo+";"+l[int(impresora)])
        dic[correo]=impresora    
        return dic

def Seleccionarimpresoras(correo):
    
    if correo in _impresoras.keys():
        return _impresoras[correo]
    else:
        print('no existe esta impresora')




def imprimir(filename,mensajetotal):

    impresora = Seleccionarimpresoras(mensajetotal[0])
    print(impresora)
    if avaliable(impresora):
        terminacion = filename.split('.')[-1]
        #hay que revisar si es que hay espacio por q parece que afecta por eso solo lo hare con el nombre
        if impresora != '':
            if "doc" in terminacion or "docx" in terminacion:
                #filename = filename.split('/')[-1]
                text = (' "'+filename+'"')*mensajetotal[2]

                #revisar uso de lp
                #lp -d printer -n 2 filename

                print('libreoffice --headless --pt '+impresora+text)
                
                k = os.popen('libreoffice --headless --pt '+impresora+text).read()
                time.sleep(5)
                sendEmail(mensajetotal[1],'Enviado a imprimir doc')
            elif 'pdf' in terminacion:
                print("impresora entro")
                args = ['lp','-d',impresora,'-n',str(mensajetotal[2]),filename]
                print(args)
                try:
                    # stdout = subprocess.PIPE lets you redirect the output
                    res = subprocess.Popen(args, stdout=subprocess.PIPE)
                except OSError:
                    print ("error: popen")
                    exit(-1) # if the subprocess call failed, there's not much point in continuing

                res.wait() # wait for process to finish; this also sets the returncode variable inside 'res'
                print(res.returncode)
                if res.returncode != 0:
                    print("  os.wait:exit status != 0\n")
                    sendEmail(mensajetotal[1],'Error Al imprimir, problemas con el archivo')
                else:
                    print("enviado")
                    sendEmail(mensajetotal[1],'Tu impresion esta siendo procesada')
                    

                # There was an error - command exited with non-zero code
                #k = os.popen('lp -d '+impresora+' -n '+mensajetotal[2]+' "'+filename+'"').read()
                #if 'No existe el archivo' in k:
                   # sendEmail(mensajetotal[1],'Error Al imprimir, problemas con el archivo')
               

                time.sleep(5)
                sendEmail(mensajetotal[1],'Enviado a imprimir')
            else:
                sendEmail(mensajetotal[1],'Error en imprimir')
                
                pass
                #responder con que el formato no sirve
    else:
        sendEmail(mensajetotal[1],'Impresora no disponible')
        

def connect_pop3_server(user_email, user_password):
    # use global pop3_server_conn variable in this function.
    global pop3_server_conn
    
    # if pop3 server connection object is null then create it.
    if(pop3_server_conn is None):
        print('********************************* start connect_pop3_server *********************************')
        # create pop3 server connection object.

        pop3_server_conn = poplib.POP3_SSL(pop3_server_domain,'995')
        #pop3_server_conn.set_debuglevel(1)
        
        # get pop3 server welcome message and print on console.
        welcome_message = pop3_server_conn.getwelcome()
        print('Below is pop3 server welcome messages : ')
        print(welcome_message)
        
        # send user email and password to pop3 server.
        pop3_server_conn.user(user_email)
        pop3_server_conn.pass_(user_password)
    
    return pop3_server_conn
'''
Close the pop3 server connection and release the connection object.
'''
def close_pop3_server_connection():
    global pop3_server_conn
    if pop3_server_conn != None:
        pop3_server_conn.quit()
        pop3_server_conn = None
'''
Get email messages status of the given user.
'''
def get_user_email_status(user_email, user_password):
    
    # connect to pop3 server with the user account.
    connect_pop3_server(user_email, user_password)
    print('********************************* start get_user_email_status *********************************')
    
    # get user total email message count and email file size. 
    (messageCount, totalMessageSize) = pop3_server_conn.stat()
    #print('Email message numbers : ' + str(messageCount))
    #print('Total message size : ' + str(totalMessageSize) + ' bytes.')
    return messageCount,totalMessageSize
    
'''
Get user email index info。
def get_user_email_index(user_email, user_password):
    
    connect_pop3_server(user_email, user_password)
    print('********************************* start get_user_email_index *********************************')
    
    # get all user email list info from pop3 server.
    (resp_message, mails_list, octets) = pop3_server_conn.list()
    # print server response message.
    print('Server response message : ' + str(resp_message))
    # loop in the mail list.
    for mail in mails_list:
        # print each mail object info.
        print('Mail : ' + str(mail))
    
    print('Octets number : ' + str(octets))
'''

    
'''
Get user account email by the provided email account and email index number.
'''
def get_email_by_index(user_email, user_password, email_index):
    
    connect_pop3_server(user_email, user_password)
    print('********************************* start get_email_by_index *********************************')
    # retrieve user email by email index. 
    try:
        (resp_message, lines, octets) = pop3_server_conn.retr(email_index) #
    except:
        return -1
    print('Server response message : ' + str(resp_message))
    print('Octets number : ' + str(octets))
   
    # join each line of email message content to create the email content and decode the data with utf-8 charset encoding.  
    msg_content = b'\r\n'.join(lines).decode('utf-8')
    # print out the email content string.
    # print('Mail content : ' + msg_content)
    
    # parse the email string to a MIMEMessage object.
    msg = Parser().parsestr(msg_content)
    parse_email_msg(msg)
    
 
# Parse email message.   
def parse_email_msg(msg):
    
    print('********************************* start parse_email_msg *********************************')
    
    mensajetotal = parse_email_header(msg)
     
    parse_email_body(msg,mensajetotal)    
    
# Delete user email by index.   
'''
def delete_email_from_pop3_server(user_email, user_password, email_index):
    connect_pop3_server(user_email, user_password)   
    print('********************************* start delete_email_from_pop3_server *********************************')
    
    pop3_server_conn.dele(email_index)
    print('Delete email at index : ' + email_index)
'''

    
    
# Parse email header data.    
def parse_email_header(msg):
    print('********************************* start parse_email_header *********************************')
    # just parse from, to, subject header value.
    header_list = ('From', 'To', 'Subject')
    
    # loop in the header list
    for header in header_list:
        # get each header value.
        header_value = msg.get(header, '')
        print(header + ' : ' + header_value) 
        if 'impresoraspython' in header_value :
            correoraw = header_value.replace(">", "")
            correo = correoraw.split('<')[-1]
            print(correo)
            
        if header == 'Subject':
            try:
                copias = int(header_value)
            except:
                copias = 1
        if header == 'From':
            correoraw = header_value.replace(">", "")
            correoOrigen = correoraw.split('<')[-1]
            print(correoOrigen)

            
    return [correo, correoOrigen,copias]
            
      
# Parse email body data.      
def parse_email_body(msg,mensajetotal):
    print('********************************* start parse_email_body *********************************')
    
    # if the email contains multiple part.
    if (msg.is_multipart()):
        # get all email message parts.
        parts = msg.get_payload()
        # loop in above parts.
        for n, part in enumerate(parts):
            # get part content type.
            content_type = part.get_content_type()
            print('---------------------------Part ' + str(n) + ' content type : ' + content_type + '---------------------------------------')
            parse_email_content(part,mensajetotal)                
    else:
       parse_email_content(msg,mensajetotal) 
# Parse email message part data.            
def parse_email_content(msg,mensajetotal):
    # get message content type.
    content_type = msg.get_content_type().lower()
    
    print('---------------------------------' + content_type + '------------------------------------------')
    # if the message part is text part.
    if content_type=='text/plain' or content_type=='text/html':
        # get text content.
        content = msg.get_payload(decode=True)
        # get text charset.
        charset = msg.get_charset()
        # if can not get charset. 
        if charset is None:
            # get message 'Content-Type' header value.
            content_type = msg.get('Content-Type', '').lower()
            # parse the charset value from 'Content-Type' header value.
            pos = content_type.find('charset=')
            if pos >= 0:
                charset = content_type[pos + 8:].strip()
                pos = charset.find(';')
                if pos>=0:
                    charset = charset[0:pos]           
        if charset:
            content = content.decode(charset)
                
        print(content)
    # if this message part is still multipart such as 'multipart/mixed','multipart/alternative','multipart/related'
    elif content_type.startswith('multipart'):
        # get multiple part list.
        body_msg_list = msg.get_payload()
        # loop in the multiple part list.
        for body_msg in body_msg_list:
            # parse each message part.
            parse_email_content(body_msg,mensajetotal)
    # if this message part is an attachment part that means it is a attached file.  
    elif content_type in ['application/msword' ,'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/pdf']:
    #      
    #elif content_type.startswith('image') or content_type.startswith('application'):
        # get message header 'Content-Disposition''s value and parse out attached file name.
        attach_file_info_string = msg.get('Content-Disposition')
        prefix = 'filename="'
        pos = attach_file_info_string.find(prefix)
        attach_file_name = attach_file_info_string[pos + len(prefix): len(attach_file_info_string) - 1]
        
        # get attached file content.
        attach_file_data = msg.get_payload(decode=True)
        # get current script execution directory path. 
        current_path = os.path.dirname(os.path.abspath(__file__))
   
        # get the attached file full path.
        
        attach_file_path = os.path.join(current_path,'archivos',attach_file_name)
        # write attached file content to the file.
        with open(attach_file_path,'wb') as f:
            f.write(attach_file_data)
        print('attached file is saved in path ' + attach_file_path)  
        imprimir(attach_file_path,mensajetotal)
        os.remove(attach_file_path)
            
          
                
    else:
        content = msg.as_string()
        print(content)         
    
if __name__ == '__main__':

    #Seleccionarimpresoras('')
    user_email = 'impresoraspython@sydneycollege.cl'
    
    user_password = 'Pehuen1070'
    _impresoras = creacionImpresora()
    print(_impresoras)
    
    while True:
        try:
            cantidad_mensajes,peso_mensajes = get_user_email_status(user_email, user_password)
            if cantidad_mensajes > 0:
                get_email_by_index(user_email, user_password, 1)
                
            #get_user_email_index(user_email, user_password)
            #get_email_by_index(user_email, user_password, 1)
            close_pop3_server_connection()
            time.sleep(5)         
        except Exception as e:
            close_pop3_server_connection()
            print(e)

######
