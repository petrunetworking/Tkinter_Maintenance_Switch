import tkinter as tk
from threading import Thread
from datetime import datetime
from pprint import pprint
from tkinter import ttk
from tkinter import *
from tkinter.ttk import *
from tkinter import filedialog as fd
from tkinter import messagebox
import os
from huawei_telnet import HuaweiTelnet
import socket
import re
window=tk.Tk()
frame = tk.Frame(window)
window.title('Maintenance Switch and Management v2.1 By Petru Network Engineer')
window.geometry('1200x920')
# parametrii pentru functionareaa aplicatiei si adaugarea functiilor noi
def delete():
    result_text.configure(state=NORMAL)
    result_text.delete(1.0,tk.END)
    result_text.configure(state=DISABLED)
def press_key(event):
    if event.char =='\x08':
        delete()
def open_window():
    newwindow = Toplevel(window)
    newwindow.geometry('880x640')
    newwindow.title('show configuration')
    input_text = Text(newwindow , width= 100 , height=36 ,)
    input_text.grid(row= 0 ,column= 5,)
    scrolbar = Scrollbar(newwindow,orient=VERTICAL)
    scrolbar.grid(row=0, column=int(0.5), sticky='NSE', padx=15 , pady=15)
    input_text.config(yscrollcommand=scrolbar.set)
    scrolbar.config(command=input_text.yview)
# parametrii de conectare la echipament si afisarea rezultatelor
def switch_interface_all():
        ip_input =input_ip_address.get(1.0,10.0)
        username =input_username.get()
        password =input_password.get()
        #ip_list =["192.168.100.1" ,"192.168.100.2" , "192.168.100.3"]
        # regex_ip =r"(?P<IP_Adress>\d+\.\d+\.\d+\.\d+)"
        # result_ip =re.search(regex_ip ,ip_input)
        # if result_ip:
        #     ip =result_ip.group()
        ip_list =ip_input.split()
        for ip in ip_list:
             pprint(ip)
             try:
                with HuaweiTelnet(ip, username, password, prompt="<") as switch:
                    result_text.configure(state=NORMAL)
                    result_text.insert(END , f"======================================={ip}=========================================\n")
                    command=switch.send_show_command("display interface brief")
                    result_text.insert(END , command)
                    result_text.insert(END,"\n==========================================================================================\n")
                    result_text.configure(state=DISABLED)
                    logfile( ip=ip ,command=command)

             except EOFError as error:
                result_text.configure(state=NORMAL)
                result_text.insert(END,f"Authentication failed on IP:{ip}\t{error}\n")
                result_text.configure(state=DISABLED)
             except socket.timeout as timeout:
               result_text.configure(state=NORMAL)
               result_text.insert(END,f"Could Not Posible Connect on IP:{ip}\t{timeout}\n") 
               result_text.configure(state=DISABLED)
        

def switch_interface():
        ip_input =input_ip_address.get(1.0,10.0)
        username =input_username.get()
        password =input_password.get()
        selected_interface =interface_string.get()
        interface =chose_interface_eth.get()
        ip_list =ip_input.split()
        pprint(ip_list)
        #ip_list =["192.168.100.1" ,"192.168.100.2" , "192.168.100.3"]
        #regex_ip =r"(?P<IP_Adress>\d+\.\d+\.\d+\.\d+)"
        #for multiple_ip in result_input:

         #result_ip =re.search(regex_ip ,multiple_ip)
       # if result_ip:
           # ip_list =[result_ip.group()]
           # pprint(ip_list)
        
        for ip in ip_list:
              pprint(ip)
              try:
                with HuaweiTelnet(ip, username, password, prompt="<") as switch:
                    result_text.configure(state=NORMAL)
                    result_text.insert(END , f"======================================={ip}=========================================\n")
                    command=switch.send_show_command(f"display interface {selected_interface}{interface}")
                    result_text.insert(END , command)
                    result_text.insert(END,"\n==========================================================================================\n")
                    result_text.configure(state=DISABLED)
                    logfile( ip=ip ,command=command)


              except EOFError as error:
                result_text.configure(state=NORMAL)
                result_text.insert(END,f"Authentication failed on IP:{ip}\t{error}\n")
                result_text.configure(state=DISABLED)
              except socket.timeout as timeout:
               result_text.configure(state=NORMAL)
               result_text.insert(END,f"Could Not Posible Connect on IP:{ip}\t{timeout}\n") 
               result_text.configure(state=DISABLED) 

def switch_interface_description():
        ip_input =input_ip_address.get(1.0,10.0)
        username =input_username.get()
        password =input_password.get()
        ip_list =ip_input.split()
        pprint(ip_list)
        #ip_list =["192.168.100.1" ,"192.168.100.2" , "192.168.100.3"]
        #regex_ip =r"(?P<IP_Adress>\d+\.\d+\.\d+\.\d+)"
        #for multiple_ip in result_input:

         #result_ip =re.search(regex_ip ,multiple_ip)
       # if result_ip:
           # ip_list =[result_ip.group()]
           # pprint(ip_list)
        
        for ip in ip_list:
              pprint(ip)
              try:
                with HuaweiTelnet(ip, username, password, prompt="<") as switch:
                    result_text.configure(state=NORMAL)
                    result_text.insert(END , f"======================================={ip}=========================================\n")
                    command =switch.send_show_command(f"display interface description")
                    result_text.insert(END , command)
                    result_text.insert(END,"\n==========================================================================================\n")
                    result_text.configure(state=DISABLED)
                    logfile( ip=ip ,command=command)

              except EOFError as error:
                result_text.configure(state=NORMAL)
                result_text.insert(END,f"Authentication failed on IP:{ip}\t{error}\n")
                result_text.configure(state=DISABLED)
              except socket.timeout as timeout:
               result_text.configure(state=NORMAL)
               result_text.insert(END,f"Could Not Posible Connect on IP:{ip}\t{timeout}\n") 
               result_text.configure(state=DISABLED)
                

def switch_interface_config():
        ip_input =input_ip_address.get(1.0,10.0)
        username =input_username.get()
        password =input_password.get()
        selected_interface =interface_string.get()
        interface =chose_interface_eth.get()
        ip_list =ip_input.split()
        pprint(ip_list)
        #ip_list =["192.168.100.1" ,"192.168.100.2" , "192.168.100.3"]
        #regex_ip =r"(?P<IP_Adress>\d+\.\d+\.\d+\.\d+)"
        #for multiple_ip in result_input:

         #result_ip =re.search(regex_ip ,multiple_ip)
       # if result_ip:
           # ip_list =[result_ip.group()]
           # pprint(ip_list)
        for ip in ip_list:
              pprint(ip)
              try:
                with HuaweiTelnet(ip, username, password, prompt="<") as switch:
                    result_text.configure(state=NORMAL)
                    result_text.insert(END , f"======================================={ip}=========================================\n")
                    command =switch.send_show_command(f"display current-configuration interface {selected_interface}{interface}")
                    result_text.insert(END ,command )
                    result_text.insert(END,"\n==========================================================================================\n")
                    log_file( ip=ip ,command=command)
                    logfile( ip=ip ,command=command)

              except EOFError as error:
                result_text.configure(state=NORMAL)
                result_text.insert(END,f"Authentication failed on IP:{ip}\t{error}\n")
                result_text.configure(state=DISABLED)
              except socket.timeout as timeout:
               result_text.configure(state=NORMAL)
               result_text.insert(END,f"Could Not Posible Connect on IP:{ip}\t{timeout}\n") 
               result_text.configure(state=DISABLED)
            
def switch_info():
        ip_input =input_ip_address.get(1.0,10.0)
        username =input_username.get()
        password =input_password.get()
        ip_list =ip_input.split()
        pprint(ip_list)
        commands=["display version" ,"display patch-information ","display environment" , "display fan verbose"]
        #ip_list =["192.168.100.1" ,"192.168.100.2" , "192.168.100.3"]
        #regex_ip =r"(?P<IP_Adress>\d+\.\d+\.\d+\.\d+)"
        #for multiple_ip in result_input:

         #result_ip =re.search(regex_ip ,multiple_ip)
       # if result_ip:
           # ip_list =[result_ip.group()]
           # pprint(ip_list)
        for ip in ip_list:
              pprint(ip)
              try:
                with HuaweiTelnet(ip, username, password, prompt="<") as switch:
                  result_text.configure(state=NORMAL)
                  result_text.insert(END , f"======================================={ip}=========================================\n")
                  command = switch.send_multiple_command(commands)
                  result_text.insert(END ,command)
                  result_text.insert(END,"\n==========================================================================================\n")
                  result_text.configure(state=DISABLED)
                  logfile( ip=ip ,command=command)

              except EOFError as error:
                result_text.configure(state=NORMAL)
                result_text.insert(END,f"Authentication failed on IP:{ip}\t{error}\n")
                result_text.configure(state=DISABLED)
              except socket.timeout as timeout:
               result_text.configure(state=NORMAL)
               result_text.insert(END,f"Could Not Posible Connect on IP:{ip}\t{timeout}\n") 
               result_text.configure(state=DISABLED)


def switch_current_config():
        ip_input =input_ip_address.get(1.0,10.0)
        username =input_username.get()
        password =input_password.get()
        ip_list =ip_input.split()
        pprint(ip_list)
        #ip_list =["192.168.100.1" ,"192.168.100.2" , "192.168.100.3"]
        #regex_ip =r"(?P<IP_Adress>\d+\.\d+\.\d+\.\d+)"
        #for multiple_ip in result_input:

         #result_ip =re.search(regex_ip ,multiple_ip)
       # if result_ip:
           # ip_list =[result_ip.group()]
           # pprint(ip_list)
        for ip in ip_list:
              pprint(ip)
              try:
                with HuaweiTelnet(ip, username, password, prompt="<") as switch:
                  result_text.configure(state=NORMAL)
                  result_text.insert(END , f"======================================={ip}=========================================\n")
                  command =switch.get_config()
                  result_text.insert(END ,command)
                  result_text.insert(END,"\n==========================================================================================\n")
                  result_text.configure(state=DISABLED)
                  logfile( ip=ip ,command=command)

              except EOFError as error:
                result_text.configure(state=NORMAL)
                result_text.insert(END,f"Authentication failed on IP:{ip}\t{error}\n")
                result_text.configure(state=DISABLED)
              except socket.timeout as timeout:
               result_text.configure(state=NORMAL)
               result_text.insert(END,f"Could Not Posible Connect on IP:{ip}\t{timeout}\n") 
               result_text.configure(state=DISABLED)
def switch_dhcp_snopping():
        ip_input =input_ip_address.get(1.0,10.0)
        username =input_username.get()
        password =input_password.get()
        selected_interface =interface_string.get()
        interface =chose_interface_eth.get()
        #ip_list =["192.168.100.1" ,"192.168.100.2" , "192.168.100.3"]
        #regex_ip =r"(?P<IP_Adress>\d+\.\d+\.\d+\.\d+)"
        #result_ip =re.search(regex_ip ,ip_input)
        #if result_ip:
            #ip =result_ip.group()
        ip_list =ip_input.split()
        for ip in ip_list:
              pprint(ip)
              try:
                with HuaweiTelnet(ip, username, password, prompt="<") as switch:
                     result_text.configure(state=NORMAL)
                     result_text.insert(END , f"======================================={ip}=========================================\n")
                     command =switch.send_show_command(f"displ dhcp snooping user-bind interface {selected_interface}{interface}")
                     result_text.insert(END ,command )
                     result_text.insert(END,"\n==========================================================================================\n")
                     result_text.configure(state=DISABLED)
                     logfile( ip=ip ,command=command)

              except EOFError as error:
                result_text.configure(state=NORMAL)
                result_text.insert(END,f"Authentication failed on IP:{ip}\t{error}\n")
                result_text.configure(state=DISABLED)
              except socket.timeout as timeout:
               result_text.configure(state=NORMAL)
               result_text.insert(END,f"Could Not Posible Connect on IP:{ip}\t{timeout}\n") 
               result_text.configure(state=DISABLED)

    
def switch_mac_address_info():
        ip_input =input_ip_address.get(1.0,10.0)
        username =input_username.get()
        password =input_password.get()
        #ip_list =["192.168.100.1" ,"192.168.100.2" , "192.168.100.3"]
        #regex_ip =r"(?P<IP_Adress>\d+\.\d+\.\d+\.\d+)"
        #result_ip =re.search(regex_ip ,ip_input)
        #if result_ip:
            #ip =result_ip.group()
        ip_list =ip_input.split()
        for ip in ip_list:
              pprint(ip)
              try:
                with HuaweiTelnet(ip, username, password, prompt="<") as switch:
                    result_text.configure(state=NORMAL)
                    result_text.insert(END , f"======================================={ip}=========================================\n")
                    command = switch.send_show_command("display arp")
                    result_text.insert(END ,command)
                    result_text.insert(END,"\n==========================================================================================\n")
                    result_text.configure(state=DISABLED)
                    logfile( ip=ip ,command=command)

              except EOFError as error:
                result_text.configure(state=NORMAL)
                result_text.insert(END,f"Authentication failed on IP:{ip}\t{error}\n")
                result_text.configure(state=DISABLED)
              except socket.timeout as timeout:
               result_text.configure(state=NORMAL)
               result_text.insert(END,f"Could Not Posible Connect on IP:{ip}\t{timeout}\n") 
               result_text.configure(state=DISABLED)
def mac_address_vlan():
        ip_input =input_ip_address.get(1.0,10.0)
        username =input_username.get()
        password =input_password.get()
        vlan=chose_vlan.get()
        ip_list =ip_input.split()
        pprint(ip_list)
        #ip_list =["192.168.100.1" ,"192.168.100.2" , "192.168.100.3"]
        #regex_ip =r"(?P<IP_Adress>\d+\.\d+\.\d+\.\d+)"
        #for multiple_ip in result_input:

         #result_ip =re.search(regex_ip ,multiple_ip)
       # if result_ip:
           # ip_list =[result_ip.group()]
           # pprint(ip_list)
        for ip in ip_list:
              pprint(ip)
              try:
                with HuaweiTelnet(ip, username, password, prompt="<") as switch:
                     result_text.configure(state=NORMAL)
                     result_text.insert(END , f"======================================={ip}=========================================\n")
                     command=switch.send_show_command(f"display mac-address vlan  {vlan}")
                     result_text.insert(END , command)
                     result_text.insert(END,"\n==========================================================================================\n")
                     result_text.configure(state=DISABLED)
                     logfile( ip=ip ,command=command)

              except EOFError as error:
                result_text.configure(state=NORMAL)
                result_text.insert(END,f"Authentication failed on IP:{ip}\t{error}\n")
                result_text.configure(state=DISABLED)
              except socket.timeout as timeout:
               result_text.configure(state=NORMAL)
               result_text.insert(END,f"Could Not Posible Connect on IP:{ip}\t{timeout}\n") 
               result_text.configure(state=DISABLED)
    

def switch_igmp_info():
        ip_input =input_ip_address.get(1.0,10.0)
        username =input_username.get()
        password =input_password.get()
        ip_list =ip_input.split()
        pprint(ip_list)
        #ip_list =["192.168.100.1" ,"192.168.100.2" , "192.168.100.3"]
        #regex_ip =r"(?P<IP_Adress>\d+\.\d+\.\d+\.\d+)"
        #for multiple_ip in result_input:

         #result_ip =re.search(regex_ip ,multiple_ip)
       # if result_ip:
           # ip_list =[result_ip.group()]
           # pprint(ip_list)
        for ip in ip_list:
              pprint(ip)
              try:
                with HuaweiTelnet(ip, username, password, prompt="<") as switch:
                     result_text.configure(state=NORMAL)
                     result_text.insert(END , f"======================================={ip}=========================================\n")
                     command =switch.send_show_command("display igmp-snooping port-info")
                     result_text.insert(END ,command )
                     result_text.insert(END,"\n==========================================================================================\n")
                     result_text.configure(state=DISABLED)
                     logfile( ip=ip ,command=command) 

              except EOFError as error:
                result_text.configure(state=NORMAL)
                result_text.insert(END,f"Authentication failed on IP:{ip}\t{error}\n")
                result_text.configure(state=DISABLED)
              except socket.timeout as timeout:
               result_text.configure(state=NORMAL)
               result_text.insert(END,f"Could Not Posible Connect on IP:{ip}\t{timeout}\n") 
               result_text.configure(state=DISABLED)
def switch_info_vlan():
        ip_input =input_ip_address.get(1.0,10.0)
        username =input_username.get()
        password =input_password.get()
        vlan=chose_vlan.get()
        ip_list =ip_input.split()
        pprint(ip_list)
        #ip_list =["192.168.100.1" ,"192.168.100.2" , "192.168.100.3"]
        #regex_ip =r"(?P<IP_Adress>\d+\.\d+\.\d+\.\d+)"
        #for multiple_ip in result_input:

         #result_ip =re.search(regex_ip ,multiple_ip)
       # if result_ip:
           # ip_list =[result_ip.group()]
           # pprint(ip_list)
        for ip in ip_list:
              pprint(ip)
              try:
                with HuaweiTelnet(ip, username, password, prompt="<") as switch:
                     result_text.configure(state=NORMAL)
                     result_text.insert(END , f"======================================={ip}=========================================\n")
                     command=switch.send_show_command(f"display vlan  {vlan}")
                     result_text.insert(END , command)
                     result_text.insert(END,"\n==========================================================================================\n")
                     result_text.configure(state=DISABLED)
                     logfile( ip=ip ,command=command)

              except EOFError as error:
                result_text.configure(state=NORMAL)
                result_text.insert(END,f"Authentication failed on IP:{ip}\t{error}\n")
                result_text.configure(state=DISABLED)
              except socket.timeout as timeout:
               result_text.configure(state=NORMAL)
               result_text.insert(END,f"Could Not Posible Connect on IP:{ip}\t{timeout}\n") 
               result_text.configure(state=DISABLED)

def switch_info_all_vlans():
        ip_input =input_ip_address.get(1.0,10.0)
        username =input_username.get()
        password =input_password.get()
        ip_list =ip_input.split()
        pprint(ip_list)
        #ip_list =["192.168.100.1" ,"192.168.100.2" , "192.168.100.3"]
        #regex_ip =r"(?P<IP_Adress>\d+\.\d+\.\d+\.\d+)"
        #for multiple_ip in result_input:

         #result_ip =re.search(regex_ip ,multiple_ip)
       # if result_ip:
           # ip_list =[result_ip.group()]
           # pprint(ip_list)
        for ip in ip_list:
              pprint(ip)
              try:
                 with HuaweiTelnet(ip, username, password, prompt="<") as switch:
                     result_text.configure(state=NORMAL)
                     result_text.insert(END , f"======================================={ip}=========================================\n")
                     command =switch.send_show_command("display vlan | include enable")
                     result_text.insert(END ,command)
                     result_text.insert(END,"\n==========================================================================================\n")
                     result_text.configure(state=DISABLED)
                     logfile( ip=ip ,command=command)

              except EOFError as error:
                result_text.configure(state=NORMAL)
                result_text.insert(END,f"Authentication failed on IP:{ip}\t{error}\n")
                result_text.configure(state=DISABLED)
              except socket.timeout as timeout:
               result_text.configure(state=NORMAL)
               result_text.insert(END,f"Could Not Posible Connect on IP:{ip}\t{timeout}\n") 
               result_text.configure(state=DISABLED)
def switch_mac_add_interface():
        ip_input =input_ip_address.get(1.0,10.0)
        username =input_username.get()
        password =input_password.get()
        selected_interface =interface_string.get()
        interface=chose_interface_eth.get()
        ip_list =ip_input.split()
        pprint(ip_list)
        #ip_list =["192.168.100.1" ,"192.168.100.2" , "192.168.100.3"]
        #regex_ip =r"(?P<IP_Adress>\d+\.\d+\.\d+\.\d+)"
        #for multiple_ip in result_input:

         #result_ip =re.search(regex_ip ,multiple_ip)
       # if result_ip:
           # ip_list =[result_ip.group()]
           # pprint(ip_list)
        for ip in ip_list:
              pprint(ip)
              try:
                with HuaweiTelnet(ip, username, password, prompt="<") as switch:
                    result_text.configure(state=NORMAL)
                    result_text.insert(END , f"======================================={ip}=========================================\n")
                    command=switch.send_show_command(f"display mac-address {selected_interface}{interface}")
                    result_text.insert(END , command)
                    result_text.insert(END,"\n==========================================================================================\n")
                    result_text.configure(state=DISABLED)
                    logfile( ip=ip ,command=command)

              except EOFError as error:
                result_text.configure(state=NORMAL)
                result_text.insert(END,f"Authentication failed on IP:{ip}\t{error}\n")
                result_text.configure(state=DISABLED)
              except socket.timeout as timeout:
               result_text.configure(state=NORMAL)
               result_text.insert(END,f"Could Not Posible Connect on IP:{ip}\t{timeout}\n") 
               result_text.configure(state=DISABLED)

def manual_command():
      ip_input =input_ip_address.get(1.0,10.0)
      username =input_username.get()
      password =input_password.get()
      ip_list =ip_input.split()
      pprint(ip_list)
      command_input =manual_cmd_entry.get()
    #   list_cmd =[command_input]
    #   list_cmd=command_input.split("\t")
      print(command_input)
      for ip in ip_list:
              pprint(ip)
              try:
                 with HuaweiTelnet(ip, username, password, prompt="<") as switch:
                     """functia data indeplineste operatia de conectare la echipament si trimiterea comenzilor pe echipament si afisarea 
                     rezultatului"""
                     result_text.configure(state=NORMAL)
                     result_text.insert(END , f"======================================={ip}=========================================\n")
                     command =switch.send_show_command(command_input)
                     result_text.insert(END ,command )
                     result_text.insert(END,"\n==========================================================================================\n")
                     result_text.configure(state=DISABLED)
                     logfile( ip=ip ,command=command)
              except EOFError as error:
                """exceptia se indeplineste doar in cazul in care nu este acces la echipamemt sau date de logare sunt incorecte """
                result_text.configure(state=NORMAL)
                result_text.insert(END,f"Authentication failed on IP:{ip}\t{error}\n")
                result_text.configure(state=DISABLED)
              except socket.timeout as timeout:
               result_text.configure(state=NORMAL)
               result_text.insert(END,f"Could Not Posible Connect on IP:{ip}\t{timeout}\n") 
               result_text.configure(state=DISABLED)

def log_file():
    """acesta functie este creata pentru a informa utilizatorul privind activarea salvarii logurilor de pe echipament sau dezactivarea"""
    if logvar.get() == "1":
         messagebox.showinfo(title="Info", message="Activat cu Success")
    elif logvar.get() =="0":
         messagebox.showinfo(title="Info", message="Dezactivat cu Success")

def logfile(ip, command):
    if logvar.get() == "1":
         folder ="logs"
         if os.path.exists("logs"):
          print("folderul este deja creat ")#acest print este creat pentru a vizualiza in regim de test daca functioneaza instructiunea
          name_files=datetime.now().strftime(f'%d.%m.%Y_{ip}')# in loc de ip  a fost scoasa temporara  formula pentru oara %H_%M
          full_file_name=os.path.join(folder,name_files)
          with open (f"{full_file_name}.txt","a" , encoding="utf-8") as log_file:
              result_text.configure(state=NORMAL)
              log_file.write("#{0} {1}\n\n\n".format(datetime.now().strftime("%Y-%m-%d %H:%M"),f"\n{command}"))
              result_text.configure(state=DISABLED)
              log_file.close
         else:
              os.makedirs(folder)
              name_files=datetime.now().strftime(f'%d.%m.%Y_{ip}')# in loc de ip formula pentru oara %H_%M
              full_file_name=os.path.join(folder,name_files)
              with open (f"{full_file_name}.txt","a" , encoding="utf-8") as log_file:
                    result_text.configure(state=NORMAL)
                    log_file.write("#{0} {1}\n\n\n".format(datetime.now().strftime("%Y-%m-%d %H:%M"),f"\n{command}"))
                    result_text.configure(state=DISABLED)
                    log_file.close

    elif logvar.get() == "0":
         print("nimic nu se salveaza")

#parametrii pentru threading functions
def threading_sw_info():
    switch =Thread(target=switch_info)
    switch.start()
    print("se executa in threading")

def threading_sw_config():
    sw_config=Thread(target=switch_current_config)
    sw_config.start()

def threading_sw_interface_all():
   interface_all =Thread(target=switch_interface_all)
   interface_all.start()

def threading_sw_interface():
    interface_thread=Thread(target=switch_interface)
    interface_thread.start()

def threading_sw_igmp():
     igmp_info_thread =Thread(target=switch_igmp_info)
     igmp_info_thread.start()

def threading_sw_dhcp_info():
     dhcp_snoop_thread =Thread(target=switch_dhcp_snopping)
     dhcp_snoop_thread.start()
def threading_mac_address_interface():
     mac_address_thread =Thread(target=switch_mac_add_interface)
     mac_address_thread.start()

def threading_interface_config():
     interface_config_thread =Thread(target=switch_interface_config)
     interface_config_thread.start()

def threading_vlans_all():
     all_vlan_thread =Thread(target=switch_info_all_vlans)
     all_vlan_thread.start()

def threading_mac_switch():
     mac_switch_thread =Thread(target=switch_mac_address_info)
     mac_switch_thread.start()

def threading_vlan():
     vlan_interface_thread = Thread(target=switch_info_vlan)
     vlan_interface_thread.start()
def threading_mac_address_vlan():
    vlan_mac_address =Thread(target=mac_address_vlan)
    vlan_mac_address.start()
def threading_interface_description():
     interface_description_thread =Thread(target=switch_interface_description)
     interface_description_thread.start()
    
def threading_manual_cmd():
    command_thread =Thread(target=manual_command)
    command_thread.start()

input_panel = ttk.Labelframe(window , text= ' Input_Panel',  width=100,  height=20 )
input_panel.grid(row= 0 , column=0 , sticky='nsew', padx=10 , pady= 10 , )
ip_address = ttk.Labelframe(input_panel , text= ' Enter IP address(es)',  width=100,  height=10 ,)
ip_address.grid(row= 1 , column=0 ,sticky='n',padx= 10 , pady=10)
input_ip_address = Text(ip_address , height=10, width=25 ,  )
input_ip_address.grid(row= 0 , column=0 , sticky='ne', padx=15, pady=15) 
scrolbar = Scrollbar(ip_address,orient=VERTICAL)
scrolbar.grid(row=0, column=int(0.5), sticky='NSE', padx=15 , pady=15)

input_ip_address.config(yscrollcommand=scrolbar.set)
scrolbar.config(command=input_ip_address.xview)
swinfo=tk.Button(ip_address, text="SwInfo" ,width=10, relief=SOLID ,activeforeground='red' ,cursor='hand2', command=threading_sw_info)
swinfo.grid(row=10 , column=0 , sticky='sw',  padx=5 , pady=5 ,)

mac_info=tk.Button(ip_address, text="MAC-switch" ,width=10, relief=SOLID ,activeforeground='red' ,cursor='hand2', command=threading_mac_switch)#bg='black',fg='green', borderless=1
mac_info.grid(row=10 , column=1 , columnspan=1, sticky='sw', padx=5 , pady=5)

button_mac_vlan=tk.Button(ip_address, text='MAC-Vlan' ,width=10, relief=SOLID , command=threading_mac_address_vlan)
button_mac_vlan.grid(row=10 , column=2 , columnspan=1, sticky='sw', padx=5 , pady=5)
logvar =StringVar()
variable = IntVar()
logvar.set(0)
save_log= tk.Checkbutton(ip_address, text = 'Logfile' , relief=FLAT,state='active' , onvalue=1 , offvalue=0 ,variable=logvar, command=log_file)
save_log.grid(row=10 , column=int(0.99) , sticky='e', padx=5 , pady=5)

 
username = StringVar()
password = StringVar()

authencation = ttk.Labelframe(input_panel , text='Authentication' ,width= 200, height= 400, )
authencation.grid(row=1 , column=1 , padx=10,sticky='we' , pady=20  )
#numele meu Petru
username_label = tk.Label(authencation, text="Username:" ,font='Arial 10 bold', )
input_username = tk.Entry(authencation ,foreground='green',relief=SUNKEN ,  width=21 , textvariable=username )

password_label = ttk.Label(authencation, text="Password:" , font='Arial 10 bold')
input_password = tk.Entry(authencation , show= '*' , relief=SUNKEN ,  width=21 ,textvariable=password ,)

input_username.grid(row=int(1.6) , column=int(1) ,  sticky='n', padx=15, pady=15)
input_password.grid(row=2 , column=1 , sticky='n', padx=15, pady= 15)

username_label.grid(row=int(1.5), column= int(0.5) , columnspan=1,  sticky='nw',padx=15, pady=15 )
password_label.grid(row=int(2.5), column= int(0.5), sticky='nw', padx=15, pady=15 )

Switch_Actions = ttk.Labelframe (input_panel ,text='Switch Actions',width= 300 , height= 400, )
Switch_Actions.grid(row=1 , column=2 , padx=20 , pady= 20 )
chose_vlan = ttk.Labelframe(window, )

var = IntVar()
button_show_config = tk.Button(Switch_Actions, text = 'Show Config Switch' ,relief=SOLID ,activeforeground='red' ,cursor='hand2', command=threading_sw_config)
button_show_config.grid(row=3 , column=0,  sticky='we',padx=5, pady=10 ,)
# button_show_vlan = tk.Button(Switch_Actions, text = 'Show vlan' ,relief=SOLID)
# button_show_vlan.grid(row=3 , column=1,  sticky='w',  pady=10 ,)

button_show_dhcp = tk.Button(Switch_Actions, text = 'Show DHCP-Snooping',width=10 ,relief=SOLID ,activeforeground='red' ,cursor='hand2', command=threading_sw_dhcp_info)
button_show_dhcp.grid(row=3 , column=1,  sticky='we',padx=5, pady=10 ,)

button_show_interface_all =tk.Button(Switch_Actions, text ='show interface brief' , relief=SOLID ,activeforeground='red' ,cursor='hand2', command=threading_sw_interface_all)
button_show_interface_all.grid(row=3 ,column =2,sticky='we',padx=5,  pady=10,)
button_show_interface=tk.Button(Switch_Actions, text = 'show interface switch' , relief=SOLID ,activeforeground='red' ,cursor='hand2', command=threading_sw_interface)
button_show_interface.grid(row=3 ,column =3,sticky='we',padx=5,  pady=10,)

button_config_interface= tk.Button(Switch_Actions, text = 'show config interface' ,relief=SOLID ,activeforeground='red' ,cursor='hand2', command=threading_interface_config )
button_config_interface.grid(row=3 , column=4 , sticky='we',padx=5,  pady=10)
#voinescu hincesti
button_show_vlans= tk.Button(Switch_Actions, text = 'Show vlan (ex 1666/2525)' ,relief=SOLID ,activeforeground='red' ,cursor='hand2', command=threading_vlan)
mac_address_info=tk.Button(Switch_Actions, text="Mac-info Interface" , relief=SOLID ,activeforeground='red' ,cursor='hand2',command=threading_mac_address_interface)
mac_address_info.grid(row=4 , column=0 , columnspan=1, sticky='we',padx=5,  pady=5)
button_show_vlans.grid(row=4 , column=1 , sticky='we',padx=5,  pady=5)
button_show_all_vlan= tk.Button(Switch_Actions, text = 'Show  all vlan switch' ,relief=SOLID ,activeforeground='red' ,cursor='hand2', command=threading_vlans_all)
button_show_all_vlan.grid(row=4 , column=2 , sticky='we',padx=5,  pady=5)

button_interface_descr=tk.Button(Switch_Actions, text = 'Show interface description' ,relief=SOLID ,activeforeground='red' ,cursor='hand2', command=threading_interface_description )
button_interface_descr.grid(row=4 , column=3 ,sticky='we', padx=5, pady=5)
button_show_igmp= tk.Button(Switch_Actions, text = 'Show IGMP-Snooping' ,relief=SOLID ,activeforeground='red' ,cursor='hand2', command=threading_sw_igmp)
button_show_igmp.grid(row=4 , column=4 , sticky='we',  pady=10)
vlans  = ttk.Label(Switch_Actions , text='Vlans:' ,width=10 ,font='Arial 10 bold')
vlans.grid(row=0, column= 0 ,  sticky='w', pady=10 )
chose_vlan  = tk.Entry(Switch_Actions,relief=SUNKEN ,  width=21)
chose_vlan.grid(row=0 , column=1 ,   sticky='n', padx=20, pady=20)

interface_eth = ttk.Label(Switch_Actions , text='Interface:' ,width=12,font='Arial 10 bold')
interface_eth.grid(row=1, column= 0 ,  sticky='w',padx=5, pady=10 )
chose_interface_eth  = tk.Entry(Switch_Actions,relief=SUNKEN ,  width=21)
chose_interface_eth.grid(row=1 , column=2 ,   sticky='we', padx=20, pady=20)
interface_list = ["Ethernet", "GigabitEthernet","XGigabitEthernet"]
interface_string = tk.StringVar(Switch_Actions)
interface_string.set("Select interface")
interface_menu =tk.OptionMenu(Switch_Actions, interface_string, *interface_list ,)
interface_menu.grid(row=1 , column=1  , sticky='we' )

manual_cmd=ttk.Label(Switch_Actions , text='Manual Command:' ,width=17,font='Arial 10 bold')
manual_cmd.grid(row=2 , column=0 ,sticky='w',padx=5, pady=10)
manual_cmd_entry=tk.Entry(Switch_Actions,relief=SUNKEN ,  width=21)
manual_cmd_entry.grid(row=2 , column=1 ,sticky='we',padx=5, pady=10)
send_cmd =PhotoImage(name="SEND",file="./photo/send.png")
manual_cmd_button=tk.Button(Switch_Actions, text = 'Send',height=20 ,relief=SOLID ,activeforeground='red' ,cursor='hand2',command=threading_manual_cmd , image=send_cmd,compound=RIGHT)
manual_cmd_button.grid(row=2 , column=2 ,sticky='w',padx=5, pady=10)

# interface_gig = ttk.Label(Switch_Actions , text='Interface GE:' ,width=11,font='Arial 10 bold')
# interface_gig.grid(row=2, column=0 ,  sticky='w',padx=10, pady=10 )
# chose_interface_gig  = tk.Entry(Switch_Actions,relief=SUNKEN ,  width=21)
# chose_interface_gig.grid(row=2 , column=1 ,   sticky='n', padx=20, pady=20)
result_for_command = ttk.Labelframe(window , text= ' Results',  width=700,  height=500 ,)
result_for_command.grid(row=3 , column=0 , columnspan=1 ,sticky='w' ,padx=25 ,)

#result_text = tk.Listbox(result_for_command  , activestyle=UNDERLINE , width= 150 , height=36 , selectmode=EXTENDED , takefocus=NORMAL, foreground="black" ,relief=SOLID)
result_text=Text(result_for_command ,state=DISABLED, width= 145 , height=34 , foreground="black",relief=SOLID)
result_text.grid(row=0 , column=2 , columnspan=4 ,sticky='se', padx= 30 )
clear_res =PhotoImage(name="Clear",file="./photo/clear.png")
clear_result =tk.Button(result_for_command , text='Clear' ,relief=SOLID, command=delete , compound=RIGHT ,image=clear_res)
clear_result.grid(row=1, column=3 , sticky='s' , ipadx=10)

#results1 = Text(results , state='disabled' , width= 100 , height=36)
#results1.grid(row=0 , column=2 , columnspan=4 ,sticky='se', padx= 50 ) 

scrolbar = Scrollbar(result_for_command,orient=VERTICAL)
scrolbar.grid(row=0, column=1, sticky= 'NS')
result_text.config(yscrollcommand=scrolbar.set)
scrolbar.config(command=result_text.yview)

scrolbar = Scrollbar(result_for_command,orient=HORIZONTAL ,)
scrolbar.grid(row=2, column=0,columnspan=8,  sticky= 'SWSE')
result_text.config(xscrollcommand=scrolbar.set)
scrolbar.config(command=result_text.yview)
window_img =PhotoImage(name="window",file="./photo/newwindow.png")
newwindow_button = tk.Button(result_for_command , text='New',  command=open_window , relief=SOLID,compound=RIGHT ,image=window_img)
newwindow_button.grid(row=1, column=4 , sticky='se' , ipadx=10 , )
#hincesti
mainmenu = Menu(window) 
window.config(menu=mainmenu) 
text = Text(width=140, height=35)
filemenu = Menu(mainmenu, tearoff=0)
def insert_text():
    try:
         file_name = fd.askopenfilename(
            filetypes=(("TXT files", "*.txt"),
                                            ))
         with open(file_name, 'r' ,encoding="utf-8") as file_read:
          for read in file_read:
           result_text.configure(state=NORMAL)
           read =file_read.read()
           result_text.insert(END,read)
           result_text.configure(state=DISABLED)
           file_read.close()
    except FileNotFoundError:
        print("Nu a fost Posibil de deschis fisierul")
open_file =PhotoImage(file="./photo/open.png" ,)
filemenu.add_command(label="Open", command=insert_text  , image=open_file , compound=TOP)
def extract_text():
    try:
        file_name = fd.asksaveasfilename(
            filetypes=(("TXT files", "*.txt"),
                       ("HTML files", "*.html"),
                       ("All files", "*.*")))
        with open(file_name, 'w') as filename:
         result_text.configure(state=NORMAL)
         filename.write(str(result_text.get(1.0,END)))
         filename.write('\n')
         filename.close()
         messagebox.showinfo("Save", f"Fisierul a fost Salvat cu success")
         result_text.configure(state=DISABLED)
    except FileNotFoundError:
        print("Fiserul nu a fost Salvat")
save =PhotoImage(file="./photo/save.png" ,)
filemenu.add_command(label=" Save..", command=extract_text ,image=save , compound=TOP)
def quit():
    window.destroy()
exit_app =PhotoImage(file="./photo/exit.png" ,)
filemenu.add_command(label="Exit", command=window.destroy ,image=exit_app ,compound=TOP)
helpmenu = Menu(mainmenu, tearoff=0)
def show_info_app():
   messagebox.showinfo("Info App","Aplicatia ese predestinata pentru utilizare in mentenanta Echipamentelor FTTx\nLa moment Aplicatia este in curs de realizare")
  
def how_work_app():
    messagebox.showinfo("How Work App", "Aici va fi informatie despre utilizarea Aplicatiei la moment acest proces este in lucru ")
    root = tk.Tk()
    root.geometry('1024x640')
    root.title('Command Info')
    app_info = ttk.Notebook(root , )
    app_info.grid(row=0 , column=1 ,pady=10)

    button_info = ttk.Frame(app_info, width=600, height=740 ,)
    app_info.add(button_info, text='General Information')
    command_vlan = tk.Label(app_info, width=150, height=60 , text="command vlan")
    command_vlan.grid(row=3 ,column=1  , padx=10 , pady=40)
    vlan_text=tk.Text(command_vlan ,state='disabled', width= 73 , height=3 , foreground="white" ,background="black",relief='solid')
    vlan_text.grid(row=4 , column=1 , padx=5 ,)
    vlan_text.configure(state='normal')
    vlan_text.insert(1.0 , "butonul show vlan  va arata pe ce porturi este vlanul configurat  trebuie doar sa indicati vlanul si deja datele de logare")
    vlan_text.configure(state='disabled')

    dhcp_snooping_info=tk.Text(command_vlan ,state='disabled', width= 73 , height=3 , foreground="white" ,relief='solid' , background="black")
    dhcp_snooping_info.grid(row=5 , column=1 , padx=5 ,)
    dhcp_snooping_info.configure(state='normal')
    dhcp_snooping_info.insert(1.0 , "butonul show dhcp snooping  va arata  adresa ip a abonatului, in casuta de linga  interface trebuie doar sa indicati interface abonat ex 0/0/1 si deja datele de logare")
    dhcp_snooping_info.configure(state='disabled')
information_img =PhotoImage(file="./photo/information.png" ,)
helpmenu.add_command(label="Info App", command=show_info_app , image=information_img , compound=BOTTOM)
help_img =PhotoImage(file="./photo/help.png" ,)
helpmenu.add_command(label="How Work App" , command=how_work_app,image=help_img , compound=BOTTOM)
 #09.09.09
mainmenu.add_cascade(label="File",
                     menu=filemenu)
mainmenu.add_cascade(label=" Help",
                     menu=helpmenu)
def on_closeicon():
    if messagebox.askokcancel("Quit", "Doriti sa esiti din program?"):
        window.destroy()
window.protocol("WM_DELETE_WINDOW", on_closeicon)
#petru
window.mainloop()
