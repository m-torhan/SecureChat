#! /usr/bin/env python
#  -*- coding: utf-8 -*-

import os
import sys
import datetime
import re

import tkinter as tk
import tkinter.ttk as ttk

from connection import *
from debug_tools import *

WINDOW_WIDTH = 1024
WINDOW_HEIGHT = 768
TAB_WIDTH = 256
TAB_HEIGHT = 24
PADDING = 8
MAX_TABS = 16
LINE_MAX_CHARS = 64

IP_PORT_REGEX = r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]):[0-9]+$'

def destroy_SecureChatTopLevel():
    global w
    w.destroy()
    w = None

def messages_to_listbox(messages, listbox):
    for message in messages:
        prefix =  ''
        if type(message.time) == datetime.datetime:
            prefix += message.time.strftime('[%y-%m-%d %H:%M:%S] ')

        if message.type == MessageFlag.INFO:
            prefix += '- '
        if message.type == MessageFlag.RECEIVED:
            prefix += '< '
        if message.type == MessageFlag.SENT:
            prefix += '> '

        for i in range((len(message.text) + LINE_MAX_CHARS - 1)//LINE_MAX_CHARS):
            if i == 0:
                listbox.insert(tk.END, prefix + message.text[i*LINE_MAX_CHARS:min((i + 1)*LINE_MAX_CHARS, len(message.text))])
            else:
                listbox.insert(tk.END, ' '*len(prefix) + message.text[i*LINE_MAX_CHARS:min((i + 1)*LINE_MAX_CHARS, len(message.text))])

class Tab(object):
    def __init__(self, button, button_close, content=[], connection=None):
        self.button = button
        self.button.pack()

        self.button_close = button_close
        if self.button_close  is not None:
            self.button_close.pack()

        self.connection = connection
        self.content = content
        if self.connection is not None:
            self.content = connection.chat_history

class SecureChatApp(object):
    def __init__(self, root=None):
        '''This class configures and populates the toplevel window.
           top is the toplevel containing window.'''

        self.tabs = []
        self.selected_tab = -1
        self.tab_messages_count = 0

        self.info_log = []

        self.log('App start.')

        self.__listener = None
        
        _bgcolor = '#d9d9d9'  # X11 color: 'gray85'
        _fgcolor = '#000000'  # X11 color: 'black'
        _compcolor = '#d9d9d9' # X11 color: 'gray85'
        _ana1color = '#d9d9d9' # X11 color: 'gray85'
        _ana2color = '#ececec' # Closest X11 color: 'gray92'
        self.style = ttk.Style()
        if sys.platform == "win32":
            self.style.theme_use('winnative')
        self.style.configure('.',background=_bgcolor)
        self.style.configure('.',foreground=_fgcolor)
        self.style.map('.',background=
            [('selected', _compcolor), ('active',_ana2color)])

        self.root = root

        def on_destroy():
            if self.__listener is not None:
                for conn in self.__listener.connections:
                    conn.close()

                self.__listener.close()

            for tab in self.tabs:
                tab.connection.close()
            self.root.destroy()

        self.root.protocol("WM_DELETE_WINDOW", on_destroy)

        self.root.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}+256+256")
        self.root.resizable(0,  0)
        self.root.title("SecureChat")
        self.root.configure(background="#d9d9d9")

        self.chat_scrolled_listbox = ScrolledListBox(self.root)
        self.chat_scrolled_listbox.place(x=TAB_WIDTH + 2*PADDING, y=PADDING, width=WINDOW_WIDTH - TAB_WIDTH - 3*PADDING, height=WINDOW_HEIGHT - TAB_HEIGHT - 3*PADDING)
        self.chat_scrolled_listbox.configure(background="white")
        self.chat_scrolled_listbox.configure(cursor="xterm")
        self.chat_scrolled_listbox.configure(disabledforeground="#a3a3a3")
        self.chat_scrolled_listbox.configure(font="TkFixedFont")
        self.chat_scrolled_listbox.configure(foreground="black")
        self.chat_scrolled_listbox.configure(highlightbackground="#d9d9d9")
        self.chat_scrolled_listbox.configure(highlightcolor="#d9d9d9")
        self.chat_scrolled_listbox.configure(selectbackground="blue")
        self.chat_scrolled_listbox.configure(selectforeground="white")

        self.chat_entry = tk.Entry(self.root)
        self.chat_entry.place(x=TAB_WIDTH + 2*PADDING, y=WINDOW_HEIGHT - TAB_HEIGHT - PADDING, width=WINDOW_WIDTH - TAB_WIDTH - 3*PADDING, height=TAB_HEIGHT)
        self.chat_entry.configure(background="white")
        self.chat_entry.configure(disabledforeground="#a3a3a3")
        self.chat_entry.configure(font="TkFixedFont")
        self.chat_entry.configure(foreground="#000000")
        self.chat_entry.configure(insertbackground="black")

        def on_chat_entry_finished(event=None):
            self.send_message(self.chat_entry.get())
            self.chat_entry.delete(0, 'end')
        self.chat_entry.bind('<Return>', on_chat_entry_finished)

        self.info_tab_button = tk.Button(self.root)
        self.info_tab_button.place(x=PADDING, y=PADDING, width=TAB_WIDTH/2 - PADDING/2, height=TAB_HEIGHT)
        self.info_tab_button.configure(activebackground="#ececec")
        self.info_tab_button.configure(activeforeground="#000000")
        self.info_tab_button.configure(background="#d9d9d9")
        self.info_tab_button.configure(disabledforeground="#a3a3a3")
        self.info_tab_button.configure(foreground="#000000")
        self.info_tab_button.configure(highlightbackground="#d9d9d9")
        self.info_tab_button.configure(highlightcolor="black")
        self.info_tab_button.configure(pady="0")
        self.info_tab_button.configure(text='''Info''')
        self.info_tab_button.configure(command=lambda: self.change_tab(0))

        self.new_tab_button = tk.Button(self.root, command=self.create_new_tab_form)
        self.new_tab_button.place(x=TAB_WIDTH/2 + 3*PADDING/2, y=PADDING, width=TAB_WIDTH/2 - PADDING/2, height=TAB_HEIGHT)
        self.new_tab_button.configure(activebackground="#ececec")
        self.new_tab_button.configure(activeforeground="#000000")
        self.new_tab_button.configure(background="#d9d9d9")
        self.new_tab_button.configure(disabledforeground="#a3a3a3")
        self.new_tab_button.configure(foreground="#000000")
        self.new_tab_button.configure(highlightbackground="#d9d9d9")
        self.new_tab_button.configure(highlightcolor="black")
        self.new_tab_button.configure(pady="0")
        self.new_tab_button.configure(text='''Connect''')
        self.new_tab_button.configure(state='disabled')

        self.new_tab_form = None
        self.select_hostname_form  = None
        self.change_tab(0)
        self.create_select_hostname_form()

        def loop():
            self.refresh_tab()
            
            if self.__listener is not None and self.__listener.connections:
                self.open_new_tab(self.__listener.connections.pop())

            self.root.after(100, loop)

        loop()
    
    def start_listening(self, hostname):
        self.select_hostname_form.attributes("-topmost", 0)
        self.root.attributes("-topmost", 1)
        self.select_hostname_form.destroy()

        self.__listener = Listener(hostname)
        hostname, port = self.__listener.address
        self.log(f'Listening on: {hostname}:{port}.')

        self.new_tab_button.configure(state='normal')

    def log(self, text):
        self.info_log.append(Message(MessageFlag.INFO, datetime.datetime.now(), text))

    def change_tab(self, tab):
        if tab is not self.selected_tab:
            self.selected_tab = tab
            if tab == 0:
                self.chat_scrolled_listbox.delete(0, tk.END)
                messages_to_listbox(self.info_log, self.chat_scrolled_listbox)
            elif isinstance(tab, Tab):
                self.chat_scrolled_listbox.delete(0, tk.END)
                messages_to_listbox(tab.content, self.chat_scrolled_listbox)
    
    def refresh_tab(self):
        if self.selected_tab == 0:
            content = self.info_log
        else:
            content = self.selected_tab.content

            if self.selected_tab.connection.closed and not self.selected_tab.connection.close_handled:
                self.selected_tab.connection.close_handled = True
                hostname, port = self.selected_tab.connection.remote_address
                self.log(f'Connection with {hostname}:{port} lost.')
                self.selected_tab.connection.chat_history.append(Message(MessageFlag.INFO, datetime.datetime.now(), f'Connection lost.'))

        if self.tab_messages_count != len(content):
            self.tab_messages_count = len(content)
            tab = self.selected_tab
            self.selected_tab = -1
            self.change_tab(tab)
            if not self.chat_scrolled_listbox.get_scroll_pressed():
                self.chat_scrolled_listbox.see(tk.END)

    def create_select_hostname_form(self):
        self.select_hostname_form = tk.Toplevel(self.root)
        self.select_hostname_form.geometry(f"{TAB_WIDTH + 2*PADDING}x{2*TAB_HEIGHT + 3*PADDING}+300+300")
        self.select_hostname_form.resizable(0,  0)
        self.select_hostname_form.title('Select hostname')
        self.root.attributes("-topmost", 0)
        self.select_hostname_form.attributes("-topmost", 1)

        self.hostname_string_var = tk.StringVar(self.select_hostname_form)
        self.hostname_string_var.set(socket.gethostbyname_ex(socket.gethostname())[-1][0])
        self.select_hostname_form_option_menu = tk.OptionMenu(self.select_hostname_form, self.hostname_string_var, *socket.gethostbyname_ex(socket.gethostname())[-1])
        self.select_hostname_form_option_menu.place(x=PADDING, y=PADDING, width=TAB_WIDTH, height=TAB_HEIGHT)

        self.select_hostname_form_button = tk.Button(self.select_hostname_form)
        self.select_hostname_form_button.configure(text='Set')
        self.select_hostname_form_button.configure(command=lambda: self.start_listening(self.hostname_string_var.get()))
        self.select_hostname_form_button.place(x=PADDING, y=1*TAB_HEIGHT + 1*PADDING, width=TAB_WIDTH, height=TAB_HEIGHT)

    def create_new_tab_form(self):
        self.new_tab_button.configure(state='disabled')

        self.new_tab_form = tk.Toplevel(self.root)
        self.new_tab_form.geometry(f"{TAB_WIDTH + 2*PADDING}x{3*TAB_HEIGHT + 4*PADDING}+300+300")
        self.new_tab_form.resizable(0,  0)
        self.new_tab_form.title('New connection')
        self.root.attributes("-topmost", 0)
        self.new_tab_form.attributes("-topmost", 1)

        def on_destroy():
            self.new_tab_button.configure(state='normal')
            self.new_tab_form.destroy()
        self.new_tab_form.protocol("WM_DELETE_WINDOW", on_destroy)

        self.new_tab_form_label = tk.Label(self.new_tab_form)
        self.new_tab_form_label.configure(text='Enter ip address')
        self.new_tab_form_label.place(x=PADDING, y=PADDING, width=TAB_WIDTH, height=TAB_HEIGHT)

        self.new_tab_form_entry = tk.Entry(self.new_tab_form)
        self.new_tab_form_button = tk.Button(self.new_tab_form)

        def validate_entry(sv):
            if re.match(IP_PORT_REGEX, sv.get()) is not None:
                self.new_tab_form_button.configure(state='normal')
            else:
                self.new_tab_form_button.configure(state='disabled')

        stringvar = tk.StringVar()
        stringvar.trace("w", lambda name, index, mode, sv=stringvar: validate_entry(stringvar))
        self.new_tab_form_entry.configure(textvariable=stringvar)
        self.new_tab_form_entry.place(x=PADDING, y=TAB_HEIGHT + 2*PADDING, width=TAB_WIDTH, height=TAB_HEIGHT)

        self.new_tab_form_button.configure(state='disabled')
        self.new_tab_form_button.configure(text='Connect')
        self.new_tab_form_button.configure(command=lambda: self.open_new_connection(self.new_tab_form_entry.get()))
        self.new_tab_form_button.place(x=PADDING, y=2*TAB_HEIGHT + 3*PADDING, width=TAB_WIDTH, height=TAB_HEIGHT)

    def open_new_connection(self, address):
        hostname, port = address.split(':')
        conn = Connection.connect(hostname, int(port))

        self.open_new_tab(conn, hostname, port)

    def open_new_tab(self, conn, hostname=None, port=None):
        self.new_tab_button.configure(state='normal')
        if self.new_tab_form is not None:
            self.new_tab_form.destroy()

        if hostname is None and port is None:
            hostname, port = conn.remote_address

        tab_button = tk.Button(self.root)
        tab_button_close = tk.Button(self.root)

        tab = Tab(tab_button, tab_button_close, [], conn)

        tab_button.place(x=PADDING, y=(len(self.tabs) + 1)*(TAB_HEIGHT + PADDING) + PADDING, width=TAB_WIDTH - TAB_HEIGHT, height=TAB_HEIGHT)
        tab_button.configure(activebackground="#ececec")
        tab_button.configure(activeforeground="#000000")
        tab_button.configure(background="#d9d9d9")
        tab_button.configure(disabledforeground="#a3a3a3")
        tab_button.configure(foreground="#000000")
        tab_button.configure(highlightbackground="#d9d9d9")
        tab_button.configure(highlightcolor="black")
        tab_button.configure(pady="0")
        tab_button.configure(text=f'{hostname}:{port}')
        tab_button.configure(command=lambda: self.change_tab(tab))
        
        tab_button_close.place(x=TAB_WIDTH - TAB_HEIGHT + PADDING, y=(len(self.tabs) + 1)*(TAB_HEIGHT + PADDING) + PADDING, width=TAB_HEIGHT, height=TAB_HEIGHT)
        tab_button_close.configure(activebackground="#ececec")
        tab_button_close.configure(activeforeground="#000000")
        tab_button_close.configure(background="#d9d9d9")
        tab_button_close.configure(disabledforeground="#a3a3a3")
        tab_button_close.configure(foreground="#000000")
        tab_button_close.configure(highlightbackground="#d9d9d9")
        tab_button_close.configure(highlightcolor="black")
        tab_button_close.configure(pady="0")
        tab_button_close.configure(text='X')
        tab_button_close.configure(command=lambda: self.close_tab(tab))

        self.tabs.append(tab)

        self.info_log.append(Message(MessageFlag.INFO, datetime.datetime.now(), f'New connection with {hostname}:{port}'))

        self.change_tab(tab)

    def close_tab(self, tab):
        if isinstance(tab, Tab):
            tab.button.destroy()
            tab.button_close.destroy()
            tab.connection.close()
            self.tabs.remove(tab)
            self.change_tab(0)

            hostname, port = tab.connection.remote_address
            self.log(f'Closed connection with {hostname}:{port}.')
            
            for i, tab in enumerate(self.tabs):
                tab.button.place(x=PADDING, y=(i + 1)*(TAB_HEIGHT + PADDING) + PADDING, width=TAB_WIDTH - TAB_HEIGHT, height=TAB_HEIGHT)
                tab.button_close.place(x=TAB_WIDTH - TAB_HEIGHT + PADDING, y=(i + 1)*(TAB_HEIGHT + PADDING) + PADDING, width=TAB_HEIGHT, height=TAB_HEIGHT)
    
    def check_max_tab_exceed(self):
        if len(self.tabs) >= MAX_TABS:
            self.new_tab_button.configure(state='disabled')
        else:
            self.new_tab_button.configure(state='normal')

    def send_message(self, text):
        if isinstance(self.selected_tab, Tab):
            self.selected_tab.connection.send_message(text)

# The following code is added to facilitate the Scrolled widgets you specified.
class AutoScroll(object):
    '''Configure the scrollbars for a widget.'''
    def __init__(self, master):
        #  Rozen. Added the try-except clauses so that this class
        #  could be used for scrolled entry widget for which vertical
        #  scrolling is not supported. 5/7/14.
        try:
            self.vsb = ttk.Scrollbar(master, orient='vertical', command=self.yview)
        except:
            pass
        self.hsb = ttk.Scrollbar(master, orient='horizontal', command=self.xview)
        try:
            self.configure(yscrollcommand=self._autoscroll(self.vsb))
        except:
            pass
        self.configure(xscrollcommand=self._autoscroll(self.hsb))
        self.grid(column=0, row=0, sticky='nsew')
        try:
            self.vsb.grid(column=1, row=0, sticky='ns')
        except:
            pass
        self.hsb.grid(column=0, row=1, sticky='ew')
        master.grid_columnconfigure(0, weight=1)
        master.grid_rowconfigure(0, weight=1)
        # Copy geometry methods of master  (taken from ScrolledText.py)
        methods = tk.Pack.__dict__.keys() | tk.Grid.__dict__.keys() | tk.Place.__dict__.keys()
        for meth in methods:
            if meth[0] != '_' and meth not in ('config', 'configure'):
                setattr(self, meth, getattr(master, meth))
        
        self.scroll_pressed = False
        self.hsb.bind("<Button-1>", lambda e: self.set_scroll_pressed(True))
        self.vsb.bind("<Button-1>", lambda e: self.set_scroll_pressed(True))
        self.hsb.bind("<ButtonRelease-1>", lambda e: self.set_scroll_pressed(False))
        self.vsb.bind("<ButtonRelease-1>", lambda e: self.set_scroll_pressed(False))

    def get_scroll_pressed(self):
        return self.scroll_pressed

    def set_scroll_pressed(self, value):
        self.scroll_pressed =  value

    @staticmethod
    def _autoscroll(sbar):
        '''Hide and show scrollbar as needed.'''
        def wrapped(first, last):
            first, last = float(first), float(last)
            if first <= 0 and last >= 1:
                sbar.grid_remove()
            else:
                sbar.grid()
            sbar.set(first, last)
        return wrapped

    def __str__(self):
        return str(self.master)

def _create_container(func):
    '''Creates a ttk Frame with a given master, and use this new frame to
    place the scrollbars and the widget.'''
    def wrapped(cls, master, **kw):
        container = ttk.Frame(master)
        container.bind('<Enter>', lambda e: _bound_to_mousewheel(e, container))
        container.bind('<Leave>', lambda e: _unbound_to_mousewheel(e, container))
        return func(cls, container, **kw)
    return wrapped

class ScrolledListBox(AutoScroll, tk.Listbox):
    '''A standard Tkinter Listbox widget with scrollbars that will
    automatically show/hide as needed.'''
    @_create_container
    def __init__(self, master, **kw):
        tk.Listbox.__init__(self, master, **kw)
        AutoScroll.__init__(self, master)
    def size_(self):
        sz = tk.Listbox.size(self)
        return sz

import platform
def _bound_to_mousewheel(event, widget):
    child = widget.winfo_children()[0]
    if platform.system() == 'Windows' or platform.system() == 'Darwin':
        child.bind_all('<MouseWheel>', lambda e: _on_mousewheel(e, child))
        child.bind_all('<Shift-MouseWheel>', lambda e: _on_shiftmouse(e, child))
    else:
        child.bind_all('<Button-4>', lambda e: _on_mousewheel(e, child))
        child.bind_all('<Button-5>', lambda e: _on_mousewheel(e, child))
        child.bind_all('<Shift-Button-4>', lambda e: _on_shiftmouse(e, child))
        child.bind_all('<Shift-Button-5>', lambda e: _on_shiftmouse(e, child))

def _unbound_to_mousewheel(event, widget):
    if platform.system() == 'Windows' or platform.system() == 'Darwin':
        widget.unbind_all('<MouseWheel>')
        widget.unbind_all('<Shift-MouseWheel>')
    else:
        widget.unbind_all('<Button-4>')
        widget.unbind_all('<Button-5>')
        widget.unbind_all('<Shift-Button-4>')
        widget.unbind_all('<Shift-Button-5>')

def _on_mousewheel(event, widget):
    if platform.system() == 'Windows':
        widget.yview_scroll(-1*int(event.delta/120),'units')
    elif platform.system() == 'Darwin':
        widget.yview_scroll(-1*int(event.delta),'units')
    else:
        if event.num == 4:
            widget.yview_scroll(-1, 'units')
        elif event.num == 5:
            widget.yview_scroll(1, 'units')

def _on_shiftmouse(event, widget):
    if platform.system() == 'Windows':
        widget.xview_scroll(-1*int(event.delta/120), 'units')
    elif platform.system() == 'Darwin':
        widget.xview_scroll(-1*int(event.delta), 'units')
    else:
        if event.num == 4:
            widget.xview_scroll(-1, 'units')
        elif event.num == 5:
            widget.xview_scroll(1, 'units')

if __name__ == '__main__':
    root = tk.Tk()
    top = SecureChatApp(root)
    root.mainloop()