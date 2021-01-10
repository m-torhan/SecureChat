import os
import sys
import datetime

import pygame
import pygame_gui

from pygame_gui.elements import UIButton, UIVerticalScrollBar, UITextBox, UILabel, UIScrollingContainer, UIPanel, UITextEntryLine

from connection import *

class Tab(object):
    def __init__(self, name, conn):
        self.name = name
        self.conn = conn

def messages_to_html(messages):
    ret = ''
    for message in messages:
        ret += '<b>'
        if type(message.time) == datetime.datetime:
            ret += message.time.strftime('[%y-%m-%d %H:%M:%S] ')
        if message.type == MessageType.RECEIVED:
            ret += '< '
        if message.type == MessageType.SENT:
            ret += '> '
        ret += '</b>'
        ret += message.text
        ret += '<br>'
    return ret

info_log = [Message(MessageType.INFO, datetime.datetime.now(), 'App start.')]
tabs = [Tab('Info', 0), Tab('Test tab', 2), Tab('New connection', 1)]
tab_idx = 0
line_idx = 0
lines_count = 0
tabs_count = 0

class SecureChatApp(object):
    def __init__(self):
        pygame.init()

        pygame.display.set_caption('SecureChat')
        self.window_surface = pygame.display.set_mode((800, 600))

        self.background = pygame.Surface((800, 600))
        self.background.fill(pygame.Color('#707070'))

        self.manager = pygame_gui.UIManager((800, 600))#, "secure_chat_theme.json")
        self.manager.preload_fonts([{'name': 'fira_code', 'point_size': 24, 'style': 'bold'},
                                    {'name': 'fira_code', 'point_size': 24, 'style': 'bold_italic'},
                                    {'name': 'fira_code', 'point_size': 18, 'style': 'bold'},
                                    {'name': 'fira_code', 'point_size': 18, 'style': 'regular'},
                                    {'name': 'fira_code', 'point_size': 18, 'style': 'bold_italic'},
                                    {'name': 'fira_code', 'point_size': 14, 'style': 'bold'}
                                    ])

        test_messages = [Message(MessageType.RECEIVED, datetime.datetime.now(), 'asddas sad asd '*10),
                         Message(MessageType.SENT, datetime.datetime(2020, 12, 23, 5, 4, 3), 'asd')]
        self.tabs_buttons = [UIButton(pygame.Rect(128*i, 0, 128, 32), tabs[i].name, self.manager) for i in range(len(tabs))]
        self.main_area = UITextBox(messages_to_html(test_messages), pygame.Rect(0, 32, 800, 550 - 32), manager=self.manager)
        self.text_input = UITextEntryLine(pygame.Rect(0, 550, 800, 100), manager=self.manager)

        self.clock = pygame.time.Clock()
        self.is_running = True

    def run(self):
        while self.is_running:
            time_delta = self.clock.tick(60) / 1000.0
            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    self.is_running = False

                self.manager.process_events(event)

            self.manager.update(time_delta)

            self.window_surface.blit(self.background, (0, 0))
            self.manager.draw_ui(self.window_surface)

            pygame.display.update()

if __name__ == '__main__':
    app = SecureChatApp()
    app.run()