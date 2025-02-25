import click
import importlib_metadata
import pathlib
import sys
import os
import re
import json
from src.bitterlich.utils.loggerHandler import LoggerInstance
from src.bitterlich.readme import README
from src.bitterlich.crypto.enc import encrypt_list, decrypt_list, decrypt


print(decrypt("2ec5fb0619f0f4ea087ca79b68be8d01e292badf8cc135290b7ff07228a143f30aa9a4e0298b20bc7ac6fc2b801d921ffa79b1275e0f3daaeafee40e0a98c051bf4da36cfb338ef519285c0ed622ca11fecd5c9f04c0b13c5bd59d44ee52ffa3b015a7488434be1328fc075852b539878e8b8e69dcd924341b2f3db1cb14b7834ca93573d57ce18aaf3280ba458ef6c8f03458428417877ccfe503d04542ec176e8d19d5603361bd73bdd6f5791b83ce86bcebb677801b6d95f8fccde0cab0f5",
              "4d7af455f08ae5e1ca1e3e0303af3a841e43b4beafda4a3aaaa56b1a1b14d537",
              "8b396cb560ec8af0cb199cfd858b93f6",
              "bb6cb70a72eb2c7356327a13"))