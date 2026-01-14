import os
from typing import TypeVar
from argparse import Namespace, ArgumentParser
from dataclasses import dataclass
from asset_store.repository.repository import Repository
from asset_store.repository.neo4j import NeoRepository
from dotenv import dotenv_values

def get_uri() -> str:
    env = {
        **os.environ,  
        **dotenv_values(".env"),  
    }
    if "NEO_URI" not in env:
        raise Exception("missing NEO_URI in environment")
    return env["NEO_URI"]

def get_creds() -> tuple[str, str]:
    env = {
        **os.environ,  
        **dotenv_values(".env"),  
    }
    if "NEO_USER" not in env:
        raise Exception("missing NEO_USER in environment")
    if "NEO_PASS" not in env:
        raise Exception("missing NEO_PASS in environment")
    return (env["NEO_USER"], env["NEO_PASS"])


Data = TypeVar("Data", bound=object)

class Context():
    prog_name: str
    config:    Namespace
    db:        Repository
    
    def __init__(self, parser: ArgumentParser):

        if parser.prog is None or parser.prog == "":
            raise Exception("missing prog name to parser")
        
        self.prog_name = parser.prog
        self.config    = parser.parse_args()
        self.db        = NeoRepository(
            get_uri(), get_creds(), emit_events = True)

    def __enter__(self):
        self.db.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.db.__exit__(exc_type, exc, tb)

