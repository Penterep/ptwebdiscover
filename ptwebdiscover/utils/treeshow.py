import json
import string    
import random

from treelib import Node, Tree


class Treeshow:
    def __init__(self, tree: Tree):
        self.tree = tree

    def url_list_to_json_tree(self, urls: list[str]):
        paths: list[list[str]] = []
        for item in urls:
            split = item.split('/')
            paths.append(split[2:-1])
            paths[-1].append(split[-1])

        root = {}
        for path in paths:
            branch = root.setdefault(path[0], [{}, []])
            for step in path[1:-1]:
                branch = branch[0].setdefault(step, [{}, []])
            branch[1].append(path[-1])
        self.deleter(root)
        return(root)

    def walker(self, courls: list):
        if isinstance(courls, list):
            for item in courls:
                yield item
        if isinstance(courls, dict):
            for item in courls.values():
                yield item

    def deleter(self, courls: list):
        for data in self.walker(courls):
            if data == [] or data == {}:
                courls.remove(data)
            self.deleter(data)

    def createTree(self, parent: str, files: dict | list):
        for key in files:
            if not parent:
                identifier = str(''.join(random.choices(string.ascii_uppercase + string.digits, k = 10)))
                self.tree.create_node(key, identifier)
            if not key:
                continue
            try:
                value = files[key]
                if parent:
                    identifier = str(''.join(random.choices(string.ascii_uppercase + string.digits, k = 10)))
                    self.tree.create_node(key, identifier, parent=parent)
                self.createTree(identifier, value)
            except:
                if type(key) == dict or type(key) == list:
                    self.createTree(parent, key)
                else:
                    identifier = str(''.join(random.choices(string.ascii_uppercase + string.digits, k = 10)))
                    self.tree.create_node(key, identifier, parent=parent)
