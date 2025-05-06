from dnst_core import DNSTRule, DNSTables
from matchers import DNSTMatcherBuilder, OrMatcher
from actions import DNSTActionBuilder

def add_del_set_map(is_add, cmd):
    #TODO: specify element types during set/map declaration
    if len(cmd) != 2 or cmd[0] not in ["set", "map"]:
        print("invalid add/delete set/map syntax")
        return -1
    is_map = cmd[0] == "map"
    name = cmd[1]
    dnstables = DNSTables.get_instance()

    if is_add:
        if is_map and name not in dnstables.maps:
            dnstables.maps[name] = dict()
        elif not is_map and name not in dnstables.sets:
            dnstables.sets[name] = set()
    else:
        if is_map and name not in dnstables.maps or not is_map and name not in dnstables.sets:
            print(f"unable to find {name} with type {cmd[0]}")
            return -1
        if is_map:
            del dnstables.maps[name]
        else:
            del dnstables.sets[name]
    return 0

def add_del_element(is_add, cmd):
    if len(cmd) < 3 or cmd[1] != "{" or cmd[-1] != "}":
        print("invalid add/delete element syntax")
        return -1
    name = cmd.pop(0)
    cmd.pop(0)
    cmd.pop(-1)
    dnstables = DNSTables.get_instance()

    is_map = False
    target = None
    if name in dnstables.maps:
        is_map = True
        target = dnstables.maps[name]
    elif name in dnstables.sets:
        target = dnstables.sets[name]
    else:
         print(f"unable to find set/map: {name}")
         return -1

    if is_map: # map
        if is_add:
            i = 0
            while i < len(cmd):
                if cmd[i+1] != ":":
                    print("invalid add element (maps) syntax")
                    return -1
                target[cmd[i]] = cmd[i+2]
                i += 3
        else:
            for key in cmd:
                target.pop(key, None)

    else: # set
        if is_add:
            target.update(cmd)
        else:
            for item in cmd:
                target.discard(item)

    return 0


# cmd: list of strings
#      e.g., drop all query from "192.168.0.0/24" -> ["preresolve", "src", "192.168.0.0/24", "drop"]
def add_del_rule(is_add, cmd):
    hook = cmd.pop(0)
    dnstables = DNSTables.get_instance()
    if hook not in dnstables.chains.keys():
        print(f"hook {hook} does not exist")
        return -1
    rulechain = dnstables.chains[hook]

    if not is_add:
        # cmd is the index in rule chain
        if len(cmd) != 2 or cmd[0] != "index" or not cmd[1].isdigit():
            print("invalid delete rule syntax")
            return -1
        index = int(cmd[1])
        if len(rulechain) < index - 1:
            print(f"{hook} rulechain has no rule with index {index}")
            return -1

        del rulechain[index]
        return 0

    # add rule
    rule = DNSTRule()
    has_action = False
    index = None
    cmd_len = len(cmd)
    while cmd_len > 0:
        consumed = False
        # parse for matchers
        pending_or = False
        final_matcher = None
        while True:
            matcher = DNSTMatcherBuilder.build(cmd)
            if matcher == None:
                break
            if pending_or:
                final_matcher = OrMatcher(matcher0 = final_matcher, matcher1 = matcher)
                pending_or = False
            else:
                final_matcher = matcher

            # if "or" is specified, continue parsing matcher
            if len(cmd) == 0 or cmd[0] != "or":
                break
            pending_or = True
            cmd.pop(0)

        if pending_or:
            print("invalid matcher after 'or'")
            return -1
        if final_matcher != None:
            rule.add_matcher(final_matcher)
        if len(cmd) == 0:
            break

        # parse for actions
        while True:
            action = DNSTActionBuilder.build(cmd)
            if action == None:
                break
            rule.add_action(action)
            has_action = True
        if len(cmd) == 0:
            break

        # parse for index
        if cmd[0] == "index":
            cmd.pop(0)
            if len(cmd) > 0 and cmd[0].isdigit():
                index = int(cmd.pop(0))
            else:
                print("invalid 'index' syntax")
                return -1

        # return error if nothing consumed this run
        if len(cmd) == cmd_len:
            print(f"failed to parse cmd at {' '.join(cmd)}")
            return -1
        cmd_len = len(cmd)

    if not has_action:
        print("require at least one action")
        return -1

    # insert rule
    if index != None:
        rulechain.insert(index, rule)
    else:
        rulechain.append(rule)
        index = len(rulechain) - 1
    rule.hook = hook
    rule.index = index
    return 0


def add_del_chain(is_add, cmd):
    if len(cmd) != 1:
        print("invalid add/delete chain syntax")
        return -1
    name = cmd[0]
    dnstables = DNSTables.get_instance()

    if is_add and name not in dnstables.hooks:
        dnstables.hooks.append(name)
        dnstables.chains[name] = []
    elif not is_add and name in dnstables.chains.keys():
        dnstables.hooks.remove(name)
        dnstables.chains.pop(name, None)
    return 0


def cmd(cmd_str):
    cmd = cmd_str.replace(',', '').split() # remove commas and split by space
    if len(cmd) == 0:
        return None
    if len(cmd) < 3:
        return "command too short"
    elif cmd[0] not in ["add", "delete"]:
        return "unknown command"

    is_add = cmd.pop(0) == "add"
    ret = 0
    if cmd[0] in ["set", "map"]:
        ret = add_del_set_map(is_add, cmd)
    elif cmd[0] == "rule":
        cmd.pop(0)
        ret = add_del_rule(is_add, cmd)
    elif cmd[0] == "element":
        cmd.pop(0)
        ret = add_del_element(is_add, cmd)
    elif cmd[0] == "chain":
        cmd.pop(0)
        ret = add_del_chain(is_add, cmd)
    else:
        return f"unknown keyword {cmd[0]}"

    if ret != 0:
        return f"failed to run command: {cmd_str}"
    return None
