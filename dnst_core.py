import asyncio
import copy
import datetime
import sys
from dataclasses import dataclass, asdict, field

class DNSTLogger:
    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance == None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self._queue = asyncio.Queue()
        asyncio.ensure_future(self._logger())

    async def _logger(self):
        while True:
            msg = await self._queue.get()
            if msg is None:
                break
            print(msg)
            sys.stdout.flush()
            self._queue.task_done()

    async def aprint(self, msg):
        await self._queue.put(msg)


async def log(msg):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    await DNSTLogger.get_instance().aprint(f"[{timestamp}] {msg}")


@dataclass
class DNSTQuery:
    src: str
    src_port:int
    qname: str
    qtype: str
    raw_query: bytes
    verbose: int
    trace_logs: list = field(default_factory=list)
    answer: list = field(default_factory=list)

    def set_verbose(self, lvl):
        self.verbose = lvl

    async def trace_flush(self):
        if len(self.trace_logs) == 0:
            return

        if len(self.trace_logs) > 0:
            msg = "\n".join(self.trace_logs)
            await DNSTLogger.get_instance().aprint(msg)
        self.trace_logs = []

    def has_answer(self):
        return len(self.answer) > 0
        return left


class Trace():
    verbose_lvl = {
        "debug" : 0,
        "info"  : 1,
        "warn"  : 2,
        "err"   : 3,
        "none"  : 4,
    }
    tracer_name = None

    def _trace(self, lvl, query, msg):
        if self.verbose_lvl[lvl] >= query.verbose:
            if callable(msg):
                # ugly way to delay expensive evaluation of msg until needed
                # easiest solution is to put an lambda before the string
                # e.g. 
                # self._trace (lvl, query, lambda: ' '.join([
                #                           word for word in very_long_list
                #                           if expensive_check(word) == True
                # ]))
                msg = msg()

            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            query.trace_logs.append(f"[{timestamp}] level={lvl}\ttracer={self.tracer_name}\t{self.msg_decor(msg)}")

    # tracers can overwrite this to decorate their own msg
    def msg_decor(self, msg):
        return f"msg=\"{msg}\""

    @classmethod
    def with_name(cls, name):
        subclass = type(name, (cls,), {"tracer_name": name})

        # Add the dynamic logging methods
        for lvl in cls.verbose_lvl.keys():
            if lvl != "none":
                def trace_lvl(self, query, msg, lvl = lvl):
                    return self._trace(lvl, query, msg)

                setattr(subclass, lvl, trace_lvl)

        return subclass


class DNSTRule(Trace.with_name("rule")):
    def __init__(self):
        self.matcher = None
        self.actions = []
        self.hook = None
        self.index = None

    def __str__(self):
        actions_str = " ".join([str(action) for action in self.actions])
        if self.matcher != None:
            return f"{self.matcher} {actions_str}"
        return actions_str

    def msg_decor(self, msg):
        return f"hook={self.hook} index={self.index} rule=\"{self}\" msg=\"{msg}\""

    def add_matcher(self, matcher):
        assert self.matcher == None
        self.matcher = matcher

    def add_action(self, action):
        self.actions.append(action)

    async def apply(self, query):
        ret = None
        matched = True
        if self.matcher != None:
            matched = self.matcher.match(query = query, **asdict(query))
        if matched:
            self.debug(query, f"query matched: qname={query.qname}, src={query.src}:{query.src_port}")
            for action in self.actions:
                if action.action_str in ["break", "return", "drop"]:
                    ret = action.action_str
                    break
                ret = await action.act(query = query, **asdict(query))
                if ret != None:
                    break
        else:
            self.debug(query, f"skipped rule")

        await query.trace_flush()
        return ret


class DNSTables(Trace.with_name("tables")):
    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance == None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self.sets = dict() # name, set
        self.maps = dict() # name, map
        self.hooks = [] # hooks are ordered
        self.chains = dict() # hook, rules

    def __str__(self):
        lines = []
        # print sets
        for name, target in self.sets.items():
            lines.append(f"set {name} {{")
            lines.extend([f"\t{item}" for item in target])
            lines.append("}\n")
        # print maps
        for name, target in self.maps.items():
            lines.append(f"map {name} {{")
            lines.extend([f"\t{k} : {v}" for k, v in target.items()])
            lines.append("}\n")
        # print rules
        for hook_index, hook in enumerate(self.hooks):
            rulechain = self.chains[hook]
            lines.append(f"chain [{hook_index}] {hook} {{")
            for index, rule in enumerate(rulechain):
                lines.append(f"\t[{index}] {rule}")
            lines.append("}\n")
        return "\n".join(lines)

    async def feed(self, query, hook = None, _hook_index = None):
        if _hook_index != None:
            hook = self.hooks[_hook_index]
        elif hook == None and len(self.hooks) > 0:
            hook = self.hooks[0]
            _hook_index = 0
        elif hook not in self.hooks:
            self.err(query, f"unknown chain name {hook}")
            return "drop"

        if hook != None:
            self.debug(query, f"enter chain {hook}")
            for rule in self.chains[hook]:
                err = await rule.apply(query)
                if err == None:
                    continue
                elif err == "break":
                    # exit the current rule chain
                    break
                elif err == "return":
                    # return (recursively) from feed()
                    return None
                elif err.startswith("jump2hook "):
                    return await self.feed(query, hook = err[10:])
                else:
                    return err

            # feed into the next chainrule
            if _hook_index < len(self.hooks) - 1:
                return await self.feed(query, _hook_index = _hook_index + 1)

        return None
