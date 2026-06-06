VERSION = '0.260521'

SECOND = 1.0
MINUTE = SECOND * 60
HOUR   = MINUTE * 60
DAY    = HOUR   * 24
WEEK   = DAY    * 7




def _module_namespace_builder_closure():
    import importlib
    import re
    import weakref

    ban       = re.compile(r'^(.*\..*|__.+__)$')
    modules   = weakref.WeakKeyDictionary()
    separator = '.'
    whitelist = set()

    whitelist.add('__future__')
    whitelist.add('__hello__')
    whitelist.add('sys.__stderr__')
    whitelist.add('sys.__stdin__')
    whitelist.add('sys.__stdout__')


    class _module_namespace_builder_Class:
        def __init__(self, *args):
            module = None

            if args:
                for arg in args:
                    if ban.fullmatch(arg) and arg not in whitelist:
                        raise ValueError

                namespace = separator.join(args)
                module    = importlib.import_module(namespace)

            modules[self] = module


        def __getattr__(self, name, /):
            cls       = self.__class__
            module    = modules[self]
            namespace = name if module is None else module.__name__ + separator + name
            allowed   = not ban.fullmatch(name) or namespace in whitelist

            if hasattr(module, name): # attribute
                getter = lambda *_, **__: getattr(module, name)

                if allowed:
                    proxy = property(fget=getter)

                    setattr(cls, name, proxy)

                return getter()
            elif allowed: # module/submodule
                arguments = namespace.split(separator)
                base      = cls.__mro__[-2]
                bases     = (base,)
                body      = {}
                label     = base.__name__ + separator + namespace
                proxy     = type(label, bases, body)
                ret       = proxy(*arguments)

                setattr(self, name, ret)

                return ret
            else:
                raise AttributeError

    return _module_namespace_builder_Class()

M = _module_namespace_builder_closure()




def _get_content_from_file(path, /, *, binary, chomp, lock):
    binary = bool(binary)
    chomp  = bool(chomp)
    lock   = bool(lock)
    path   = normalize_path(path)
    ret    = False

    with M.contextlib.suppress(OSError):
        with open(path, mode='rb') as fd:
            if lock:
                M.fcntl.flock(fd, M.fcntl.LOCK_SH)

            ret = fd.read()

        if chomp:
            ret = ret.removesuffix(M.os.linesep.encode())

        if not binary:
            ret = ret.decode(encoding='utf-8', errors='replace')

    return ret




def _ping(address, family, /, *, retries=None, timeout=None):
    address  = str(address)
    families = {4: resolve_dns_ipv4, 6: resolve_dns_ipv6}
    family   = int(family)
    get_ip   = lambda address: families[family](address)
    ret      = False
    retries  = 1 if retries is None else normalize_integer(retries, minimum=0)
    template = 'ping -{family} -c 1 -n -q -W {wait} {ip}'
    timeout  = SECOND if timeout is None else normalize_float(timeout, minimum=0.0)

    if not family in families:
        raise ValueError

    if timeout and retries and (ip := get_ip(address)):
        if M.math.isinf(timeout):
            wait = '0.0'
        else:
            wait = normalize_float(timeout, maximum=HOUR, padding=True, precision=3)

        command = template.format(family=family, ip=ip, wait=wait)

        for _ in range(retries):
            if ret := run(command, cwd='/', timeout=timeout):
                break

    return ret




def _put_content_to_file(path, content, /, *, eol, exclusive, lock, overwrite):
    eol       = bool(eol)
    exclusive = bool(exclusive)
    lock      = bool(lock)
    mode      = 'xb' if exclusive else 'ab'
    overwrite = bool(overwrite)
    path      = normalize_path(path)
    ret       = False

    try:
        content = memoryview(content)
    except TypeError:
        content = str(content).encode()
    else:
        content = bytes(content)

    if eol:
        content += M.os.linesep.encode()

    with M.contextlib.suppress(OSError):
        with open(path, mode=mode) as fd:
            if lock:
                M.fcntl.flock(fd, M.fcntl.LOCK_EX)

            if exclusive or overwrite:
                fd.truncate(0)

            fd.write(content)

            ret = True

    return ret




def append_file(path, content, /, *, eol=False, lock=False):
    return _put_content_to_file(path, content, eol=eol, exclusive=False, lock=lock, overwrite=False)




def check_internet(*, ipv4=True, ipv6=True, retries=None, timeout=None):
    families = {'ipv4': M.types.SimpleNamespace(), 'ipv6': M.types.SimpleNamespace()}
    ipv4     = bool(ipv4)
    ipv6     = bool(ipv6)
    retries  = 1      if retries is None else normalize_integer(retries, minimum=0)
    timeout  = SECOND if timeout is None else normalize_float(timeout,   minimum=0.0)


    ipv4_addresses = (
        '1.0.0.1',        '1.1.1.1',        # Cloudflare
        '86.54.11.100',   '86.54.11.200',   # DNS4EU
        '8.8.4.4',        '8.8.8.8',        # Google
        '9.9.9.10',       '149.112.112.10', # Quad9
        '208.67.220.220', '208.67.222.222', # OpenDNS
    )

    ipv6_addresses = (
        '2606:4700:4700::1001',    '2606:4700:4700::1111',    # Cloudflare
        '2a13:1001::86:54:11:100', '2a13:1001::86:54:11:200', # DNS4EU
        '2001:4860:4860::8844',    '2001:4860:4860::8888',    # Google
        '2620:fe::10',             '2620:fe::fe:10',          # Quad9
        '2620:0:ccc::2',           '2620:0:ccd::2',           # OpenDNS
    )


    families['ipv4'].addresses = M.collections.deque(ipv4_addresses)
    families['ipv6'].addresses = M.collections.deque(ipv6_addresses)
    families['ipv4'].ping      = ping_ipv4
    families['ipv6'].ping      = ping_ipv6
    families['ipv4'].success   = not ipv4
    families['ipv6'].success   = not ipv6

    families = list(families.items())
    M.random.shuffle(families)
    families = dict(families)


    for family in families.values():
        if family.success or not len(family.addresses):
            continue

        M.random.shuffle(family.addresses)

        for _ in range(retries):
            address = family.addresses[0]
            family.addresses.rotate(-1)

            if family.ping(address, retries=1, timeout=timeout):
                family.success = True
                break

    return (ipv4 or ipv6) and all( i.success for i in families.values() )




def check_internet_ipv4(**kwargs):
    return check_internet(ipv4=True, ipv6=False, **kwargs)




def check_internet_ipv6(**kwargs):
    return check_internet(ipv4=False, ipv6=True, **kwargs)




def clamp(value, /, minimum, maximum):
    if minimum > maximum:
        raise ValueError

    if value < minimum:
        value = minimum
    elif value > maximum:
        value = maximum

    return value




def dir_is_empty(path, /):
    path     = normalize_path(path)
    ret      = False
    sentinel = None

    if path_is_dir(path, follow=True):
        with M.contextlib.suppress(OSError):
            with M.os.scandir(path) as iterator:
                ret = next(iterator, sentinel) is sentinel

    return ret




def get_interfaces(*, down=True, loopback=True, up=True):
    dots             = ('.', '..')
    down             = bool(down)
    fstr_pathf_flags = '/sys/class/net/{}/flags'
    loopback         = bool(loopback)
    regex            = f'^0x[0-9A-Fa-f]+$'
    ret              = []
    up               = bool(up)

    interfaces = [ i[1] for i in M.socket.if_nameindex() ]
    interfaces = [ i for i in interfaces if i not in dots ]
    interfaces = [ i for i in interfaces if M.os.path.sep not in i ]

    for interface in interfaces:
        path    = fstr_pathf_flags.format(interface)
        content = read_text_file(path, chomp=True)

        if content is False or not M.re.fullmatch(regex, content):
            continue

        flags = int(content, base=16)

        if not down and not (flags & 0x1):
            continue

        if not loopback and (flags & 0x8):
            continue

        if not up and (flags & 0x1):
            continue

        ret.append(interface)

    ret = set(ret)
    ret = sorted(ret)
    ret = tuple(ret)

    return ret




def get_timestamp(epoch=None, /, *, utc=False):
    empty     = ''
    epoch     = M.time.time() if epoch is None else normalize_float(epoch, minimum=0.0)
    ret       = M.types.SimpleNamespace()
    template  = '%Y/%m/%d-%H:%M:%S.%f%z'
    utc       = bool(utc)
    tz        = M.datetime.timezone.utc if utc else None
    now       = M.datetime.datetime.fromtimestamp(epoch).astimezone(tz=tz)
    timestamp = now.strftime(template)

    ret.epoch = now.timestamp()

    ret.full    = timestamp
    ret.human   = timestamp[0:19] + timestamp[-5:]
    ret.compact = ret.human[2:].replace('/', empty).replace(':', empty)
    ret.iso     = now.isoformat(timespec='microseconds')
    ret.short   = timestamp[2:19]

    ret.date = timestamp[0:10]
    ret.time = timestamp[11:19]

    ret.year        = timestamp[0:4]
    ret.month       = timestamp[5:7]
    ret.day         = timestamp[8:10]
    ret.hour        = timestamp[11:13]
    ret.minute      = timestamp[14:16]
    ret.second      = timestamp[17:19]
    ret.microsecond = timestamp[20:26]
    ret.timezone    = timestamp[26:]

    return ret




def ip_in_network(address, network, /):
    address = normalize_ip(address, host=True)
    network = normalize_ip(network, network=True)

    address = M.ipaddress.ip_address(address)
    network = M.ipaddress.ip_network(network)

    if address.version == network.version:
        return address in network
    else:
        raise ValueError




def is_ip(address, /, *, host=False, ipv4=True, ipv6=True, network=False):
    address       = str(address)
    function      = noop
    host          = bool(host)
    ipv4          = bool(ipv4)
    ipv6          = bool(ipv6)
    network       = bool(network)
    ret           = False
    separator     = '/'
    sub_cidr_weak = r'(0|[1-9][0-9]*)'
    sub_ipv4_weak = r'((0|[1-9][0-9]*)\.){3}(0|[1-9][0-9]*)'
    sub_ipv6_weak = r'([0-9a-f]{1,4}:*)*:+(:*[0-9a-f]{1,4})*'
    regex         = f'^({sub_ipv4_weak}|{sub_ipv6_weak})(/{sub_cidr_weak})?$'

    if M.re.fullmatch(regex, address, flags=M.re.IGNORECASE):
        if not host or separator not in address:
            if ipv4 and ipv6:
                function = getattr(M.ipaddress, 'ip_network')
            elif ipv4:
                function = getattr(M.ipaddress, 'IPv4Network')
            elif ipv6:
                function = getattr(M.ipaddress, 'IPv6Network')

            with M.contextlib.suppress(ValueError):
                ret = bool(function(address, strict=network))

    return ret




def is_ipv4(address, /, **kwargs):
    return is_ip(address, ipv4=True, ipv6=False, **kwargs)




def is_ipv6(address, /, **kwargs):
    return is_ip(address, ipv4=False, ipv6=True, **kwargs)




def is_pid(pid, /, *, check=False):
    check = bool(check)
    pid   = int(pid)
    ret   = False

    if pid > 0:
        try:
            M.os.kill(pid, 0)
        except PermissionError:
            ret = True
        except ProcessLookupError:
            ret = not check
        except Exception:
            pass
        else:
            ret = True

    return ret




def noop(*args, **kwargs):
    pass




def normalize_float(number, /, *, maximum=None, minimum=None, padding=False, precision=None):
    fallback = 15
    infinity = M.math.inf
    maximum  =  infinity if maximum is None else float(maximum)
    minimum  = -infinity if minimum is None else float(minimum)
    number   = clamp(float(number), minimum, maximum)
    padding  = bool(padding)

    if M.math.isnan(number):
        raise ValueError
    else:
        number = number + 0.0 # -0.0 -> 0.0

    if precision is not None:
        precision = max(int(precision), 0)

        try:
            scale  = M.decimal.Decimal(1).scaleb(-precision)
            number = M.decimal.Decimal(number).quantize(scale, rounding=M.decimal.ROUND_HALF_UP)
            number = float(number)
        except M.decimal.InvalidOperation:
            try:
                precision = min(fallback, precision)
                number    = round(number, precision)
                number    = float(number)
            except Exception:
                raise ValueError

    if padding:
        fmt    = 'f' if precision is None else f'.{precision}f'
        number = M.decimal.Decimal(str(number)) + M.decimal.Decimal('0.0') # 0 -> 0.0

        return format(number, fmt)
    else:
        return number




def normalize_integer(number, /, *, maximum=None, minimum=None):
    if isinstance(number, float):
        number = normalize_float(number, precision=0)

    number = int(number)

    if None not in (maximum, minimum):
        maximum = int(maximum)
        minimum = int(minimum)
        number  = clamp(number, minimum, maximum)
    elif maximum is not None:
        number = min(int(maximum), number)
    elif minimum is not None:
        number = max(int(minimum), number)

    return number




def normalize_ip(address, /, *, exploded=False, host=False, network=False, upper=False):
    address   = str(address)
    exploded  = bool(exploded)
    host      = bool(host)
    network   = bool(network)
    prefixlen = None
    separator = '/'
    upper     = bool(upper)

    if not is_ip(address):
        raise ValueError

    if separator in address:
        if network:
            address = M.ipaddress.ip_network(address, strict=False).with_prefixlen

        address, prefixlen = address.split(separator)

    address = M.ipaddress.ip_address(address)
    address = address.exploded if exploded else address.compressed
    address = address.upper()  if upper    else address.lower()

    return address if host or prefixlen is None else f'{address}{separator}{prefixlen}'




def normalize_path(*args, absolute=False, leading=False, resolve=False, trailing=False):
    absolute  = bool(absolute)
    args      = list(args)
    leading   = bool(leading)
    null      = '\x00'
    resolve   = bool(resolve)
    separator = M.os.path.sep
    trailing  = bool(trailing)


    if not args:
        raise ValueError

    for i, value in enumerate(args):
        try:
            value = M.os.fspath(value)
        except TypeError:
            value = str(value)

        if isinstance(value, bytes):
            value = M.os.fsdecode(value)

        if null in value or not len(value):
            raise ValueError

        if i and M.os.path.isabs(value):
            raise ValueError

        args[i] = value


    path = M.os.path.join(*args)
    path = M.os.path.normpath(path)

    if resolve:
        path = M.os.path.realpath(path)
    elif absolute:
        path = M.os.path.abspath(path)

    if leading and path.startswith(separator * 2):
        path = separator + path.lstrip(separator)

    if trailing and not path.endswith(separator):
        path += separator

    return path




def normalize_text(text, /, *, full=False, printable=None, reduce=None, strip=None, uniform=None):
    empty       = ''
    full        = bool(full)
    function    = lambda arg: arg.group(1)
    regex       = r'(\s)\1+'
    replacement = '\uFFFD'
    space       = ' '
    text        = str(text)
    whitelist   = ('\t', '\n')

    printable = full if printable is None else bool(printable)
    reduce    = full if reduce    is None else bool(reduce)
    strip     = full if strip     is None else bool(strip)
    uniform   = full if uniform   is None else bool(uniform)

    if uniform:
        text = empty.join( space if i.isspace() else i for i in text )

    if reduce:
        text = M.re.sub(regex, function, text, flags=M.re.UNICODE)

    if strip:
        text = text.strip()

    if printable:
        text = empty.join( i if i.isprintable() or i in whitelist else replacement for i in text )

    return text




def path_is_dir(path, /, *, follow):
    path   = normalize_path(path)
    follow = bool(follow)
    ret    = False

    with M.contextlib.suppress(Exception):
        ret = M.os.path.isdir(path) if follow else M.stat.S_ISDIR(M.os.lstat(path).st_mode)

    return ret




def path_is_file(path, /, *, follow):
    path   = normalize_path(path)
    follow = bool(follow)
    ret    = False

    with M.contextlib.suppress(Exception):
        ret = M.os.path.isfile(path) if follow else M.stat.S_ISREG(M.os.lstat(path).st_mode)

    return ret




def path_is_link(path, /, *, follow):
    path   = normalize_path(path)
    follow = bool(follow)
    ret    = False

    with M.contextlib.suppress(Exception):
        real = M.os.path.realpath(path, strict=False)
        ret  = M.os.path.islink(real) if follow else M.stat.S_ISLNK(M.os.lstat(path).st_mode)

    return ret




def ping_ipv4(address, *args, **kwargs):
    return _ping(address, 4, *args, **kwargs)




def ping_ipv6(address, *args, **kwargs):
    return _ping(address, 6, *args, **kwargs)




def printe(*args, **kwargs):
    with Spinner.hide():
        with Terminal.brush:
            return print(*args, file=M.sys.__stderr__, **kwargs)




def printo(*args, **kwargs):
    with Spinner.hide():
        with Terminal.brush:
            return print(*args, file=M.sys.__stdout__, **kwargs)




def randomize_ip(address, /, *, network=False, seed=None):
    address = normalize_ip(address)
    address = M.ipaddress.ip_network(address, strict=False)
    first   = int(address.network_address)
    free    = address.max_prefixlen - address.prefixlen
    last    = int(address.broadcast_address)
    network = bool(network)

    if free > 1:
        margin = 1
        first  = first + margin # network (IPv4), Subnet-Router anycast (IPv6)

        if address.version == 4:
            last = last - margin # broadcast

    if seed is not None:
        try:
            seed = memoryview(seed)
        except TypeError:
            seed = str(seed).encode()
        else:
            seed = bytes(seed)

    host = M.random.Random(seed).randint(first, last)
    ret  = M.ipaddress.ip_address(host)
    ret  = M.ipaddress.ip_interface(f'{ret}/{address.prefixlen}')

    return ret.with_prefixlen if network else ret.ip.compressed




def read_binary_file(path, /, *, lock=False):
    return _get_content_from_file(path, binary=True, chomp=False, lock=lock)




def read_text_file(path, /, *, chomp=False, lock=False):
    return _get_content_from_file(path, binary=False, chomp=chomp, lock=lock)




def resolve_dns(domain, /, *, ipv4=True, ipv6=True, shuffle=False):
    domain   = str(domain)
    families = [M.socket.AF_INET, M.socket.AF_INET6]
    family   = M.socket.AF_UNSPEC
    ipv4     = bool(ipv4)
    ipv6     = bool(ipv6)
    port     = None
    ret      = []
    shuffle  = bool(shuffle)

    if not ipv4:
        families.remove(M.socket.AF_INET)

    if not ipv6:
        families.remove(M.socket.AF_INET6)

    if families:
        with M.contextlib.suppress(Exception):
            ret = M.socket.getaddrinfo(domain, port, family)

        ret = [ i[4][0] for i in ret if i[0] in families ]
        ret = [ normalize_ip(i) for i in ret if is_ip(i) ]
        ret = list(set(ret))

        if shuffle:
            M.random.shuffle(ret)

    return tuple(ret)




def resolve_dns_ipv4(domain, /, *, shuffle=False, zen=True):
    ret = resolve_dns(domain, ipv4=True, ipv6=False, shuffle=shuffle)
    zen = bool(zen)

    if zen:
        ret = ret[0] if ret else False

    return ret




def resolve_dns_ipv6(domain, /, *, shuffle=False, zen=True):
    ret = resolve_dns(domain, ipv4=False, ipv6=True, shuffle=shuffle)
    zen = bool(zen)

    if zen:
        ret = ret[0] if ret else False

    return ret




def run(command, /, *, binary=False, cwd=None, stdin=None, timeout=None, zen=True):
    binary    = bool(binary)
    code      = None
    command   = str(command)
    arguments = M.shlex.split(command)
    encoding  = 'utf-8'
    errors    = 'replace'
    exception = None
    options   = {}
    ret       = M.types.SimpleNamespace()
    stderr    = bytes()
    stdout    = bytes()
    zen       = bool(zen)


    if cwd is not None:
        cwd = normalize_path(cwd, absolute=True)

    if stdin is not None:
        try:
            stdin = memoryview(stdin)
        except TypeError:
            stdin = str(stdin).encode()
        else:
            stdin = bytes(stdin)

    if timeout is not None:
        timeout = normalize_float(timeout, minimum=0.0)


    options['cwd']     = cwd
    options['input']   = stdin
    options['shell']   = False
    options['stderr']  = M.subprocess.DEVNULL if zen           else M.subprocess.PIPE
    options['stdin']   = M.subprocess.DEVNULL if stdin is None else None
    options['stdout']  = M.subprocess.DEVNULL if zen           else M.subprocess.PIPE
    options['timeout'] = timeout

    try:
        result = M.subprocess.run(arguments, **options)
    except Exception as e:
        exception = e
    else:
        code = result.returncode

        if not zen:
            stderr = result.stderr
            stdout = result.stdout


    ret.code      = code
    ret.exception = exception
    ret.stderr    = stderr if binary else stderr.decode(encoding, errors=errors)
    ret.stdout    = stdout if binary else stdout.decode(encoding, errors=errors)
    ret.success   = False if code is None else not code

    return ret.success if zen else ret




def user_is_admin():
    return M.os.geteuid() == 0




def write_file(path, content, /, *, exclusive=False, lock=False):
    return _put_content_to_file(path, content, eol=False, exclusive=exclusive, lock=lock, overwrite=True)




class Chrono:
    def _fget_delta(self, /):
        delta = self._calculate_raw_delta()
        delta = self._round_if_precision(delta)

        return delta


    def _fget_expired(self, /):
        return not self.remaining


    def _fget_precision(self, /):
        return self._precision


    def _fget_remaining(self, /):
        remaining = M.math.inf

        if (timeout := self.timeout) is not False:
            delta     = self._calculate_raw_delta()
            remaining = max(timeout - delta, 0.0)
            remaining = self._round_if_precision(remaining)

        return remaining


    def _fget_timeout(self, /):
        return self._timeout


    def _fset_precision(self, value, /):
        if value is not False:
            value = normalize_integer(value, minimum=0)

        self._precision = value


    def _fset_timeout(self, value, /):
        if value is not False:
            value = normalize_float(value, minimum=0.0)

        self._timeout = value


    delta     = property(fget=_fget_delta)
    expired   = property(fget=_fget_expired)
    precision = property(fget=_fget_precision, fset=_fset_precision)
    remaining = property(fget=_fget_remaining)
    timeout   = property(fget=_fget_timeout,   fset=_fset_timeout)


    def __init__(self, /, *, precision=False, timeout=False):
        self.precision = precision
        self.timeout   = timeout

        self.reset()


    def _calculate_raw_delta(self, /):
        return M.time.monotonic() - self._start


    def _round_if_precision(self, value, /):
        if (precision := self.precision) is not False:
            value = normalize_float(value, precision=precision)

        return value


    def reset(self, /):
        self._start = M.time.monotonic()




class _metaclass_CPU(type):
    _break_engine        = M.threading.Event()
    _chrono              = Chrono(timeout=0.0)
    _fingerprint         = tuple()
    _interval            = False
    _lock                = M.threading.RLock()
    _minimum_interval    = SECOND / 10
    _monitors            = []
    _pathf_offline       = '/sys/devices/system/cpu/offline'
    _pathf_online        = '/sys/devices/system/cpu/online'
    _pathf_possible      = '/sys/devices/system/cpu/possible'
    _pathf_present       = '/sys/devices/system/cpu/present'
    _previous_load       = dict()
    _regex_fname_input   = M.re.compile(r'^temp(0|[1-9][0-9]*)_input$')
    _regex_label_ccd     = M.re.compile(r'^Tccd(0|[1-9][0-9]*)$')
    _regex_label_core    = M.re.compile(r'^Core (0|[1-9][0-9]*)$')
    _regex_label_package = M.re.compile(r'^Package id (0|[1-9][0-9]*)$')
    _regex_label_tdie    = M.re.compile(r'^Tdie$')
    _regex_stat          = M.re.compile(r'^cpu( |0|[1-9][0-9]*)( (0|[1-9][0-9]*)){10,}$')
    _sensors             = dict()
    _thread_engine       = M.threading.Thread()


    def _fget_interval(cls, /):
        return cls._interval


    def _fget_load(cls, /):
        return cls._calc_load_from_stat(None)


    def _fget_temperature(cls, /):
        return cls._calc_temperature_from_sensors(None)


    def _fset_interval(cls, value, /):
        if value is not False:
            value = normalize_float(value, minimum=cls._minimum_interval)

        with cls._lock:
            cls._interval = value

            if cls._thread_engine.is_alive():
                cls._break_engine.set()
            elif cls.interval:
                cls._thread_engine = M.threading.Thread(daemon=True, target=cls._target_engine)

                cls._thread_engine.start()


    interval    = property(fget=_fget_interval, fset=_fset_interval)
    load        = property(fget=_fget_load)
    temperature = property(fget=_fget_temperature)


    def _calc_frequency_from_file(cls, path, /):
        content = read_text_file(path, chomp=True)
        divisor = 1000
        minimum = 0.0
        ret     = minimum

        if content is not False and content.isdigit():
            ret = int(content) / divisor
            ret = max(ret, minimum)

        return ret


    def _calc_load_from_stat(cls, thread, /):
        empty        = ''
        get_template = lambda: M.types.SimpleNamespace(busy=0, load=0.0, total=0)
        dummy        = get_template()
        names        = ('user', 'nice', 'system', 'idle', 'iowait', 'irq', 'softirq', 'steal', 'guest', 'guest_nice')
        pathf_stat   = '/proc/stat'
        prefix       = 'cpu'
        thread       = cls._normalize_if_thread(thread)

        if cls._chrono.expired:
            content  = read_text_file(pathf_stat)
            current  = dict()
            snapshot = cls._previous_load

            if content is not False:
                for line in content.split(M.os.linesep):
                    if not cls._regex_stat.fullmatch(line):
                        break

                    split  = line.split()
                    cpu    = split.pop(0).removeprefix(prefix)
                    cpu    = None if cpu == empty else int(cpu)
                    values = split[:len(names)]
                    values = list(map(int, values))
                    fields = dict(zip(names, values))

                    curr = current[cpu] = get_template()

                    curr.total = sum(values) - fields['guest'] - fields['guest_nice']
                    curr.busy  = curr.total  - fields['idle']  - fields['iowait']

                    if cpu in snapshot:
                        prev = snapshot[cpu]

                        try:
                            curr.load = (curr.busy - prev.busy) / (curr.total - prev.total) * 100
                            curr.load = clamp(curr.load, minimum=0.0, maximum=100.0)
                        except ZeroDivisionError:
                            curr.load = prev.load

                with cls._lock:
                    cls._chrono        = Chrono(timeout=cls._minimum_interval)
                    cls._previous_load = current

        return cls._previous_load.get(thread, dummy).load


    def _calc_temperature_from_sensors(cls, thread, /):
        divisor      = 1000
        minimum      = 0.0
        temperatures = [minimum]
        thread       = cls._normalize_if_thread(thread)

        with cls._lock:
            cls._refresh_cache_if_needed()

            if thread in cls._sensors:
                sensors = cls._sensors[thread]
            elif thread is None:
                sensors = cls._sensors[thread] = cls._select_common_sensors()
            else:
                sensors = cls._sensors[thread] = cls._select_thread_sensors(thread)

        for path in sensors:
            content = read_text_file(path, chomp=True)

            if content is not False and content.isdigit():
                temperature = int(content) / divisor
                temperature = max(temperature, minimum)

                temperatures.append(temperature)

        return max(temperatures)


    def _detect_monitors(cls, /):
        drivers_amd      = ('k10temp', 'zenpower')
        drivers_intel    = ('coretemp',)
        drivers_rpi      = ('cpu_thermal',)
        drivers          = drivers_amd + drivers_intel + drivers_rpi
        fname_name       = 'name'
        fstr_label       = 'temp{}_label'
        glob_fname_input = 'temp*_input'
        glob_fname_label = 'temp*_label'
        glob_pathd_hwmon = '/sys/class/hwmon/hwmon*/'
        natural_sort     = lambda p: int(cls._regex_fname_input.search(M.os.path.basename(p)).group(1))
        purge_and_sort   = lambda l: sorted([ p for p in l if path_is_file(p, follow=False) ], key=natural_sort)
        ret              = []

        for pathd_hwmon in M.glob.glob(glob_pathd_hwmon):
            pathd_hwmon = normalize_path(pathd_hwmon, trailing=True)
            pathf_name  = normalize_path(pathd_hwmon, fname_name)

            if (driver := read_text_file(pathf_name, chomp=True)) is False:
                continue
            elif driver not in drivers:
                continue

            monitor         = M.types.SimpleNamespace()
            monitor.ccd     = M.collections.defaultdict(list)
            monitor.core    = M.collections.defaultdict(list)
            monitor.main    = []
            monitor.package = M.collections.defaultdict(list)
            monitor.unknown = []

            for fname_input in M.glob.glob(glob_fname_input, root_dir=pathd_hwmon):
                if result := cls._regex_fname_input.search(fname_input):
                    reference = result.group(1)
                else:
                    continue

                pathf_input = normalize_path(pathd_hwmon, fname_input)
                pathf_label = normalize_path(pathd_hwmon, fstr_label.format(reference))
                label       = read_text_file(pathf_label, chomp=True)
                where       = monitor.unknown

                if label is not False:
                    if result := cls._regex_label_core.search(label):
                        index = int(result.group(1))
                        where = monitor.core[index]
                    elif result := cls._regex_label_package.search(label):
                        index = int(result.group(1))
                        where = monitor.package[index]
                    elif result := cls._regex_label_ccd.search(label):
                        index = int(result.group(1))
                        where = monitor.ccd[index]
                    elif cls._regex_label_tdie.fullmatch(label):
                        where = monitor.main
                elif driver in drivers_rpi:
                    where = monitor.main

                where.append(pathf_input)

            ret.append(monitor)

        for monitor in ret:
            monitor.ccd     = { k: purge_and_sort(v) for k, v in sorted(monitor.ccd.items()) }
            monitor.core    = { k: purge_and_sort(v) for k, v in sorted(monitor.core.items()) }
            monitor.main    = purge_and_sort(monitor.main)
            monitor.package = { k: purge_and_sort(v) for k, v in sorted(monitor.package.items()) }
            monitor.unknown = purge_and_sort(monitor.unknown)

        return ret


    def _get_topology(cls, thread, /):
        fname_core          = 'core_id'
        fname_die           = 'die_id'
        fname_package       = 'physical_package_id'
        fstr_pathd_topology = '/sys/devices/system/cpu/cpu{}/topology'
        thread              = normalize_integer(thread, minimum=0)
        pathd_topology      = fstr_pathd_topology.format(thread)
        ret                 = M.types.SimpleNamespace(core=None, die=None, package=None, thread=thread)

        if path_is_dir(pathd_topology, follow=False):
            pathf_core    = normalize_path(pathd_topology, fname_core)
            pathf_die     = normalize_path(pathd_topology, fname_die)
            pathf_package = normalize_path(pathd_topology, fname_package)

            if (core := read_text_file(pathf_core, chomp=True)) is not False:
                if core.isdigit():
                    ret.core = int(core)

            if (die := read_text_file(pathf_die, chomp=True)) is not False:
                if die.isdigit():
                    ret.die = int(die)

            if (package := read_text_file(pathf_package, chomp=True)) is not False:
                if package.isdigit():
                    ret.package = int(package)

        return ret


    def _normalize_if_thread(cls, thread, /):
        if thread is not None:
            thread = normalize_integer(thread, minimum=0)

        return thread


    def _refresh_cache_if_needed(cls, /):
        glob_pathd_hwmon = '/sys/class/hwmon/hwmon*/'
        monitors         = sorted(M.glob.glob(glob_pathd_hwmon))
        present          = read_text_file(cls._pathf_present)
        fingerprint      = (tuple(monitors), present)

        with cls._lock:
            if cls._fingerprint != fingerprint:
                cls._fingerprint = fingerprint
                cls._monitors    = cls._detect_monitors()
                cls._sensors     = dict()


    def _select_common_sensors(cls, /):
        monitors = cls._monitors
        ret      = []

        for monitor in monitors:
            ret.extend(monitor.main)

        if not ret:
            for monitor in monitors:
                [ ret.extend(i) for i in monitor.package.values() ]

        if not ret:
            for monitor in monitors:
                [ ret.extend(i) for i in monitor.ccd.values() ]

        if not ret:
            for monitor in monitors:
                [ ret.extend(i) for i in monitor.core.values() ]

        if not ret:
            for monitor in monitors:
                ret.extend(monitor.unknown)

        return tuple(ret)


    def _select_thread_sensors(cls, thread, /):
        monitors = cls._monitors
        ret      = []
        thread   = normalize_integer(thread, minimum=0)
        topology = cls._get_topology(thread)

        for monitor in monitors:
            if topology.package in monitor.package:
                if topology.core in monitor.core:
                    ret.extend(monitor.core[topology.core])
                else:
                    ret.extend(monitor.package[topology.package])

        if not ret:
            for monitor in monitors:
                ret.extend(monitor.main)

        if not ret:
            for monitor in monitors:
                if topology.core in monitor.core:
                    ret.extend(monitor.core[topology.core])

        if not ret:
            for monitor in monitors:
                [ ret.extend(i) for i in monitor.ccd.values() ]

        if not ret:
            for monitor in monitors:
                ret.extend(monitor.unknown)

        return tuple(ret)


    def _target_engine(cls, /):
        while True:
            with cls._lock:
                if cls.interval is False:
                    return
                else:
                    interval = cls.interval
                    cls._break_engine.clear()

            while not cls._break_engine.is_set():
                cls._calc_load_from_stat(None)
                cls._break_engine.wait(interval)


    def get_cpus(cls, /, *, auto=False, offline=False, online=False, possible=False, present=False):
        auto      = bool(auto)
        offline   = bool(offline)
        online    = bool(online)
        paths     = []
        possible  = bool(possible)
        present   = bool(present)
        ret       = []
        sep_field = ','
        sep_range = '-'

        if offline:
            paths.append(cls._pathf_offline)

        if online:
            paths.append(cls._pathf_online)

        if possible:
            paths.append(cls._pathf_possible)

        if present:
            paths.append(cls._pathf_present)

        for path in paths:
            if (content := read_text_file(path, chomp=True)) is not False:
                for field in content.split(sep_field):
                    if sep_range in field:
                        first, last = field.split(sep_range, maxsplit=1)

                        if first.isdigit() and last.isdigit():
                            ret += range(int(first), int(last) + 1)
                    elif field.isdigit():
                        ret.append(int(field))

        ret = set(ret)
        ret = sorted(ret)

        return tuple( cls(i) for i in ret ) if auto else tuple(ret)




class CPU(metaclass=_metaclass_CPU):
    def _fget_frequency(self, /):
        cls  = self.__class__
        path = f'/sys/devices/system/cpu/cpu{self.thread}/cpufreq/scaling_cur_freq'

        return cls._calc_frequency_from_file(path)


    def _fget_load(self, /):
        return self.__class__._calc_load_from_stat(self.thread)


    def _fget_maxfreq(self, /):
        cls  = self.__class__
        path = f'/sys/devices/system/cpu/cpu{self.thread}/cpufreq/cpuinfo_max_freq'

        return cls._calc_frequency_from_file(path)


    def _fget_maxscal(self, /):
        cls  = self.__class__
        path = f'/sys/devices/system/cpu/cpu{self.thread}/cpufreq/scaling_max_freq'

        return cls._calc_frequency_from_file(path)


    def _fget_minfreq(self, /):
        cls  = self.__class__
        path = f'/sys/devices/system/cpu/cpu{self.thread}/cpufreq/cpuinfo_min_freq'

        return cls._calc_frequency_from_file(path)


    def _fget_minscal(self, /):
        cls  = self.__class__
        path = f'/sys/devices/system/cpu/cpu{self.thread}/cpufreq/scaling_min_freq'

        return cls._calc_frequency_from_file(path)


    def _fget_online(self, /):
        return self.thread in self.__class__.get_cpus(online=True)


    def _fget_temperature(self, /):
        return self.__class__._calc_temperature_from_sensors(self.thread)


    def _fget_thread(self, /):
        return self._thread


    frequency   = property(fget=_fget_frequency)
    load        = property(fget=_fget_load)
    maxfreq     = property(fget=_fget_maxfreq)
    maxscal     = property(fget=_fget_maxscal)
    minfreq     = property(fget=_fget_minfreq)
    minscal     = property(fget=_fget_minscal)
    online      = property(fget=_fget_online)
    temperature = property(fget=_fget_temperature)
    thread      = property(fget=_fget_thread)


    def __init__(self, thread, /):
        cls    = self.__class__
        thread = normalize_integer(thread, minimum=0)

        if thread not in cls.get_cpus(possible=True):
            raise ValueError

        self._thread = thread




class Latch:
    def _fget_path(self, /):
        return self._path


    def _fget_pid(self, /):
        return self._pid


    def _fget_socket(self, /):
        return self._socket


    def _fget_status(self, /):
        return bool(self._endpoint) if self.socket else bool(self._fd)


    path   = property(fget=_fget_path)
    pid    = property(fget=_fget_pid)
    socket = property(fget=_fget_socket)
    status = property(fget=_fget_status)


    def __enter__(self, /):
        self.on()
        return self


    def __exit__(self, exc_type, exc_value, traceback, /):
        self.off()


    def __init__(self, path, /, *, auto=False, pid=None, socket=False):
        auto   = bool(auto)
        path   = normalize_path(path, absolute=True, resolve=True)
        pid    = M.os.getpid() if pid is None else int(pid)
        socket = bool(socket)

        if not is_pid(pid, check=False):
            raise ValueError

        self._endpoint      = None
        self._fd            = None
        self._instance_lock = M.threading.RLock()
        self._path          = path
        self._pid           = pid
        self._socket        = socket

        if auto:
            self.on()


    def _disable_flock(self, /):
        with self._instance_lock:
            if not self.socket and self.status:
                with M.contextlib.suppress(OSError):
                    M.os.remove(self.path)

                with M.contextlib.suppress(OSError):
                    self._fd.close()

                self._fd = None


    def _disable_socket(self, /):
        with self._instance_lock:
            if self.socket and self.status:
                with M.contextlib.suppress(OSError):
                    self._endpoint.close()

                self._endpoint = None


    def _enable_flock(self, /):
        with self._instance_lock:
            if not self.socket and not self.status and is_pid(self.pid, check=True):
                content = f'{self.pid}{M.os.linesep}'
                fd      = None

                with M.contextlib.suppress(OSError):
                    fd = open(self.path, mode='at')

                    previous = M.os.fstat(fd.fileno())
                    previous = (previous.st_dev, previous.st_ino)

                    M.fcntl.flock(fd, M.fcntl.LOCK_EX | M.fcntl.LOCK_NB)

                    current = M.os.lstat(self.path)
                    current = (current.st_dev, current.st_ino)

                    if previous == current:
                        fd.truncate(0)
                        fd.write(content)
                        fd.flush()
                        M.fcntl.flock(fd, M.fcntl.LOCK_SH)

                        self._fd = fd

                if not self._fd and fd:
                    with M.contextlib.suppress(OSError):
                        fd.close()


    def _enable_socket(self, /):
        with self._instance_lock:
            if self.socket and not self.status:
                seed = self.path.encode()

                address_first = int(M.ipaddress.IPv4Address('127.0.0.2'))
                address_last  = int(M.ipaddress.IPv4Address('127.255.255.254'))
                address_seed  = M.hashlib.blake2s(seed).digest()
                port_first    = 1024
                port_last     = 65535
                port_seed     = M.hashlib.md5(seed).digest()

                address  = M.random.Random(address_seed).randint(address_first, address_last)
                address  = M.ipaddress.IPv4Address(address).compressed
                port     = M.random.Random(port_seed).randint(port_first, port_last)
                endpoint = M.socket.socket(family=M.socket.AF_INET, type=M.socket.SOCK_STREAM)
                where    = (address, port)

                with M.contextlib.suppress(OSError):
                    endpoint.bind(where)
                    self._endpoint = endpoint


    def off(self, /):
        with self._instance_lock:
            if self.socket:
                self._disable_socket()
            else:
                self._disable_flock()


    def on(self, /):
        with self._instance_lock:
            if self.socket:
                self._enable_socket()
            else:
                self._enable_flock()

            return self.status




class Logger:
    def _fget_mute(self, /):
        return self._mute


    def _fget_path(self, /):
        return self._path


    def _fget_stderr(self, /):
        return self._terminal.stderr


    def _fget_timestamp(self, /):
        return self._timestamp


    def _fget_type(self, /):
        return self._type


    def _fset_mute(self, value, /):
        with self._instance_lock:
            self._mute = bool(value)


    def _fset_path(self, value, /):
        with self._instance_lock:
            if value is not False:
                value = normalize_path(value, absolute=True)

            self._path = value


    def _fset_stderr(self, value, /):
        with self._instance_lock:
            value          = bool(value)
            self._terminal = Terminal(stderr=value)


    def _fset_timestamp(self, value, /):
        with self._instance_lock:
            if value in (False, *LoggerTimestamp):
                self._timestamp = value
            else:
                raise ValueError


    mute      = property(fget=_fget_mute,      fset=_fset_mute)
    path      = property(fget=_fget_path,      fset=_fset_path)
    stderr    = property(fget=_fget_stderr,    fset=_fset_stderr)
    timestamp = property(fget=_fget_timestamp, fset=_fset_timestamp)
    type      = property(fget=_fget_type)


    def __init__(self, kind, /, *, mute=False, path=False, stderr=None, timestamp=False):
        self._instance_lock = M.threading.RLock()
        self._terminal      = Terminal()

        if isinstance(kind, LoggerType):
            self._type = kind
        else:
            raise TypeError

        self.mute      = mute
        self.path      = path
        self.stderr    = kind._stderr if stderr is None else stderr
        self.timestamp = timestamp


    def __call__(self, message=None, /, *args, **kwargs):
        empty     = ''
        message   = empty if message is None else str(message)
        message   = message.format(*args, **kwargs) if args or kwargs else message
        message   = normalize_text(message, full=True)
        ret       = True
        separator = ' '

        with self._instance_lock:
            kind      = self.type
            mute      = self.mute
            now       = get_timestamp()
            path      = self.path
            terminal  = self._terminal
            timestamp = self.timestamp

        if not mute:
            colorful  = []
            colorless = []

            if timestamp:
                timestamp = getattr(now, timestamp.name.lower())

                colorful.append(f'\x1B[37m{timestamp}\x1B[39m')
                colorless.append(timestamp)

            colorful.append(kind._colorful)
            colorless.append(kind._colorless)

            if terminal.stream.isatty():
                margin    = sum( len(i) + len(separator) for i in colorless )
                indent    = M.os.linesep + (separator * margin)[:margin]
                minimum   = 1
                width     = max(minimum, terminal.width - margin)
                multiline = M.textwrap.wrap(message, break_long_words=True, width=width)
                multiline = indent.join(multiline)

                colorful.append(multiline)
                content = colorful
            else:
                colorless.append(message)
                content = colorless

            content = separator.join(content) + M.os.linesep
            terminal.write(content)

        if path:
            content = f'{now.iso}{separator}{kind.name}{separator}{message}'
            ret     = append_file(path, content, eol=True, lock=True)

        return ret




class LoggerTimestamp(M.enum.Enum):
    COMPACT = 1
    DATE    = 2
    FULL    = 4
    HUMAN   = 8
    ISO     = 16
    SHORT   = 32
    TIME    = 64




class LoggerType(M.enum.Enum):
    ALERT = 1
    DEBUG = 2
    ERROR = 4
    FATAL = 8
    INFO  = 16
    OKAY  = 32

    def __init__(self, flag, /):
        members = {
            1:  M.types.SimpleNamespace(color='1;33', stderr=False),
            2:  M.types.SimpleNamespace(color='1;36', stderr=True),
            4:  M.types.SimpleNamespace(color='1;31', stderr=True),
            8:  M.types.SimpleNamespace(color='1;35', stderr=True),
            16: M.types.SimpleNamespace(color='1;34', stderr=False),
            32: M.types.SimpleNamespace(color='1;32', stderr=False),
        }

        if flag not in members:
            raise ValueError

        color  = members[flag].color
        names  = [self.name] + [ i for i in self.__class__.__dict__ if i.isalpha() and i.isupper() ]
        length = max( len(i) for i in names )
        tag    = self.name.ljust(length)

        self._colorful  = f'\x1B[{color}m{tag}\x1B[22;39m'
        self._colorless = tag
        self._stderr    = members[flag].stderr




class Alert(Logger):
    def __init__(self, *args, **kwargs):
        super().__init__(LoggerType.ALERT, *args, **kwargs)

class Debug(Logger):
    def __init__(self, *args, **kwargs):
        super().__init__(LoggerType.DEBUG, *args, **kwargs)

class Error(Logger):
    def __init__(self, *args, **kwargs):
        super().__init__(LoggerType.ERROR, *args, **kwargs)

class Fatal(Logger):
    def __init__(self, *args, **kwargs):
        super().__init__(LoggerType.FATAL, *args, **kwargs)

class Info(Logger):
    def __init__(self, *args, **kwargs):
        super().__init__(LoggerType.INFO, *args, **kwargs)

class Okay(Logger):
    def __init__(self, *args, **kwargs):
        super().__init__(LoggerType.OKAY, *args, **kwargs)




class _metaclass_Reader(type):
    _active_readers = M.weakref.WeakSet()
    _class_lock     = M.threading.RLock()
    _eof            = False
    _thread         = M.threading.Thread()
    _wait           = SECOND / 4


    def _fget_wait(cls, /):
        return cls._wait


    def _fset_wait(cls, value, /):
        with cls._class_lock:
            cls._wait = normalize_float(value, minimum=0.0)


    wait = property(fget=_fget_wait, fset=_fset_wait)


    def _activate_reader(cls, reader, /):
        if not isinstance(reader, cls):
            raise TypeError

        with cls._class_lock:
            with reader._instance_lock:
                if not reader.status:
                    cls._active_readers.add(reader)

                    if not cls._thread.is_alive():
                        cls._thread = M.threading.Thread(daemon=False, target=cls._engine)
                        cls._thread.start()


    def _deactivate_reader(cls, reader, /):
        if not isinstance(reader, cls):
            raise TypeError

        with cls._class_lock:
            with reader._instance_lock:
                cls._active_readers.discard(reader)
                reader._buffer.clear()
                reader._sleeper.clear()


    def _engine(cls, /):
        fd       = M.sys.__stdin__.fileno()
        maximum  = 1024
        settings = M.termios.tcgetattr(fd) if M.os.isatty(fd) else None

        try:
            if settings:
                M.tty.setcbreak(fd)

            while cls._active_readers:
                if cls._eof:
                    M.time.sleep(cls.wait)
                elif cls._stdin_is_ready():
                    chunk = M.os.read(fd, maximum)
                    eof   = not len(chunk)

                    if eof:
                        cls._eof = True

                    with cls._class_lock:
                        readers = tuple(cls._active_readers)

                    for reader in readers:
                        with reader._instance_lock:
                            if reader.status:
                                if not eof:
                                    reader._buffer.append(chunk)

                                reader._sleeper.set()
        finally:
            if settings:
                M.termios.tcsetattr(fd, M.termios.TCSADRAIN, settings)


    def _stdin_is_ready(cls, /):
        stdin    = M.sys.__stdin__.fileno()
        rlist    = [stdin]
        empty    = []
        readable = M.select.select(rlist, empty, empty, cls.wait)[0]

        return bool(readable)


    def bye(cls, /):
        with cls._class_lock:
            readers = tuple(cls._active_readers)

            for reader in readers:
                reader.off()




class Reader(metaclass=_metaclass_Reader):
    def _fget_status(self, /):
        return self in self.__class__._active_readers


    status = property(fget=_fget_status)


    def __enter__(self, /):
        self.on()
        return self


    def __exit__(self, exc_type, exc_value, traceback, /):
        self.off()


    def __init__(self, /):
        self._buffer        = M.collections.deque()
        self._instance_lock = M.threading.RLock()
        self._sleeper       = M.threading.Event()


    def off(self, /):
        self.__class__._deactivate_reader(self)


    def on(self, /):
        self.__class__._activate_reader(self)


    def poll(self, /):
        cls = self.__class__
        ret = None

        self._sleeper.wait(cls.wait)

        with self._instance_lock:
            if self._buffer:
                ret = self._buffer.popleft()

            if not cls._eof and not self._buffer:
                self._sleeper.clear()

        if cls._eof and ret is None:
            ret = False

        return ret




class _metaclass_Terminal(type):
    _brush = M.threading.RLock()


    def _fget_brush(cls, /):
        return cls._brush


    brush = property(fget=_fget_brush)




class Terminal(metaclass=_metaclass_Terminal):
    _sequence_clear_line              = '\x1B[2K'
    _sequence_clear_line_from_start   = '\x1B[1K'
    _sequence_clear_line_to_end       = '\x1B[0K'
    _sequence_clear_screen            = '\x1B[2J'
    _sequence_clear_screen_from_start = '\x1B[1J'
    _sequence_clear_screen_to_end     = '\x1B[0J'
    _sequence_clear_scrollback        = '\x1B[3J'
    _sequence_disable_alt_screen      = '\x1B[?1049l'
    _sequence_disable_alt_scroll      = '\x1B[?1007l'
    _sequence_disable_cursor          = '\x1B[?25l'
    _sequence_enable_alt_screen       = '\x1B[?1049h'
    _sequence_enable_alt_scroll       = '\x1B[?1007h'
    _sequence_enable_cursor           = '\x1B[?25h'
    _sequence_move_by_negative_x      = '\x1B[{x}D'
    _sequence_move_by_negative_y      = '\x1B[{y}A'
    _sequence_move_by_positive_x      = '\x1B[{x}C'
    _sequence_move_by_positive_y      = '\x1B[{y}B'
    _sequence_move_home               = '\x1B[H'
    _sequence_move_to_x_y             = '\x1B[{y};{x}H'
    _sequence_move_to_x               = '\x1B[{x}G'
    _sequence_move_to_y               = '\x1B[{y}d'
    _sequence_reset_terminal          = '\x1Bc'
    _sequence_restore_cursor          = '\x1B[u'
    _sequence_save_cursor             = '\x1B[s'


    def _fget_height(self, /):
        return self._get_terminal_size().height


    def _fget_mute(self, /):
        return self._mute


    def _fget_stderr(self, /):
        return self._stream is M.sys.__stderr__


    def _fget_stream(self, /):
        return self._stream


    def _fget_width(self, /):
        return self._get_terminal_size().width


    def _fset_mute(self, value, /):
        with self._instance_lock:
            self._mute = bool(value)


    def _fset_stderr(self, value, /):
        with self._instance_lock:
            self._stream = M.sys.__stderr__ if value else M.sys.__stdout__


    height = property(fget=_fget_height)
    mute   = property(fget=_fget_mute,   fset=_fset_mute)
    stderr = property(fget=_fget_stderr, fset=_fset_stderr)
    stream = property(fget=_fget_stream)
    width  = property(fget=_fget_width)


    def __init__(self, /, *, mute=False, stderr=False):
        self._instance_lock = M.threading.RLock()
        self.mute           = mute
        self.stderr         = stderr


    def _get_terminal_size(self, /):
        fallback = M.types.SimpleNamespace(height=1, width=1)
        fd       = self.stream.fileno()
        height   = 0
        width    = 0

        with M.contextlib.suppress(M.termios.error):
            height, width = M.termios.tcgetwinsize(fd)

        if not height:
            height = fallback.height

        if not width:
            width = fallback.width

        return M.types.SimpleNamespace(height=height, width=width)


    def _print(self, *args, **kwargs):
        cls = self.__class__

        with self._instance_lock:
            mute   = self.mute
            stream = self.stream

        if not mute:
            with Spinner.hide():
                with cls.brush:
                    return print(*args, file=stream, **kwargs)


    def clear_line(self, /, *, end=True, start=True):
        content = ''
        end     = bool(end)
        start   = bool(start)

        if end and start:
            content = self._sequence_clear_line
        elif end:
            content = self._sequence_clear_line_to_end
        elif start:
            content = self._sequence_clear_line_from_start

        if len(content):
            self.write(content)


    def clear_screen(self, /, *, end=True, start=True):
        content = ''
        end     = bool(end)
        start   = bool(start)

        if end and start:
            content = self._sequence_clear_screen
        elif end:
            content = self._sequence_clear_screen_to_end
        elif start:
            content = self._sequence_clear_screen_from_start

        if len(content):
            self.write(content)


    def clear_scrollback(self, /):
        self.write(self._sequence_clear_scrollback)


    def disable_alt_screen(self, /):
        self.write(self._sequence_disable_alt_screen)


    def disable_alt_scroll(self, /):
        self.write(self._sequence_disable_alt_scroll)


    def disable_cursor(self, /):
        self.write(self._sequence_disable_cursor)


    def enable_alt_screen(self, /):
        self.write(self._sequence_enable_alt_screen)


    def enable_alt_scroll(self, /):
        self.write(self._sequence_enable_alt_scroll)


    def enable_cursor(self, /):
        self.write(self._sequence_enable_cursor)


    def move_by(self, /, *, x=None, y=None):
        content = ''
        minimum = 0
        x       = minimum if x is None else normalize_integer(x)
        y       = minimum if y is None else normalize_integer(y)

        if x > minimum:
            content += self._sequence_move_by_positive_x.format(x=x)
        elif x < minimum:
            content += self._sequence_move_by_negative_x.format(x=abs(x))

        if y > minimum:
            content += self._sequence_move_by_positive_y.format(y=y)
        elif y < minimum:
            content += self._sequence_move_by_negative_y.format(y=abs(y))

        if len(content):
            self.write(content)


    def move_home(self, /):
        self.write(self._sequence_move_home)


    def move_to(self, /, *, x=None, y=None):
        content = ''
        minimum = 0
        x       = minimum if x is None else normalize_integer(x, minimum=minimum)
        y       = minimum if y is None else normalize_integer(y, minimum=minimum)

        if x and y:
            content = self._sequence_move_to_x_y.format(x=x, y=y)
        elif x:
            content = self._sequence_move_to_x.format(x=x)
        elif y:
            content = self._sequence_move_to_y.format(y=y)

        if len(content):
            self.write(content)


    def reset_terminal(self, /):
        self.write(self._sequence_reset_terminal)


    def restore_cursor(self, /):
        self.write(self._sequence_restore_cursor)


    def save_cursor(self, /):
        self.write(self._sequence_save_cursor)


    def write(self, content, /, *, flush=True):
        content = str(content)
        empty   = ''
        flush   = bool(flush)

        self._print(content, end=empty, flush=flush)




class _metaclass_Spinner(type):
    _active_spinners    = []
    _break_engine       = M.threading.Event()
    _class_lock         = M.threading.RLock()
    _default_colors     = ( 21,  27,  33,  39,  45,
                            51,  50,  49,  48,  47,
                            46,  82, 118, 154, 190,
                           226, 220, 214, 208, 202,
                           196, 197, 198, 199, 200,
                           201, 165, 129,  93,  57,)
    _default_colors     = _default_colors + _default_colors[-2:0:-1]
    _default_glyphs     = ('|', '/', '—', '\\')
    _default_message    = ''
    _default_tempo      = SECOND / 4
    _hide_depth         = 0
    _template_colorful  = '\x1B[2K' + '\r\x1B[38;5;{color}m{glyph}\x1B[39m{separator}{message}\r'
    _template_colorless = '\x1B[2K' + '\r{glyph}{separator}{message}\r'
    _terminal           = Terminal(mute=not M.sys.__stderr__.isatty(), stderr=True)
    _thread             = M.threading.Thread()

    def _fget_current(cls, /):
        with cls._class_lock:
            return cls._active_spinners[-1] if cls._active_spinners else False


    def _fget_stderr(cls, /):
        return cls._terminal.stderr


    def _fset_stderr(cls, value, /):
        value         = bool(value)
        terminal      = Terminal(stderr=value)
        terminal.mute = not terminal.stream.isatty()

        with cls._class_lock:
            cls._terminal = terminal


    current = property(fget=_fget_current)
    stderr  = property(fget=_fget_stderr, fset=_fset_stderr)


    def _activate_spinner(cls, spinner, /):
        if not isinstance(spinner, cls):
            raise TypeError

        with cls._class_lock:
            previous = cls.current

            if spinner is not previous:
                if previous:
                    cls._break_engine.set()
                elif not cls._hide_depth:
                    cls._undo_cursor_line()

                if spinner in cls._active_spinners:
                    cls._active_spinners.remove(spinner)

                spinner._ticker.reset()
                cls._active_spinners.append(spinner)
                cls._start_engine()


    def _deactivate_spinner(cls, spinner, /):
        if not isinstance(spinner, cls):
            raise TypeError

        with cls._class_lock:
            previous = cls.current

            if spinner in cls._active_spinners:
                cls._active_spinners.remove(spinner)

            if spinner is previous:
                cls._break_engine.set()

            if not cls.current and not cls._hide_depth:
                cls._redo_cursor_line()


    def _engine(cls, /):
        while True:
            with cls._class_lock:
                if cls.current:
                    spinner = cls.current
                    cls._break_engine.clear()
                else:
                    return

            while not cls._break_engine.is_set():
                with cls._class_lock:
                    if not cls._hide_depth:
                        spinner._print_frame()

                cls._break_engine.wait(spinner.tempo)


    def _enter_hide(cls, /, *, fake=False):
        with cls._class_lock:
            cls._hide_depth += 1

            if not fake and cls.current and cls._hide_depth == 1:
                cls._redo_cursor_line()


    def _exit_hide(cls, /, *, fake=False):
        with cls._class_lock:
            if not fake and cls.current and cls._hide_depth == 1:
                cls._undo_cursor_line()

            cls._hide_depth -= 1


    @M.contextlib.contextmanager
    def _hide(cls, /, *, fake=False):
        fake = bool(fake)

        cls._enter_hide(fake=fake)

        try:
            yield
        finally:
            cls._exit_hide(fake=fake)


    def _redo_cursor_line(cls, /):
        with cls._class_lock:
            with Terminal.brush:
                cls._terminal.clear_line()
                cls._terminal.enable_cursor()


    def _start_engine(cls, /):
        with cls._class_lock:
            if not cls._thread.is_alive():
                cls._thread = M.threading.Thread(daemon=True, target=cls._engine)
                cls._thread.start()


    def _undo_cursor_line(cls, /):
        with cls._class_lock:
            with Terminal.brush:
                cls._terminal.disable_cursor()

                if cls.current:
                    cls.current._print_frame()


    def bye(cls, /):
        with cls._class_lock:
            while cls.current:
                cls.current.off()


    def hide(cls, /):
        return cls._hide()




class Spinner(metaclass=_metaclass_Spinner):
    def _fget_colors(self, /):
        return self._colors


    def _fget_glyphs(self, /):
        return self._glyphs


    def _fget_message(self, /):
        return self._message


    def _fget_status(self, /):
        return self in self.__class__._active_spinners


    def _fget_tempo(self, /):
        return self._tempo


    def _fset_colors(self, value, /):
        value = [ clamp(int(i), minimum=0, maximum=255) for i in value ]

        with self._instance_lock:
            self._animation.colors = M.collections.deque(value)
            self._colors           = tuple(value)


    def _fset_glyphs(self, value, /):
        value = [ normalize_text(i, printable=True, uniform=True) for i in value ]
        value = [ i for i in value if len(i) == 1 ]

        with self._instance_lock:
            self._animation.glyphs = M.collections.deque(value)
            self._glyphs           = tuple(value)


    def _fset_message(self, value, /):
        empty = ''

        if callable(value):
            def sandbox():
                try:
                    return normalize_text(value(), full=True)
                except Exception:
                    return empty

            function = sandbox
        else:
            value    = normalize_text(value, full=True)
            function = lambda: value

        with self._instance_lock:
            self._animation.message = function
            self._message           = value


    def _fset_tempo(self, value, /):
        with self._instance_lock:
            self._tempo  = normalize_float(value, minimum=0.0)
            self._ticker = Chrono(timeout=self.tempo)


    colors  = property(fget=_fget_colors,  fset=_fset_colors)
    glyphs  = property(fget=_fget_glyphs,  fset=_fset_glyphs)
    message = property(fget=_fget_message, fset=_fset_message)
    status  = property(fget=_fget_status)
    tempo   = property(fget=_fget_tempo,   fset=_fset_tempo)


    def __enter__(self, /):
        self.on()
        return self


    def __exit__(self, exc_type, exc_value, traceback, /):
        self.off()


    def __init__(self, /, *, auto=False, colors=None, glyphs=None, message=None, tempo=None):
        auto                = bool(auto)
        cls                 = self.__class__
        self._animation     = M.types.SimpleNamespace()
        self._instance_lock = M.threading.RLock()
        self.colors         = cls._default_colors  if colors  is None else colors
        self.glyphs         = cls._default_glyphs  if glyphs  is None else glyphs
        self.message        = cls._default_message if message is None else message
        self.tempo          = cls._default_tempo   if tempo   is None else tempo

        if auto:
            self.on()


    def _print_frame(self, /):
        cls   = self.__class__
        frame = self._render_frame()

        with cls._hide(fake=True):
            cls._terminal.write(frame)


    def _render_frame(self, /):
        animation = self._animation
        cls       = self.__class__
        empty     = ''
        space     = ' '

        with self._instance_lock:
            if self._ticker.expired:
                self._ticker.reset()
                animation.colors.rotate(-1)
                animation.glyphs.rotate(-1)

            color    = animation.colors[0] if animation.colors else empty
            colorful = animation.colors and animation.glyphs
            glyph    = animation.glyphs[0] if animation.glyphs else empty
            message  = animation.message

        message   = message()
        separator = space if len(glyph) and len(message) else empty
        maximum   = max(cls._terminal.width - len(glyph) - len(separator), 0)
        message   = message[0:maximum]
        template  = cls._template_colorful if colorful else cls._template_colorless

        return template.format(color=color, glyph=glyph, message=message, separator=separator)


    def off(self, /):
        self.__class__._deactivate_spinner(self)


    def on(self, /):
        self.__class__._activate_spinner(self)




# vim: et fenc=utf-8 nobomb sts=4 sw=4 ts=4
