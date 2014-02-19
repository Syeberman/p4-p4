#!/usr/bin/env python
#
# p4-p4.py -- A tool for bidirectional operation between two Perforce depots.
#
# Adapted from Git's git-p4.py:
#   Author: Simon Hausmann <simon@lst.de>
#   Copyright: 2007 Simon Hausmann <simon@lst.de>
#              2007 Trolltech ASA
#   License: MIT <http://www.opensource.org/licenses/mit-license.php>
#
#   Permission is hereby granted, free of charge, to any person obtaining a copy
#    of this software and associated documentation files (the "Software"), to deal
#    in the Software without restriction, including without limitation the rights
#    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#    copies of the Software, and to permit persons to whom the Software is
#    furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in
#    all copies or substantial portions of the Software.
#
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
#    THE SOFTWARE.

import sys
if sys.hexversion < 0x02040000:
    # The limiter is the subprocess module
    sys.stderr.write("p4-p4: requires Python 2.4 or later.\n")
    sys.exit(1)
import os
import optparse
import pprint
import marshal
import subprocess
import tempfile
import time
import platform
import re
import shutil
import stat

try:
    from subprocess import CalledProcessError
except ImportError:
    # from python2.7:subprocess.py
    # Exception classes used by this module.
    class CalledProcessError(Exception):
        """This exception is raised when a process run by check_call() returns
        a non-zero exit status.  The exit status will be stored in the
        returncode attribute."""
        def __init__(self, returncode, cmd):
            self.returncode = returncode
            self.cmd = cmd
        def __str__(self):
            return "Command '%s' returned non-zero exit status %d" % (self.cmd, self.returncode)

verbose = False

# Only labels/tags matching this will be imported/exported
defaultLabelRegexp = r'[a-zA-Z0-9_\-.]+$'

def die(msg):
    if verbose:
        raise Exception(msg)
    else:
        sys.stderr.write(msg + "\n")
        sys.exit(1)

def write_pipe(c, stdin):
    if verbose:
        sys.stderr.write('Writing pipe: %s\n' % str(c))

    expand = isinstance(c,basestring)
    p = subprocess.Popen(c, stdin=subprocess.PIPE, shell=expand)
    pipe = p.stdin
    val = pipe.write(stdin)
    pipe.close()
    if p.wait():
        die('Command failed: %s' % str(c))

    return val

def read_pipe(c, ignore_error=False):
    if verbose:
        sys.stderr.write('Reading pipe: %s\n' % str(c))

    expand = isinstance(c,basestring)
    p = subprocess.Popen(c, stdout=subprocess.PIPE, shell=expand)
    pipe = p.stdout
    val = pipe.read()
    if p.wait() and not ignore_error:
        die('Command failed: %s' % str(c))

    return val

def read_pipe_lines(c):
    if verbose:
        sys.stderr.write('Reading pipe: %s\n' % str(c))

    expand = isinstance(c, basestring)
    p = subprocess.Popen(c, stdout=subprocess.PIPE, shell=expand)
    pipe = p.stdout
    val = pipe.readlines()
    if pipe.close() or p.wait():
        die('Command failed: %s' % str(c))

    return val

def system(cmd):
    expand = isinstance(cmd,basestring)
    if verbose:
        sys.stderr.write("executing %s\n" % str(cmd))
    retcode = subprocess.call(cmd, shell=expand)
    if retcode:
        raise CalledProcessError(retcode, cmd)

#
# Canonicalize the p4 type and return a tuple of the
# base type, plus any modifiers.  See "p4 help filetypes"
# for a list and explanation.
#
def split_p4_type(p4type):

    p4_filetypes_historical = {
        "ctempobj": "binary+Sw",
        "ctext": "text+C",
        "cxtext": "text+Cx",
        "ktext": "text+k",
        "kxtext": "text+kx",
        "ltext": "text+F",
        "tempobj": "binary+FSw",
        "ubinary": "binary+F",
        "uresource": "resource+F",
        "uxbinary": "binary+Fx",
        "xbinary": "binary+x",
        "xltext": "text+Fx",
        "xtempobj": "binary+Swx",
        "xtext": "text+x",
        "xunicode": "unicode+x",
        "xutf16": "utf16+x",
    }
    if p4type in p4_filetypes_historical:
        p4type = p4_filetypes_historical[p4type]
    mods = ""
    s = p4type.split("+")
    base = s[0]
    mods = ""
    if len(s) > 1:
        mods = s[1]
    return (base, mods)

#
# Given a type base and modifier, return a regexp matching
# the keywords that can be expanded in the file
#
def p4_keywords_regexp_for_type(base, type_mods):
    if base in ("text", "unicode", "binary"):
        kwords = None
        if "ko" in type_mods:
            kwords = 'Id|Header'
        elif "k" in type_mods:
            kwords = 'Id|Header|Author|Date|DateTime|Change|File|Revision'
        else:
            return None
        pattern = r"""
            \$              # Starts with a dollar, followed by...
            (%s)            # one of the keywords, followed by...
            (:[^$\n]+)?     # possibly an old expansion, followed by...
            \$              # another dollar
            """ % kwords
        return pattern
    else:
        return None

#
# Given a file, return a regexp matching the possible
# RCS keywords that will be expanded, or None for files
# with kw expansion turned off.
#
def p4_keywords_regexp_for_file(file):
    if not os.path.exists(file):
        return None
    else:
        (type_base, type_mods) = split_p4_type(p4_type(file))
        return p4_keywords_regexp_for_type(type_base, type_mods)

class P4DictUnflattener:
    """You'd expect Perforce to represent things like, say, revision history, like this:
        {"depotFile": "//depot/test", [{"rev": 1, "change": 15}, {"rev": 2, "change": 301}]}
    But it actually flattens this all into a single dict, adding subscripts to key names:
        {"depotFile": "//depot/test", "rev0": 1, "change0": 15, "rev1": 2, "change1": 301}
    This class makes accessing these values a little easier by providing a minimal list- and dict-
    interface for the "elements" of the "list":
        for elem in P4DictUnflattener(d, "rev"): # stop iterating when "rev%s"%i doesn't exist
            print elem["change"]                 # automatically translates to "change%s"%i

    To complicate even further, the "values" of the "elements" of the "list" can be "lists" too.
    P4DictUnflattener accepts P4DictUnflattener elements to deal with these sub-lists:
        for elem in P4DictUnflattener(d, "rev"):
            for sub_elem in P4DictUnflattener(elem, "how"):
                print sub_elem["how"], sub_elem["file"] # ie "how%s,%s"%(i,j)
    """
    def __init__(self, p4Dict, canary):
        if isinstance(p4Dict, P4DictUnflattener.Element):
            self.p4Dict = p4Dict.p4Dict
            self.suffix = p4Dict.suffix+","
        elif isinstance(p4Dict, dict):
            self.p4Dict = p4Dict
            self.suffix = ""
        else:
            raise TypeError
        self.canary = canary
    def __iter__(self):
        i = 0
        while True:
            sub_suffix = self.suffix+str(i)
            if self.canary+sub_suffix not in self.p4Dict: break
            yield P4DictUnflattener.Element(self.p4Dict, sub_suffix)
            i += 1

    class Element:
        """For use via P4DictUnflattener."""
        def __init__(self, p4Dict, suffix):
            self.p4Dict = p4Dict
            self.suffix = suffix
        def __getitem__(self, key):
            return self.p4Dict[key+self.suffix]
        def get(self, key, default=None):
            return self.p4Dict.get(key+self.suffix, default)


class P4Repo:
    """Represents a particular connection to a Perforce server."""
    def __init__(self, clientRoot):
        """Connects to the Perforce server/client at the given client root.  Assumes there's a
        P4CONFIG file in place that specifies connection settings."""
        self.clientRoot = os.path.abspath(clientRoot)
        self._version_string = None

        # Cache the results of certain operations to improve the dev/test cycle
        # FIXME remove for release?
        self.cacheDir = os.path.join(clientRoot, ".p4-p4-cache")
        if os.path.exists(self.cacheDir):
            if verbose: print "Using cached server information at %r" % self.cacheDir
        infoList = self.cmdList("info")
        if len(infoList) != 1:
            die('Output from "info" is %d lines, expecting 1' % len(infoList))
        self.info = infoList[0]

        # Check that the client settings appear correct, then create the client cache if needed.
        # Perforce sets clientName to *unknown* if the client doesn't exist.
        unknown = "*unknown*"
        self.clientName = self.info.get("clientName", unknown)
        if self.clientName == unknown:
            die("unknown client for %r"% clientRoot)
        server_cr = os.path.normcase(os.path.normpath(self.info["clientRoot"]))
        given_cr = os.path.normcase(os.path.normpath(clientRoot))
        if server_cr != given_cr:
            die("Perforce settings at %r do not match intended client" % clientRoot)

    def build_cmd(self, cmd):
        """Build a suitable p4 command line.

        This consolidates building and returning a p4 command line into one
        location. It means that hooking into the environment, or other configuration
        can be done more easily.
        """
        # Using -d is an alternative to using subprocess' cwd argument: it runs the command
        # relative to that directory, including pulling settings from P4CONFIG files
        real_cmd = ["p4", "-d", self.clientRoot]

        if 0: # FIXME pull this info from another location
            user = gitConfig("git-p4.user")
            if len(user) > 0:
                real_cmd += ["-u",user]

            password = gitConfig("git-p4.password")
            if len(password) > 0:
                real_cmd += ["-P", password]

            port = gitConfig("git-p4.port")
            if len(port) > 0:
                real_cmd += ["-p", port]

            host = gitConfig("git-p4.host")
            if len(host) > 0:
                real_cmd += ["-H", host]

            client = gitConfig("git-p4.client")
            if len(client) > 0:
                real_cmd += ["-c", client]

        if isinstance(cmd,basestring):
            real_cmd = ' '.join(real_cmd) + ' ' + cmd
        else:
            real_cmd += cmd
        return real_cmd

    def write_pipe(self, c, stdin):
        real_cmd = self.build_cmd(c)
        return write_pipe(real_cmd, stdin)

    def read_pipe(self, c, ignore_error=False):
        real_cmd = self.build_cmd(c)
        return read_pipe(real_cmd, ignore_error)

    def read_pipe_lines(self, c):
        """Specifically invoke p4 on the command supplied. """
        real_cmd = self.build_cmd(c)
        return read_pipe_lines(real_cmd)

    def has_command(self, cmd):
        """Ask p4 for help on this command.  If it returns an error, the
        command does not exist in this version of p4."""
        real_cmd = self.build_cmd(["help", cmd])
        p = subprocess.Popen(real_cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
        p.communicate()
        return p.returncode == 0

    def has_move_command(self):
        """See if the move command exists, that it supports -k, and that
        it has not been administratively disabled.  The arguments
        must be correct, but the filenames do not have to exist.  Use
        ones with wildcards so even if they exist, it will fail."""

        if not self.has_command("move"):
            return False
        cmd = self.build_cmd(["move", "-k", "@from", "@to"])
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (out, err) = p.communicate()
        # return code will be 1 in either case
        if err.find("Invalid option") >= 0:
            return False
        if err.find("disabled") >= 0:
            return False
        # assume it failed because @... was invalid changelist
        return True

    def system(self, cmd):
        """Specifically invoke p4 as the system command. """
        real_cmd = self.build_cmd(cmd)
        expand = isinstance(real_cmd, basestring)
        retcode = subprocess.call(real_cmd, shell=expand)
        if retcode:
            raise CalledProcessError(retcode, real_cmd)

    def version_string(self):
        """Read the version string, showing just the last line, which
        hopefully is the interesting version bit.

        $ p4 -V
        Perforce - The Fast Software Configuration Management System.
        Copyright 1995-2011 Perforce Software.  All rights reserved.
        Rev. P4/NTX86/2011.1/393975 (2011/12/16).
        """
        if not self._version_string:
            a = self.read_pipe_lines(["-V"])
            self._version_string = a[-1].rstrip()
        return self._version_string

    def integrate(self, src, dest):
        self.system(["integrate", "-Dt", wildcard_encode(src), wildcard_encode(dest)])

    def sync(self, f, *options):
        self.system(["sync"] + list(options) + [wildcard_encode(f)])

    def add(self, f, filetype):
        cmd = ["add", "-t", filetype, "-I"]
        # forcibly add file names with wildcards
        if wildcard_present(f): cmd.append("-f")
        cmd.append(f)
        self.system(cmd)

    def delete(self, f):
        self.system(["delete", wildcard_encode(f)])

    def edit(self, f, filetype):
        self.system(["edit", "-t", filetype, wildcard_encode(f)])

    def revert(self, f):
        self.system(["revert", wildcard_encode(f)])

    def reopen(self, type, f):
        self.system(["reopen", "-t", type, wildcard_encode(f)])

    def move(self, src, dest):
        self.system(["move", "-k", wildcard_encode(src), wildcard_encode(dest)])

    def advance_change_counter(self, value):
        """This command is dangerous and requires admin access."""
        current = int(self.read_pipe(["counter", "change"]).strip())
        if current > value: raise ValueError("I refuse to decrease the change counter (%d) to %d" % (current, value))
        if current == value: return
        self.read_pipe(["counter", "-f", "change", str(value)])

    def change_out(self, change="default"):
        cmd = ["change", "-o"]
        if change != "default": cmd.append(str(change))
        result = self.cmdList(cmd)
        if len(result) != 1:
            die('Output from "change" is %d lines, expecting 1' % len(result))
        return result[0]

    def submit(self, description, change="default"):
        """description must be in the format as returned by change_out.  Returns the result of 
        "submit".
        """
        cmd = ["submit", "-i", "-f", "submitunchanged"]
        if change != "default": cmd.extend(["-c", str(change)])
        return self.cmdList(cmd, stdin=marshal.dumps(description))

    def change_in(self, description):
        """Changes a pending or submitted change; requires admin access.  Returns the result of 
        "change".  The changelist is taken from description["Change"].
        """
        return self.cmdList(["change", "-f", "-i"], stdin=marshal.dumps(description))

    def describe(self, change):
        """Make sure it returns a valid result by checking for
        the presence of field "time".  Return a dict of the
        results."""

        # Change descriptions don't often change, so cache them
        cache_name = os.path.join("describe", str(change))
        ds = self.cmdList(["describe", "-s", str(change)], cache_name=cache_name)
        if "p4ExitCode" in ds[-1]: 
            die("".join(x.get("data", "") for x in ds))
        if len(ds) != 1:
            die("p4 describe -s %d did not return 1 result: %s" % (change, str(ds)))

        d = ds[0]
        if "code" in d:
            if d["code"] == "error":
                die("p4 describe -s %d returned error code: %s" % (change, str(d)))

        if "time" not in d:
            die("p4 describe -s %d returned no \"time\": %s" % (change, str(d)))

        return d

    #
    # return the raw p4 type of a file (text, text+ko, etc)
    #
    def file_type(self, f):
        results = self.cmdList(["fstat", "-T", "headType", wildcard_encode(f)])
        return results[0]['headType']

    def setExecBit(self, file, mode):
        # Reopens an already open file and changes the execute bit to match
        # the execute bit setting in the passed in mode.

        p4Type = "+x"

        if not isModeExec(mode):
            p4Type = self.getOpenedType(file)
            p4Type = re.sub('^([cku]?)x(.*)', '\\1\\2', p4Type)
            p4Type = re.sub('(.*?\+.*?)x(.*?)', '\\1\\2', p4Type)
            if p4Type[-1] == "+":
                p4Type = p4Type[0:-1]

        self.reopen(p4Type, file)

    def getOpenedType(self, file):
        # Returns the perforce file type for the given file.

        result = self.read_pipe(["opened", wildcard_encode(file)])
        match = re.match(".*\((.+)\)\r?$", result)
        if match:
            return match.group(1)
        else:
            die("Could not determine file type for %s (result: '%s')" % (file, result))

    # Return the set of all p4 labels
    def getLabels(self, depotPaths):
        labels = set()
        if isinstance(depotPaths,basestring):
            depotPaths = [depotPaths]

        for l in self.cmdList(["labels"] + ["%s..." % p for p in depotPaths]):
            label = l['label']
            labels.add(label)

        return labels

    def cmdList(self, cmd, stdin=None, stdin_mode='w+b', cb=None, cache_name=None):
        """If cache_name is given ('client', say), a .py.marshal file is created in self.cacheDir
        to cache the results of the operation, and used on subsequent calls instead of going direct
        to Perforce.  This is intended to improve the dev/test cycle, and may be removed."""
        if cache_name:
            assert not cb
            cache_path = os.path.join(self.cacheDir, cache_name+".py.marshal")
            if os.path.exists(cache_path):
                with open(cache_path, "rb") as infile:
                    return marshal.load(infile)

        if isinstance(cmd,basestring):
            cmd = "-G " + cmd
            expand = True
        else:
            cmd = ["-G"] + cmd
            expand = False

        cmd = self.build_cmd(cmd)
        if verbose:
            sys.stderr.write("Opening pipe: %s\n" % str(cmd))

        # Use a temporary file to avoid deadlocks without
        # subprocess.communicate(), which would put another copy
        # of stdout into memory.
        stdin_file = None
        if stdin is not None:
            stdin_file = tempfile.TemporaryFile(prefix='p4-stdin', mode=stdin_mode)
            if isinstance(stdin,basestring):
                stdin_file.write(stdin)
            else:
                for i in stdin:
                    stdin_file.write(i + '\n')
            stdin_file.flush()
            stdin_file.seek(0)

        p4 = subprocess.Popen(cmd,
                            shell=expand,
                            stdin=stdin_file,
                            stdout=subprocess.PIPE)

        result = []
        try:
            while True:
                entry = marshal.load(p4.stdout)
                if cb is not None:
                    cb(entry)
                else:
                    result.append(entry)
        except EOFError:
            pass
        exitCode = p4.wait()
        if exitCode != 0:
            entry = {}
            entry["p4ExitCode"] = exitCode
            result.append(entry)

        if cache_name:
            try: os.makedirs(os.path.dirname(cache_path))
            except OSError: pass
            with open(cache_path, "wb") as outfile:
                marshal.dump(result, outfile)

        return result

    def where(self, depotPath):
        if not depotPath.endswith("/"):
            depotPath += "/"
        depotPath = depotPath + "..."
        outputList = self.cmdList(["where", depotPath])
        output = None
        for entry in outputList:
            if "depotFile" in entry:
                if entry["depotFile"] == depotPath:
                    output = entry
                    break
            elif "data" in entry:
                data = entry.get("data")
                space = data.find(" ")
                if data[:space] == depotPath:
                    output = entry
                    break
        if output == None:
            return ""
        if output["code"] == "error":
            return ""
        clientPath = ""
        if "path" in output:
            clientPath = output.get("path")
        elif "data" in output:
            data = output.get("data")
            lastSpace = data.rfind(" ")
            clientPath = data[lastSpace + 1:]

        if clientPath.endswith("..."):
            clientPath = clientPath[:-3]
        return clientPath

    def changesForPaths(self, depotPaths, changeRange):
        assert depotPaths
        cmd = ['changes']
        for p in depotPaths:
            cmd += ["%s...%s" % (p, changeRange)]
        output = self.read_pipe_lines(cmd)

        changes = {}
        for line in output:
            changeNum = int(line.split(" ")[1])
            changes[changeNum] = True

        changelist = changes.keys()
        changelist.sort()
        return changelist

    def getClient(self, cache_name=None):
        # Large clients can take a long time to parse, so cache the info
        try: return self._client
        except AttributeError: pass
        clientOutput = self.cmdList("client -o", cache_name=cache_name)
        if len(clientOutput) != 1:
            die('Output from "client -o" is %d lines, expecting 1' % len(clientOutput))
        self._client = clientOutput[0]
        return self._client

    def getClientView(self):
        """Look at the p4 client spec, create a View() object that contains
        all the mappings, and return it."""
        entry = self.getClient(cache_name="client")

        # hold this new View
        view = View()

        # append the lines, in order, to the view
        for elem in P4DictUnflattener(entry, "View"):
            view.append(elem["View"])

        return view

    def userId(self):
        if self.myUserId:
            return self.myUserId

        results = self.cmdList("user -o")
        for r in results:
            if r.has_key('User'):
                self.myUserId = r['User']
                return r['User']
        die("Could not find your p4 user id")

    def userIsMe(self, p4User):
        # return True if the given p4 user is actually me
        me = self.userId()
        if not p4User or p4User != me:
            return False
        else:
            return True

    def buildUserMap(self, cache_name=None):
        if hasattr(self, "users"): return
        self.users = {}
        self.emails = {}

        for output in self.cmdList("users", cache_name=cache_name):
            if not output.has_key("User"):
                continue
            self.users[output["User"]] = output["FullName"] + " <" + output["Email"] + ">"
            self.emails[output["Email"]] = output["User"]

        s = ''
        for (key, val) in self.users.items():
            s += "%s\t%s\n" % (key.expandtabs(1), val.expandtabs(1))

    def _convert_client_path(self, client_prefix, clientFile):
        # chop off //client/ part to make it relative
        if not clientFile.startswith(client_prefix):
            die("No prefix '%s' on clientFile '%s'" %
                (client_prefix, clientFile))
        return clientFile[len(client_prefix):]

    def update_client_spec_path_cache(self):
        """ Caching file paths by "p4 fstat" batch query """
        if hasattr(self, "client_spec_path_cache"): return

        # cache results of "p4 fstat" to lookup client file locations
        self.client_spec_path_cache = {}
        client_prefix = "//%s/" % self.clientName

        # Get the depotFile->clientFile mapping in Perforce syntax (-Op) for all files (//...) that
        # are mapped in this client view (-Rc)
        fstat_result = self.cmdList(["fstat", "-T", "depotFile clientFile", "-Op", "-Rc", "//..."],
                cache_name="client-fstat-where")
        for res in fstat_result:
            if "code" in res and res["code"] == "error":
                # assume error is "... file(s) not in client view"
                continue
            if "clientFile" not in res:
                die("No clientFile in 'p4 fstat' output")
            if "unmap" in res:
                # it will list all of them, but only one not unmap-ped
                continue
            self.client_spec_path_cache[res['depotFile']] = \
                    self._convert_client_path(client_prefix, res["clientFile"])

    def map_to_relative_path(self, depot_path):
        """Return the relative location in the client where this
           depot file should live.  Returns "" if the file should
           not be mapped in the client."""
        return self.client_spec_path_cache.get(depot_path, "")

    def update_client_filelog_cache(self, depot_path):
        """Update the cache with contributory file history of the given file."""
        # "filelog -1s" to get exact contributory integration history of the given path
        # TODO If we could do this in a fast-ish batch command for all files mapped to the client,
        # then we could remove the need for --changesfile
        filelog_result = self.cmdList(["filelog", "-1s", depot_path])
        if len(filelog_result) != 1:
            die('Output from "filelog" is %d lines, expecting 1' % len(filelog_result))
        filelog_info = filelog_result[0]
        pprint.pprint(filelog_info) # FIXME remove
        for rev_info in P4DictUnflattener(filelog_info, "rev"):
            change_cache = self.client_filelog_cache.setdefault(rev_info["change"], {})
            file_cache = change_cache[depot_path] = {}
            # Most filelog information also comes via describe, but integrationAction is unique
            file_cache["rev"] = rev_info["rev"]
            file_cache["action"] = rev_info["action"]
            file_cache["integrationActions"] = [
                    dict(how=x["how"], file=x["file"], srev=x["srev"], erev=x["erev"])
                        for x in P4DictUnflattener(rev_info, "how")
                    ]

    def file_revision_filelog(self, change, depot_path):
        # Caching filelog commands in individual files is problematic because the cached filename
        # would have to be based somehow on the depot filename.  So, just keep one large cache.
        if not hasattr(self, "client_filelog_cache"):
            self.client_filelog_cache_path = os.path.join(self.cacheDir, "client-filelog-1s.py.marshal")
            if os.path.exists(self.client_filelog_cache_path):
                with open(self.client_filelog_cache_path, "rb") as infile:
                    self.client_filelog_cache = marshal.load(infile)
            else:
                try: os.makedirs(os.path.dirname(self.client_filelog_cache_path))
                except OSError: pass
                self.client_filelog_cache = {}

        # We might already have information on this file
        try: return self.client_filelog_cache[change][depot_path]
        except: pass

        # We haven't run filelog on this file yet, so do so, update the cache, and try again
        self.update_client_filelog_cache(depot_path)
        with open(self.client_filelog_cache_path, "wb") as outfile:
            marshal.dump(self.client_filelog_cache, outfile)
        return self.client_filelog_cache[change][depot_path]


def extractSettingsGitLog(log):
    raise NotImplementedError( "Adapt to Perforce" )
    values = {}
    for line in log.split("\n"):
        line = line.strip()
        m = re.search (r"^ *\[git-p4: (.*)\]$", line)
        if not m:
            continue

        assignments = m.group(1).split (':')
        for a in assignments:
            vals = a.split ('=')
            key = vals[0].strip()
            val = ('='.join (vals[1:])).strip()
            if val.endswith ('\"') and val.startswith('"'):
                val = val[1:-1]

            values[key] = val

    paths = values.get("depot-paths")
    if not paths:
        paths = values.get("depot-path")
    if paths:
        values['depot-paths'] = paths.split(',')
    return values

def p4PathStartsWith(path, prefix):
    # This method tries to remedy a potential mixed-case issue:
    #
    # If UserA adds  //depot/DirA/file1
    # and UserB adds //depot/dira/file2
    #
    # we may or may not have a problem. If you have core.ignorecase=true,
    # we treat DirA and dira as the same directory
    if gitConfigBool("core.ignorecase"):
        return path.lower().startswith(prefix.lower())
    return path.startswith(prefix)

#
# P4 wildcards are not allowed in filenames.  P4 complains
# if you simply add them, but you can force it with "-f", in
# which case it translates them into %xx encoding internally.
#
def wildcard_decode(path):
    # Search for and fix just these four characters.  Do % last so
    # that fixing it does not inadvertently create new %-escapes.
    # Cannot have * in a filename in windows; untested as to
    # what p4 would do in such a case.
    if not platform.system() == "Windows":
        path = path.replace("%2A", "*")
    path = path.replace("%23", "#") \
               .replace("%40", "@") \
               .replace("%25", "%")
    return path

def wildcard_encode(path):
    # do % first to avoid double-encoding the %s introduced here
    path = path.replace("%", "%25") \
               .replace("*", "%2A") \
               .replace("#", "%23") \
               .replace("@", "%40")
    return path

def wildcard_present(path):
    m = re.search("[*#@%]", path)
    return m is not None

class Command:
    def __init__(self):
        self.usage = "usage: %prog [options]"
        self.verbose = False

class P4Debug(Command):
    def __init__(self):
        Command.__init__(self)
        self.options = []
        self.description = "A tool to debug the output of p4 -G."

    def run(self, args):
        j = 0
        for output in p4CmdList(args):
            print 'Element: %d' % j
            j += 1
            pprint.pprint( output )
        return True

class P4RollBack(Command):
    def __init__(self):
        raise NotImplementedError( "Adapt to Perforce" )
        Command.__init__(self)
        self.options = [
            optparse.make_option("--local", dest="rollbackLocalBranches", action="store_true")
        ]
        self.description = "A tool to debug the multi-branch import. Don't use :)"
        self.rollbackLocalBranches = False

    def run(self, args):
        raise NotImplementedError( "Adapt to Perforce" )
        if len(args) != 1:
            return False
        maxChange = int(args[0])

        if "p4ExitCode" in p4Cmd("changes -m 1"):
            die("Problems executing p4");

        if self.rollbackLocalBranches:
            refPrefix = "refs/heads/"
            lines = read_pipe_lines("git rev-parse --symbolic --branches")
        else:
            refPrefix = "refs/remotes/"
            lines = read_pipe_lines("git rev-parse --symbolic --remotes")

        for line in lines:
            if self.rollbackLocalBranches or (line.startswith("p4/") and line != "p4/HEAD\n"):
                line = line.strip()
                ref = refPrefix + line
                log = extractLogMessageFromGitCommit(ref)
                settings = extractSettingsGitLog(log)

                depotPaths = settings['depot-paths']
                change = settings['change']

                changed = False

                if len(p4Cmd("changes -m 1 "  + ' '.join (['%s...@%s' % (p, maxChange)
                                                           for p in depotPaths]))) == 0:
                    print "Branch %s did not exist at change %s, deleting." % (ref, maxChange)
                    system("git update-ref -d %s `git rev-parse %s`" % (ref, ref))
                    continue

                while change and int(change) > maxChange:
                    changed = True
                    if self.verbose:
                        print "%s is at %s ; rewinding towards %s" % (ref, change, maxChange)
                    system("git update-ref %s \"%s^\"" % (ref, ref))
                    log = extractLogMessageFromGitCommit(ref)
                    settings =  extractSettingsGitLog(log)


                    depotPaths = settings['depot-paths']
                    change = settings['change']

                if changed:
                    print "%s rewound to %s" % (ref, change)

        return True

class P4Submit(Command):

    conflict_behavior_choices = ("ask", "skip", "quit")

    def __init__(self):
        raise NotImplementedError( "Adapt to Perforce" )
        Command.__init__(self)
        self.options = [
                optparse.make_option("--origin", dest="origin"),
                optparse.make_option("-M", dest="detectRenames", action="store_true"),
                # preserve the user, requires relevant p4 permissions
                optparse.make_option("--preserve-user", dest="preserveUser", action="store_true"),
                optparse.make_option("--export-labels", dest="exportLabels", action="store_true"),
                optparse.make_option("--dry-run", "-n", dest="dry_run", action="store_true"),
                optparse.make_option("--prepare-p4-only", dest="prepare_p4_only", action="store_true"),
                optparse.make_option("--conflict", dest="conflict_behavior",
                                     choices=self.conflict_behavior_choices),
        ]
        self.description = "Submit changes from git to the perforce depot."
        self.usage += " [name of git branch to submit into perforce depot]"
        self.origin = ""
        self.detectRenames = False
        self.preserveUser = gitConfigBool("git-p4.preserveUser")
        self.dry_run = False
        self.prepare_p4_only = False
        self.conflict_behavior = None
        self.isWindows = (platform.system() == "Windows")
        self.exportLabels = False
        self.p4HasMoveCommand = p4_has_move_command()

    def check(self):
        if len(p4CmdList("opened ...")) > 0:
            die("You have files opened with perforce! Close them before starting the sync.")

    def separate_jobs_from_description(self, message):
        """Extract and return a possible Jobs field in the commit
           message.  It goes into a separate section in the p4 change
           specification.

           A jobs line starts with "Jobs:" and looks like a new field
           in a form.  Values are white-space separated on the same
           line or on following lines that start with a tab.

           This does not parse and extract the full git commit message
           like a p4 form.  It just sees the Jobs: line as a marker
           to pass everything from then on directly into the p4 form,
           but outside the description section.

           Return a tuple (stripped log message, jobs string)."""

        m = re.search(r'^Jobs:', message, re.MULTILINE)
        if m is None:
            return (message, None)

        jobtext = message[m.start():]
        stripped_message = message[:m.start()].rstrip()
        return (stripped_message, jobtext)

    def prepareLogMessage(self, template, message, jobs):
        """Edits the template returned from "p4 change -o" to insert
           the message in the Description field, and the jobs text in
           the Jobs field."""
        result = ""

        inDescriptionSection = False

        for line in template.split("\n"):
            if line.startswith("#"):
                result += line + "\n"
                continue

            if inDescriptionSection:
                if line.startswith("Files:") or line.startswith("Jobs:"):
                    inDescriptionSection = False
                    # insert Jobs section
                    if jobs:
                        result += jobs + "\n"
                else:
                    continue
            else:
                if line.startswith("Description:"):
                    inDescriptionSection = True
                    line += "\n"
                    for messageLine in message.split("\n"):
                        line += "\t" + messageLine + "\n"

            result += line + "\n"

        return result

    def patchRCSKeywords(self, file, pattern):
        # Attempt to zap the RCS keywords in a p4 controlled file matching the given pattern
        (handle, outFileName) = tempfile.mkstemp(dir='.')
        try:
            outFile = os.fdopen(handle, "w+")
            inFile = open(file, "r")
            regexp = re.compile(pattern, re.VERBOSE)
            for line in inFile.readlines():
                line = regexp.sub(r'$\1$', line)
                outFile.write(line)
            inFile.close()
            outFile.close()
            # Forcibly overwrite the original file
            os.unlink(file)
            shutil.move(outFileName, file)
        except:
            # cleanup our temporary file
            os.unlink(outFileName)
            print "Failed to strip RCS keywords in %s" % file
            raise

        print "Patched up RCS keywords in %s" % file

    def p4UserForCommit(self,id):
        raise NotImplementedError( "Adapt to Perforce" )
        # Return the tuple (perforce user,git email) for a given git commit id
        self.getUserMapFromPerforceServer()
        gitEmail = read_pipe(["git", "log", "--max-count=1",
                              "--format=%ae", id])
        gitEmail = gitEmail.strip()
        if not self.emails.has_key(gitEmail):
            return (None,gitEmail)
        else:
            return (self.emails[gitEmail],gitEmail)

    def checkValidP4Users(self,commits):
        # check if any git authors cannot be mapped to p4 users
        for id in commits:
            (user,email) = self.p4UserForCommit(id)
            if not user:
                msg = "Cannot find p4 user for email %s in commit %s." % (email, id)
                if gitConfigBool("git-p4.allowMissingP4Users"):
                    print "%s" % msg
                else:
                    die("Error: %s\nSet git-p4.allowMissingP4Users to true to allow this." % msg)

    def lastP4Changelist(self):
        # Get back the last changelist number submitted in this client spec. This
        # then gets used to patch up the username in the change. If the same
        # client spec is being used by multiple processes then this might go
        # wrong.
        results = p4CmdList("client -o")        # find the current client
        client = None
        for r in results:
            if r.has_key('Client'):
                client = r['Client']
                break
        if not client:
            die("could not get client spec")
        results = p4CmdList(["changes", "-c", client, "-m", "1"])
        for r in results:
            if r.has_key('change'):
                return r['change']
        die("Could not get changelist number for last submit - cannot patch up user details")

    def modifyChangelistUser(self, changelist, newUser):
        # fixup the user field of a changelist after it has been submitted.
        changes = p4CmdList("change -o %s" % changelist)
        if len(changes) != 1:
            die("Bad output from p4 change modifying %s to user %s" %
                (changelist, newUser))

        c = changes[0]
        if c['User'] == newUser: return   # nothing to do
        c['User'] = newUser
        input = marshal.dumps(c)

        result = p4CmdList("change -f -i", stdin=input)
        for r in result:
            if r.has_key('code'):
                if r['code'] == 'error':
                    die("Could not modify user field of changelist %s to %s:%s" % (changelist, newUser, r['data']))
            if r.has_key('data'):
                print("Updated user field for changelist %s to %s" % (changelist, newUser))
                return
        die("Could not modify user field of changelist %s to %s" % (changelist, newUser))

    def canChangeChangelists(self):
        # check to see if we have p4 admin or super-user permissions, either of
        # which are required to modify changelists.
        results = p4CmdList(["protects", self.depotPath])
        for r in results:
            if r.has_key('perm'):
                if r['perm'] == 'admin':
                    return 1
                if r['perm'] == 'super':
                    return 1
        return 0

    def prepareSubmitTemplate(self):
        """Run "p4 change -o" to grab a change specification template.
           This does not use "p4 -G", as it is nice to keep the submission
           template in original order, since a human might edit it.

           Remove lines in the Files section that show changes to files
           outside the depot path we're committing into."""

        template = ""
        inFilesSection = False
        for line in p4_read_pipe_lines(['change', '-o']):
            if line.endswith("\r\n"):
                line = line[:-2] + "\n"
            if inFilesSection:
                if line.startswith("\t"):
                    # path starts and ends with a tab
                    path = line[1:]
                    lastTab = path.rfind("\t")
                    if lastTab != -1:
                        path = path[:lastTab]
                        if not p4PathStartsWith(path, self.depotPath):
                            continue
                else:
                    inFilesSection = False
            else:
                if line.startswith("Files:"):
                    inFilesSection = True

            template += line

        return template

    def edit_template(self, template_file):
        """Invoke the editor to let the user change the submission
           message.  Return true if okay to continue with the submit."""
        raise NotImplementedError( "Adapt to Perforce" )

        # if configured to skip the editing part, just submit
        if gitConfigBool("git-p4.skipSubmitEdit"):
            return True

        # look at the modification time, to check later if the user saved
        # the file
        mtime = os.stat(template_file).st_mtime

        # invoke the editor
        if os.environ.has_key("P4EDITOR") and (os.environ.get("P4EDITOR") != ""):
            editor = os.environ.get("P4EDITOR")
        else:
            editor = read_pipe("git var GIT_EDITOR").strip()
        system([editor, template_file])

        # If the file was not saved, prompt to see if this patch should
        # be skipped.  But skip this verification step if configured so.
        if gitConfigBool("git-p4.skipSubmitEditCheck"):
            return True

        # modification time updated means user saved the file
        if os.stat(template_file).st_mtime > mtime:
            return True

        while True:
            response = raw_input("Submit template unchanged. Submit anyway? [y]es, [n]o (skip this patch) ")
            if response == 'y':
                return True
            if response == 'n':
                return False

    def applyCommit(self, id):
        """Apply one commit, return True if it succeeded."""

        raise NotImplementedError( "Adapt to Perforce" )
        print "Applying", read_pipe(["git", "show", "-s",
                                     "--format=format:%h %s", id])

        (p4User, gitEmail) = self.p4UserForCommit(id)

        diff = read_pipe_lines("git diff-tree -r %s \"%s^\" \"%s\"" % (self.diffOpts, id, id))
        filesToAdd = set()
        filesToDelete = set()
        editedFiles = set()
        pureRenameCopy = set()
        filesToChangeExecBit = {}

        for line in diff:
            diff = parseDiffTreeEntry(line)
            modifier = diff['status']
            path = diff['src']
            if modifier == "M":
                p4_edit(path)
                if isModeExecChanged(diff['src_mode'], diff['dst_mode']):
                    filesToChangeExecBit[path] = diff['dst_mode']
                editedFiles.add(path)
            elif modifier == "A":
                filesToAdd.add(path)
                filesToChangeExecBit[path] = diff['dst_mode']
                if path in filesToDelete:
                    filesToDelete.remove(path)
            elif modifier == "D":
                filesToDelete.add(path)
                if path in filesToAdd:
                    filesToAdd.remove(path)
            elif modifier == "C":
                src, dest = diff['src'], diff['dst']
                p4_integrate(src, dest)
                pureRenameCopy.add(dest)
                if diff['src_sha1'] != diff['dst_sha1']:
                    p4_edit(dest)
                    pureRenameCopy.discard(dest)
                if isModeExecChanged(diff['src_mode'], diff['dst_mode']):
                    p4_edit(dest)
                    pureRenameCopy.discard(dest)
                    filesToChangeExecBit[dest] = diff['dst_mode']
                if self.isWindows:
                    # turn off read-only attribute
                    os.chmod(dest, stat.S_IWRITE)
                os.unlink(dest)
                editedFiles.add(dest)
            elif modifier == "R":
                src, dest = diff['src'], diff['dst']
                if self.p4HasMoveCommand:
                    p4_edit(src)        # src must be open before move
                    p4_move(src, dest)  # opens for (move/delete, move/add)
                else:
                    p4_integrate(src, dest)
                    if diff['src_sha1'] != diff['dst_sha1']:
                        p4_edit(dest)
                    else:
                        pureRenameCopy.add(dest)
                if isModeExecChanged(diff['src_mode'], diff['dst_mode']):
                    if not self.p4HasMoveCommand:
                        p4_edit(dest)   # with move: already open, writable
                    filesToChangeExecBit[dest] = diff['dst_mode']
                if not self.p4HasMoveCommand:
                    if self.isWindows:
                        os.chmod(dest, stat.S_IWRITE)
                    os.unlink(dest)
                    filesToDelete.add(src)
                editedFiles.add(dest)
            else:
                die("unknown modifier %s for %s" % (modifier, path))

        diffcmd = "git diff-tree -p \"%s\"" % (id)
        patchcmd = diffcmd + " | git apply "
        tryPatchCmd = patchcmd + "--check -"
        applyPatchCmd = patchcmd + "--check --apply -"
        patch_succeeded = True

        if os.system(tryPatchCmd) != 0:
            fixed_rcs_keywords = False
            patch_succeeded = False
            print "Unfortunately applying the change failed!"

            # Patch failed, maybe it's just RCS keyword woes. Look through
            # the patch to see if that's possible.
            if gitConfigBool("git-p4.attemptRCSCleanup"):
                file = None
                pattern = None
                kwfiles = {}
                for file in editedFiles | filesToDelete:
                    # did this file's delta contain RCS keywords?
                    pattern = p4_keywords_regexp_for_file(file)

                    if pattern:
                        # this file is a possibility...look for RCS keywords.
                        regexp = re.compile(pattern, re.VERBOSE)
                        for line in read_pipe_lines(["git", "diff", "%s^..%s" % (id, id), file]):
                            if regexp.search(line):
                                if verbose:
                                    print "got keyword match on %s in %s in %s" % (pattern, line, file)
                                kwfiles[file] = pattern
                                break

                for file in kwfiles:
                    if verbose:
                        print "zapping %s with %s" % (line,pattern)
                    # File is being deleted, so not open in p4.  Must
                    # disable the read-only bit on windows.
                    if self.isWindows and file not in editedFiles:
                        os.chmod(file, stat.S_IWRITE)
                    self.patchRCSKeywords(file, kwfiles[file])
                    fixed_rcs_keywords = True

            if fixed_rcs_keywords:
                print "Retrying the patch with RCS keywords cleaned up"
                if os.system(tryPatchCmd) == 0:
                    patch_succeeded = True

        if not patch_succeeded:
            for f in editedFiles:
                p4_revert(f)
            return False

        #
        # Apply the patch for real, and do add/delete/+x handling.
        #
        system(applyPatchCmd)

        for f in filesToAdd:
            p4_add(f)
        for f in filesToDelete:
            p4_revert(f)
            p4_delete(f)

        # Set/clear executable bits
        for f in filesToChangeExecBit.keys():
            mode = filesToChangeExecBit[f]
            setP4ExecBit(f, mode)

        #
        # Build p4 change description, starting with the contents
        # of the git commit message.
        #
        logMessage = extractLogMessageFromGitCommit(id)
        logMessage = logMessage.strip()
        (logMessage, jobs) = self.separate_jobs_from_description(logMessage)

        template = self.prepareSubmitTemplate()
        submitTemplate = self.prepareLogMessage(template, logMessage, jobs)

        if self.preserveUser:
           submitTemplate += "\n######## Actual user %s, modified after commit\n" % p4User

        if self.checkAuthorship and not self.p4UserIsMe(p4User):
            submitTemplate += "######## git author %s does not match your p4 account.\n" % gitEmail
            submitTemplate += "######## Use option --preserve-user to modify authorship.\n"
            submitTemplate += "######## Variable git-p4.skipUserNameCheck hides this message.\n"

        separatorLine = "######## everything below this line is just the diff #######\n"

        # diff
        if os.environ.has_key("P4DIFF"):
            del(os.environ["P4DIFF"])
        diff = ""
        for editedFile in editedFiles:
            diff += p4_read_pipe(['diff', '-du',
                                  wildcard_encode(editedFile)])

        # new file diff
        newdiff = ""
        for newFile in filesToAdd:
            newdiff += "==== new file ====\n"
            newdiff += "--- /dev/null\n"
            newdiff += "+++ %s\n" % newFile
            f = open(newFile, "r")
            for line in f.readlines():
                newdiff += "+" + line
            f.close()

        # change description file: submitTemplate, separatorLine, diff, newdiff
        (handle, fileName) = tempfile.mkstemp()
        tmpFile = os.fdopen(handle, "w+")
        if self.isWindows:
            submitTemplate = submitTemplate.replace("\n", "\r\n")
            separatorLine = separatorLine.replace("\n", "\r\n")
            newdiff = newdiff.replace("\n", "\r\n")
        tmpFile.write(submitTemplate + separatorLine + diff + newdiff)
        tmpFile.close()

        if self.prepare_p4_only:
            #
            # Leave the p4 tree prepared, and the submit template around
            # and let the user decide what to do next
            #
            print
            print "P4 workspace prepared for submission."
            print "To submit or revert, go to client workspace"
            print "  " + self.clientPath
            print
            print "To submit, use \"p4 submit\" to write a new description,"
            print "or \"p4 submit -i %s\" to use the one prepared by" \
                  " \"git p4\"." % fileName
            print "You can delete the file \"%s\" when finished." % fileName

            if self.preserveUser and p4User and not self.p4UserIsMe(p4User):
                print "To preserve change ownership by user %s, you must\n" \
                      "do \"p4 change -f <change>\" after submitting and\n" \
                      "edit the User field."
            if pureRenameCopy:
                print "After submitting, renamed files must be re-synced."
                print "Invoke \"p4 sync -f\" on each of these files:"
                for f in pureRenameCopy:
                    print "  " + f

            print
            print "To revert the changes, use \"p4 revert ...\", and delete"
            print "the submit template file \"%s\"" % fileName
            if filesToAdd:
                print "Since the commit adds new files, they must be deleted:"
                for f in filesToAdd:
                    print "  " + f
            print
            return True

        #
        # Let the user edit the change description, then submit it.
        #
        if self.edit_template(fileName):
            # read the edited message and submit
            ret = True
            tmpFile = open(fileName, "rb")
            message = tmpFile.read()
            tmpFile.close()
            submitTemplate = message[:message.index(separatorLine)]
            if self.isWindows:
                submitTemplate = submitTemplate.replace("\r\n", "\n")
            p4_write_pipe(['submit', '-i'], submitTemplate)

            if self.preserveUser:
                if p4User:
                    # Get last changelist number. Cannot easily get it from
                    # the submit command output as the output is
                    # unmarshalled.
                    changelist = self.lastP4Changelist()
                    self.modifyChangelistUser(changelist, p4User)

            # The rename/copy happened by applying a patch that created a
            # new file.  This leaves it writable, which confuses p4.
            for f in pureRenameCopy:
                p4_sync(f, "-f")

        else:
            # skip this patch
            ret = False
            print "Submission cancelled, undoing p4 changes."
            for f in editedFiles:
                p4_revert(f)
            for f in filesToAdd:
                p4_revert(f)
                os.remove(f)
            for f in filesToDelete:
                p4_revert(f)

        os.remove(fileName)
        return ret

    # Export git tags as p4 labels. Create a p4 label and then tag
    # with that.
    def exportGitTags(self, gitTags):
        raise NotImplementedError( "Adapt to Perforce" )
        validLabelRegexp = gitConfig("git-p4.labelExportRegexp")
        if len(validLabelRegexp) == 0:
            validLabelRegexp = defaultLabelRegexp
        m = re.compile(validLabelRegexp)

        for name in gitTags:

            if not m.match(name):
                if verbose:
                    print "tag %s does not match regexp %s" % (name, validLabelRegexp)
                continue

            # Get the p4 commit this corresponds to
            logMessage = extractLogMessageFromGitCommit(name)
            values = extractSettingsGitLog(logMessage)

            if not values.has_key('change'):
                # a tag pointing to something not sent to p4; ignore
                if verbose:
                    print "git tag %s does not give a p4 commit" % name
                continue
            else:
                changelist = values['change']

            # Get the tag details.
            inHeader = True
            isAnnotated = False
            body = []
            for l in read_pipe_lines(["git", "cat-file", "-p", name]):
                l = l.strip()
                if inHeader:
                    if re.match(r'tag\s+', l):
                        isAnnotated = True
                    elif re.match(r'\s*$', l):
                        inHeader = False
                        continue
                else:
                    body.append(l)

            if not isAnnotated:
                body = ["lightweight tag imported by git p4\n"]

            # Create the label - use the same view as the client spec we are using
            clientSpec = getClientSpec()

            labelTemplate  = "Label: %s\n" % name
            labelTemplate += "Description:\n"
            for b in body:
                labelTemplate += "\t" + b + "\n"
            labelTemplate += "View:\n"
            for depot_side in clientSpec.mappings:
                labelTemplate += "\t%s\n" % depot_side

            if self.dry_run:
                print "Would create p4 label %s for tag" % name
            elif self.prepare_p4_only:
                print "Not creating p4 label %s for tag due to option" \
                      " --prepare-p4-only" % name
            else:
                p4_write_pipe(["label", "-i"], labelTemplate)

                # Use the label
                p4_system(["tag", "-l", name] +
                          ["%s@%s" % (depot_side, changelist) for depot_side in clientSpec.mappings])

                if verbose:
                    print "created p4 label for tag %s" % name

    def run(self, args):
        raise NotImplementedError( "Adapt to Perforce" )
        if len(args) == 0:
            self.master = currentGitBranch()
            if len(self.master) == 0 or not gitBranchExists("refs/heads/%s" % self.master):
                die("Detecting current git branch failed!")
        elif len(args) == 1:
            self.master = args[0]
            if not branchExists(self.master):
                die("Branch %s does not exist" % self.master)
        else:
            return False

        allowSubmit = gitConfig("git-p4.allowSubmit")
        if len(allowSubmit) > 0 and not self.master in allowSubmit.split(","):
            die("%s is not in git-p4.allowSubmit" % self.master)

        [upstream, settings] = findUpstreamBranchPoint()
        self.depotPath = settings['depot-paths'][0]
        if len(self.origin) == 0:
            self.origin = upstream

        if self.preserveUser:
            if not self.canChangeChangelists():
                die("Cannot preserve user names without p4 super-user or admin permissions")

        # if not set from the command line, try the config file
        if self.conflict_behavior is None:
            val = gitConfig("git-p4.conflict")
            if val:
                if val not in self.conflict_behavior_choices:
                    die("Invalid value '%s' for config git-p4.conflict" % val)
            else:
                val = "ask"
            self.conflict_behavior = val

        if self.verbose:
            print "Origin branch is " + self.origin

        if len(self.depotPath) == 0:
            print "Internal error: cannot locate perforce depot path from existing branches"
            sys.exit(128)

        self.clientSpec = False

        if self.clientSpec:
            # all files are relative to the client spec
            self.clientPath = getClientRoot(self.clientSpec)
        else:
            self.clientPath = p4Where(self.depotPath)

        if self.clientPath == "":
            die("Error: Cannot locate perforce checkout of %s in client view" % self.depotPath)

        print "Perforce checkout for depot path %s located at %s" % (self.depotPath, self.clientPath)
        self.oldWorkingDirectory = os.getcwd()

        # ensure the clientPath exists
        new_client_dir = False
        if not os.path.exists(self.clientPath):
            new_client_dir = True
            os.makedirs(self.clientPath)

        chdir(self.clientPath, is_client_path=True)
        if self.dry_run:
            print "Would synchronize p4 checkout in %s" % self.clientPath
        else:
            print "Synchronizing p4 checkout..."
            if new_client_dir:
                # old one was destroyed, and maybe nobody told p4
                p4_sync("...", "-f")
            else:
                p4_sync("...")
        self.check()

        commits = []
        for line in read_pipe_lines(["git", "rev-list", "--no-merges", "%s..%s" % (self.origin, self.master)]):
            commits.append(line.strip())
        commits.reverse()

        if self.preserveUser or gitConfigBool("git-p4.skipUserNameCheck"):
            self.checkAuthorship = False
        else:
            self.checkAuthorship = True

        if self.preserveUser:
            self.checkValidP4Users(commits)

        #
        # Build up a set of options to be passed to diff when
        # submitting each commit to p4.
        #
        if self.detectRenames:
            # command-line -M arg
            self.diffOpts = "-M"
        else:
            # If not explicitly set check the config variable
            detectRenames = gitConfig("git-p4.detectRenames")

            if detectRenames.lower() == "false" or detectRenames == "":
                self.diffOpts = ""
            elif detectRenames.lower() == "true":
                self.diffOpts = "-M"
            else:
                self.diffOpts = "-M%s" % detectRenames

        # no command-line arg for -C or --find-copies-harder, just
        # config variables
        detectCopies = gitConfig("git-p4.detectCopies")
        if detectCopies.lower() == "false" or detectCopies == "":
            pass
        elif detectCopies.lower() == "true":
            self.diffOpts += " -C"
        else:
            self.diffOpts += " -C%s" % detectCopies

        if gitConfigBool("git-p4.detectCopiesHarder"):
            self.diffOpts += " --find-copies-harder"

        #
        # Apply the commits, one at a time.  On failure, ask if should
        # continue to try the rest of the patches, or quit.
        #
        if self.dry_run:
            print "Would apply"
        applied = []
        last = len(commits) - 1
        for i, commit in enumerate(commits):
            if self.dry_run:
                print " ", read_pipe(["git", "show", "-s",
                                      "--format=format:%h %s", commit])
                ok = True
            else:
                ok = self.applyCommit(commit)
            if ok:
                applied.append(commit)
            else:
                if self.prepare_p4_only and i < last:
                    print "Processing only the first commit due to option" \
                          " --prepare-p4-only"
                    break
                if i < last:
                    quit = False
                    while True:
                        # prompt for what to do, or use the option/variable
                        if self.conflict_behavior == "ask":
                            print "What do you want to do?"
                            response = raw_input("[s]kip this commit but apply"
                                                 " the rest, or [q]uit? ")
                            if not response:
                                continue
                        elif self.conflict_behavior == "skip":
                            response = "s"
                        elif self.conflict_behavior == "quit":
                            response = "q"
                        else:
                            die("Unknown conflict_behavior '%s'" %
                                self.conflict_behavior)

                        if response[0] == "s":
                            print "Skipping this commit, but applying the rest"
                            break
                        if response[0] == "q":
                            print "Quitting"
                            quit = True
                            break
                    if quit:
                        break

        chdir(self.oldWorkingDirectory)

        if self.dry_run:
            pass
        elif self.prepare_p4_only:
            pass
        elif len(commits) == len(applied):
            print "All commits applied!"

            sync = P4Sync()
            sync.run([])

            rebase = P4Rebase()
            rebase.rebase()

        else:
            if len(applied) == 0:
                print "No commits applied."
            else:
                print "Applied only the commits marked with '*':"
                for c in commits:
                    if c in applied:
                        star = "*"
                    else:
                        star = " "
                    print star, read_pipe(["git", "show", "-s",
                                           "--format=format:%h %s",  c])
                print "You will have to do 'git p4 sync' and rebase."

        if gitConfigBool("git-p4.exportLabels"):
            self.exportLabels = True

        if self.exportLabels:
            p4Labels = getP4Labels(self.depotPath)
            gitTags = getGitTags()

            missingGitTags = gitTags - p4Labels
            self.exportGitTags(missingGitTags)

        # exit with error unless everything applied perfectly
        if len(commits) != len(applied):
                sys.exit(1)

        return True

class View(object):
    """Represent a p4 view ("p4 help views"), and map files in a
       repo according to the view."""

    def __init__(self):
        self.mappings = []

    def append(self, view_line):
        """Parse a view line, splitting it into depot and client
           sides.  Append to self.mappings, preserving order.  This
           is only needed for tag creation."""

        # Split the view line into exactly two words.  P4 enforces
        # structure on these lines that simplifies this quite a bit.
        #
        # Either or both words may be double-quoted.
        # Single quotes do not matter.
        # Double-quote marks cannot occur inside the words.
        # A + or - prefix is also inside the quotes.
        # There are no quotes unless they contain a space.
        # The line is already white-space stripped.
        # The two words are separated by a single space.
        #
        if view_line[0] == '"':
            # First word is double quoted.  Find its end.
            close_quote_index = view_line.find('"', 1)
            if close_quote_index <= 0:
                die("No first-word closing quote found: %s" % view_line)
            depot_side = view_line[1:close_quote_index]
            # skip closing quote and space
            rhs_index = close_quote_index + 1 + 1
        else:
            space_index = view_line.find(" ")
            if space_index <= 0:
                die("No word-splitting space found: %s" % view_line)
            depot_side = view_line[0:space_index]
            rhs_index = space_index + 1

        # prefix + means overlay on previous mapping
        if depot_side.startswith("+"):
            depot_side = depot_side[1:]

        # prefix - means exclude this path, leave out of mappings
        exclude = False
        if depot_side.startswith("-"):
            exclude = True
            depot_side = depot_side[1:]

        if not exclude:
            self.mappings.append(depot_side)


class P4Sync(Command):
    
    def __init__(self):
        Command.__init__(self)
        self.options = [
                optparse.make_option("--changesfile", dest="changesFile"),
                optparse.make_option("--silent", dest="silent", action="store_true"),
                optparse.make_option("--import-labels", dest="importLabels", action="store_true"),
                optparse.make_option("--max-changes", dest="maxChanges"),
        ]
        # XXX Note the terminology!  The primary direction of changes is repo0->repo1, but
        # P4Submit moves individual changes from repo1->repo0.
        self.description = "Imports from one Perforce repo (repo0) into another (repo1).  " \
                "P4CONFIG files must exist at each client's root to specify connection settings.  " \
                "Only files mapped by repo0's client spec are imported.  You must have admin " \
                "access to repo1."

        self.usage += " <repo0-client-root> <repo1-client-root>"
        self.silent = False
        self.repo0 = None
        self.createdBranches = set()
        self.importLabels = False
        self.changesFile = ""
        self.maxChanges = ""
        self.repo0_clientRoot = False
        self.repo1_clientRoot = False

    def extractFilesFromCommit(self, commit):
        files = []
        for fileInfo in P4DictUnflattener(commit, "depotFile"):
            path = fileInfo["depotFile"]
            # only consider files that have a path in the client
            relPath = self.repo0.map_to_relative_path(path)
            if not relPath: continue

            file = {}
            file["path"] = path
            file["repo1Path"] = "//%s/%s" % (self.repo1.clientName, relPath)
            file["rev"] = fileInfo["rev"]
            file["action"] = fileInfo["action"]
            file["type"] = fileInfo["type"]
            files.append(file)
        return files

    def replayIntegrations(self, change, file):
        """Replays the integrations for a particular file in a particular change.  Returns the
        effective action the calling code should apply to the file:
            branch, integrate: write the exact repo0 file to the repo1 client
            integrate/delete: no further action
            add, edit: mark for add/edit and write the exact repo0 file to the repo1 client
            delete: mark for delete
        """
        # FIXME with only srev and erev, will need a map for file->rev->cl
        fileLog = self.repo0.file_revision_filelog(change, file["path"])
        pprint.pprint(fileLog)

        # There may not be any integrationActions, or we may not be able to replay any of the ones
        # that _are_ there (ie if all sources weren't migrated to repo1).  In those cases, the
        # calling code needs to use add/edit/delete.
        fileOpened = False

        for integLog in fileLog["integrationActions"]:
            die("create this code")

        # Return the "effective action" that the calling code should apply
        if fileOpened:
            if file["action"] == "delete": return "integrate/delete"
            return file["action"]
        else:
            if file["action"] in ("branch", "add"):
                return "add"
            elif file["action"] in ("integrate", "edit"):
                return "edit"
            elif file["action"] == "delete":
                return "delete"
            else:
                die("Unexpected action %r" % file["action"])

    # output one file from the P4 stream
    # - helper for streamP4Files
    def streamOneP4File(self, file, contents):
        relPath = self.repo0.map_to_relative_path(file['depotFile'])
        assert relPath, "expected path in client"
        if verbose:
            sys.stderr.write("%s\n" % relPath)
        hostPath = os.path.join(self.repo1.clientRoot, relPath)

        (type_base, type_mods) = split_p4_type(file["type"])

        if type_base == "symlink":
            # p4 print on a symlink sometimes contains "target\n";
            # if it does, remove the newline
            data = ''.join(contents)
            if not data:
                # Some version of p4 allowed creating a symlink that pointed
                # to nothing.  This causes p4 errors when checking out such
                # a change, and errors here too.  Work around it by ignoring
                # the bad symlink; hopefully a future change fixes it.
                print "\nIgnoring empty symlink in %s" % file['depotFile']
                return
            elif data[-1] == '\n':
                contents = [data[:-1]]
            else:
                contents = [data]

        if type_base == "utf16":
            # p4 delivers different text in the python output to -G
            # than it does when using "print -o", or normal p4 client
            # operations.  utf16 is converted to ascii or utf8, perhaps.
            # But ascii text saved as -t utf16 is completely mangled.
            # Invoke print -o to get the real contents.
            #
            # On windows, the newlines will always be mangled by print, so put
            # them back too.  This is not needed to the cygwin windows version,
            # just the native "NT" type.
            #
            text = self.repo0.read_pipe(['print', '-q', '-o', '-', file['depotFile']])
            # FIXME verify this mangling
            if self.repo0.version_string().find("/NT") >= 0:
                text = text.replace("\r\n", "\n")
            contents = [ text ]

        if type_base == "apple":
            # Apple filetype files will be streamed as a concatenation of
            # its appledouble header and the contents.  This is useless
            # on both macs and non-macs.  If using "print -q -o xx", it
            # will create "xx" with the data, and "%xx" with the header.
            # This is also not very useful.
            #
            # Ideally, someday, this script can learn how to generate
            # appledouble files directly and import those to git, but
            # non-mac machines can never find a use for apple filetype.
            print "\nIgnoring apple filetype file %s" % file['depotFile']
            return

        # Note that we do not try to de-mangle keywords on utf16 files,
        # even though in theory somebody may want that.
        pattern = p4_keywords_regexp_for_type(type_base, type_mods)
        if pattern:
            regexp = re.compile(pattern, re.VERBOSE)
            text = ''.join(contents)
            text = regexp.sub(r'$\1$', text)
            contents = [ text ]

        try: os.makedirs(os.path.dirname(hostPath))
        except: pass
        # FIXME don't turn off read-only attribute...it might save us from mistakes
        try: os.chmod(hostPath, stat.S_IWRITE)
        except: pass
        with open(hostPath, "wb") as outfile:
            for d in contents: outfile.write(d)

    # handle another chunk of streaming data
    def streamP4FilesCb(self, marshalled):
        # catch p4 errors and complain
        err = None
        if "code" in marshalled:
            if marshalled["code"] == "error":
                if "data" in marshalled:
                    err = marshalled["data"].rstrip()
        if err:
            f = None
            if self.stream_have_file_info:
                if "depotFile" in self.stream_file:
                    f = self.stream_file["depotFile"]
            if f:
                die("Error from p4 print for %s: %s" % (f, err))
            else:
                die("Error from p4 print: %s" % err)

        if marshalled.has_key('depotFile') and self.stream_have_file_info:
            # start of a new file - output the old one first
            self.streamOneP4File(self.stream_file, self.stream_contents)
            self.stream_file = {}
            self.stream_contents = []
            self.stream_have_file_info = False

        # pick up the new file information... for the
        # 'data' field we need to append to our array
        for k in marshalled.keys():
            if k == 'data':
                self.stream_contents.append(marshalled['data'])
            else:
                self.stream_file[k] = marshalled[k]

        self.stream_have_file_info = True

    def streamP4Files(self, details, files):
        """Stream directly from "p4 files" into "p4 edit", etc"""
        filesToRead = []

        # We run the commands through Perforce first, even though the files may not exist on the
        # client
        for file in files:
            # FIXME remove
            print file['action'], file['path'], file['rev'], file['type']
            f_action = self.replayIntegrations(details["change"], file)
            if f_action == "add":
                self.repo1.add(file['repo1Path'], file['type'])
                filesToRead.append(file)
            elif f_action == "edit":
                self.repo1.edit(file['repo1Path'], file['type'])
                filesToRead.append(file)
            elif f_action == "delete":
                self.repo1.delete(file['repo1Path'])
            elif f_action in ("branch", "integrate"):
                # marked for branch/integrate by replayIntegrations
                filesToRead.append(file) 
            elif f_action == "integrate/delete":
                pass # marked for delete by replayIntegrations
            else:
                raise ValueError("unknown Perforce action %r" % f_action)

        if len(filesToRead) > 0:
            self.stream_file = {}
            self.stream_contents = []
            self.stream_have_file_info = False

            fileArgs = ['%s#%s' % (f['path'], f['rev']) for f in filesToRead]

            # FIXME convert to sync, which I assume will be faster
            self.repo0.cmdList(["-x", "-", "print"],
                      stdin=fileArgs,
                      cb=self.streamP4FilesCb)

            # do the last chunk
            if self.stream_file.has_key('depotFile'):
                self.streamOneP4File(self.stream_file, self.stream_contents)

    # Stream a p4 tag
    def streamTag(self, gitStream, labelName, labelDetails, commit, epoch):
        raise NotImplementedError( "Adapt to Perforce" )
        if verbose:
            print "writing tag %s for commit %s" % (labelName, commit)
        gitStream.write("tag %s\n" % labelName)
        gitStream.write("from %s\n" % commit)

        if labelDetails.has_key('Owner'):
            owner = labelDetails["Owner"]
        else:
            owner = None

        # Try to use the owner of the p4 label, or failing that,
        # the current p4 user id.
        if owner:
            email = self.make_email(owner)
        else:
            email = self.make_email(self.p4UserId())
        tagger = "%s %s %s" % (email, epoch, self.tz)

        gitStream.write("tagger %s\n" % tagger)

        print "labelDetails=",labelDetails
        if labelDetails.has_key('Description'):
            description = labelDetails['Description']
        else:
            description = 'Label from git p4'

        gitStream.write("data %d\n" % len(description))
        gitStream.write(description)
        gitStream.write("\n")

    def commitChange(self, details, files):
        if self.verbose:
            print "commit change %s" % details["change"]
        self.streamP4Files(details, files)

        # To ensure the next submitted change is given the number details["change"], we must 
        # advance the counter to details["change"]-1.
        self.repo1.advance_change_counter(int(details["change"])-1)    

        # All the files are now sitting open in the default changelist.  Submitting is a two-step
        # process, because we can't change the user, client, or date with "submit".
        # TODO Need to use the correct client here...or forgo client replication
        description = self.repo1.change_out()
        description["Description"] = "<p4-p4.py placeholder>"
        submit_result = self.repo1.submit(description)
        if "p4ExitCode" in submit_result[-1]: 
            die("".join(x.get("data", "") for x in submit_result))
        submit_change = submit_result[-1]["submittedChange"]
        if submit_change != details["change"]:
            die("Submitted change %s doesn't equal original (%s)" % (submit_change, details["change"]))

        # Now we can update the fields that only admins can modify
        self.adjustUserDateDesc(details)

    def adjustUserDateDesc(self, details):
        """Updates the repo1 copy of the change with details from repo0.  Perforce limits this to
        Date, Description, and User."""
        description = self.repo1.change_out(details["change"])
        description.update(
                Date = details["time"],
                # Empty descriptions appear as "" on output, but "" is rejected on input
                Description = details["desc"] if details["desc"] else "\n",
                User = details["user"],
                )
        change_result = self.repo1.change_in(description)
        if "p4ExitCode" in change_result[-1]: 
            die("".join(x.get("data", "") for x in change_result))

    # Import p4 labels as git tags. A direct mapping does not
    # exist, so assume that if all the files are at the same revision
    # then we can use that, or it's something more complicated we should
    # just ignore.
    def importP4Labels(self, stream, p4Labels):
        raise NotImplementedError( "Adapt to Perforce" )
        if verbose:
            print "import p4 labels: " + ' '.join(p4Labels)

        ignoredP4Labels = gitConfigList("git-p4.ignoredP4Labels")
        validLabelRegexp = gitConfig("git-p4.labelImportRegexp")
        if len(validLabelRegexp) == 0:
            validLabelRegexp = defaultLabelRegexp
        m = re.compile(validLabelRegexp)

        for name in p4Labels:
            commitFound = False

            if not m.match(name):
                if verbose:
                    print "label %s does not match regexp %s" % (name,validLabelRegexp)
                continue

            if name in ignoredP4Labels:
                continue

            labelDetails = p4CmdList(['label', "-o", name])[0]

            # get the most recent changelist for each file in this label
            change = p4Cmd(["changes", "-m", "1"] + ["%s...@%s" % (p, name)
                                for p in self.depotPaths])

            if change.has_key('change'):
                # find the corresponding git commit; take the oldest commit
                changelist = int(change['change'])
                gitCommit = read_pipe(["git", "rev-list", "--max-count=1",
                     "--reverse", ":/\[git-p4:.*change = %d\]" % changelist])
                if len(gitCommit) == 0:
                    print "could not find git commit for changelist %d" % changelist
                else:
                    gitCommit = gitCommit.strip()
                    commitFound = True
                    # Convert from p4 time format
                    try:
                        tmwhen = time.strptime(labelDetails['Update'], "%Y/%m/%d %H:%M:%S")
                    except ValueError:
                        print "Could not convert label time %s" % labelDetails['Update']
                        tmwhen = 1

                    when = int(time.mktime(tmwhen))
                    self.streamTag(stream, name, labelDetails, gitCommit, when)
                    if verbose:
                        print "p4 label %s mapped to git commit %s" % (name, gitCommit)
            else:
                if verbose:
                    print "Label %s has no changelists - possibly deleted?" % name

            if not commitFound:
                # We can't import this label; don't try again as it will get very
                # expensive repeatedly fetching all the files for labels that will
                # never be imported. If the label is moved in the future, the
                # ignore will need to be removed manually.
                system(["git", "config", "--add", "git-p4.ignoredP4Labels", name])

    def gitRefForBranch(self, branch):
        raise NotImplementedError( "Adapt to Perforce" )
        if branch == "main":
            return self.refPrefix + "master"

        if len(branch) <= 0:
            return branch

        return self.refPrefix + self.projectName + branch

    def gitCommitByP4Change(self, ref, change):
        raise NotImplementedError( "Adapt to Perforce" )
        if self.verbose:
            print "looking in ref " + ref + " for change %s using bisect..." % change

        earliestCommit = ""
        latestCommit = parseRevision(ref)

        while True:
            if self.verbose:
                print "trying: earliest %s latest %s" % (earliestCommit, latestCommit)
            next = read_pipe("git rev-list --bisect %s %s" % (latestCommit, earliestCommit)).strip()
            if len(next) == 0:
                if self.verbose:
                    print "argh"
                return ""
            log = extractLogMessageFromGitCommit(next)
            settings = extractSettingsGitLog(log)
            currentChange = int(settings['change'])
            if self.verbose:
                print "current change %s" % currentChange

            if currentChange == change:
                if self.verbose:
                    print "found %s" % next
                return next

            if currentChange < change:
                earliestCommit = "^%s" % next
            else:
                latestCommit = "%s" % next

        return ""

    def importChanges(self, changes):
        # Recover from aborted imports
        self.repo1.revert("//...")
        changes_m1 = self.repo1.cmdList("changes -m 1")
        if "p4ExitCode" in changes_m1[-1]: 
            die("".join(x.get("data", "") for x in changes_m1))
        lastCommitted = int(changes_m1[0]["change"])
        
        cnt = 1
        for change in changes:
            if not self.silent:
                sys.stdout.write("\rImporting revision %s (%s%%)" % (change, cnt * 100 / len(changes)))
                if self.verbose: sys.stdout.write("\n")
                sys.stdout.flush()
            cnt = cnt + 1

            if change < lastCommitted:
                pass
            elif change == lastCommitted:
                # The previous abort may not have adjusted the user/date/etc
                details = self.repo0.describe(change)
                self.adjustUserDateDesc(details)
            else:
                details = self.repo0.describe(change)
                files = self.extractFilesFromCommit(details)
                self.commitChange(details, files)
                lastCommitted = change

    def importHeadRevision(self, revision):
        raise NotImplementedError( "Adapt to Perforce" )
        print "Doing initial import of %s from revision %s" % (' '.join(self.depotPaths), revision)

        details = {}
        details["user"] = "git perforce import user"
        details["desc"] = ("Initial import of %s from the state at revision %s\n"
                           % (' '.join(self.depotPaths), revision))
        details["change"] = revision
        newestRevision = 0

        fileCnt = 0
        fileArgs = ["%s...%s" % (p,revision) for p in self.depotPaths]

        for info in p4CmdList(["files"] + fileArgs):

            if 'code' in info and info['code'] == 'error':
                sys.stderr.write("p4 returned an error: %s\n"
                                 % info['data'])
                if info['data'].find("must refer to client") >= 0:
                    sys.stderr.write("This particular p4 error is misleading.\n")
                    sys.stderr.write("Perhaps the depot path was misspelled.\n");
                    sys.stderr.write("Depot path:  %s\n" % " ".join(self.depotPaths))
                sys.exit(1)
            if 'p4ExitCode' in info:
                sys.stderr.write("p4 exitcode: %s\n" % info['p4ExitCode'])
                sys.exit(1)

            change = int(info["change"])
            if change > newestRevision:
                newestRevision = change

            if info["action"] in self.delete_actions:
                # don't increase the file cnt, otherwise details["depotFile123"] will have gaps!
                #fileCnt = fileCnt + 1
                continue

            for prop in ["depotFile", "rev", "action", "type" ]:
                details["%s%s" % (prop, fileCnt)] = info[prop]

            fileCnt = fileCnt + 1

        details["change"] = newestRevision

        # Use time from top-most change so that all git p4 clones of
        # the same p4 repo have the same commit SHA1s.
        res = p4_describe(newestRevision)
        details["time"] = res["time"]

        self.updateOptionDict(details)
        try:
            self.commitChange(details, self.extractFilesFromCommit(details))
        except IOError:
            print "IO error with git fast-import. Is your git version recent enough?"
            print self.gitError.read()


    def run(self, args):
        if not len(args) == 2: die("exactly two arguments required")
        self.repo0_clientRoot, self.repo1_clientRoot = args
        self.changeRange = ""

        # TODO A mandatory option is a contradiction in terms
        if not self.repo0_clientRoot: die("Must supply --repo0-client-root")
        if not os.path.exists(self.repo0_clientRoot): die("--repo0-client-root must exist")
        self.repo0 = P4Repo(self.repo0_clientRoot)
        self.repo0.buildUserMap(cache_name="users")
        self.repo0.update_client_spec_path_cache()

        # TODO A mandatory option is a contradiction in terms
        if not self.repo1_clientRoot: die("Must supply --repo1-client-root")
        if not os.path.exists(self.repo1_clientRoot): die("--repo1-client-root must exist")
        self.repo1 = P4Repo(self.repo1_clientRoot)
        self.repo1.buildUserMap() # do not cached to disk, because we will change it

        # Sanity checks
        if self.repo0.info["serverAddress"] == self.repo1.info["serverAddress"]:
            die("repo0 and repo1 can't be the same server")
        if self.repo1.getClient()["LineEnd"] != "unix":
            die("repo1's client must have 'LineEnd: unix'")

        # TODO: should always look at previous commits,
        # merge with previous imports, if possible.
        p4Change = 0 # FIXME set to last-imported-change + 1
        if p4Change > 0:
            self.changeRange = "@%s,#head" % p4Change
            if not self.silent:
                print "Performing incremental import"

        revision = ""

        # TODO Make sure no revision specifiers are used when --changesfile
        # is specified.
        if not self.changesFile:
            # import the entire p4 tree, as per the clientspec, at the head revision
            # TODO specify a revision
            revision = "#head"

        self.tz = "%+03d%02d" % (- time.timezone / 3600, ((- time.timezone % 3600) / 60))

        if revision:
            self.importHeadRevision(revision)
        else:
            changes = []

            if len(self.changesFile) > 0:
                output = open(self.changesFile).readlines()
                changeSet = set()
                for line in output:
                    changeSet.add(int(line))

                for change in changeSet:
                    changes.append(change)

                changes.sort()
            else:
                raise NotImplementedError( "TODO A better way to get list of changes" )
                if self.verbose:
                    print "Getting p4 changes for %s...%s" % (', '.join(self.depotPaths),
                                                              self.changeRange)
                changes = p4ChangesForPaths(self.depotPaths, self.changeRange)

                if len(self.maxChanges) > 0:
                    changes = changes[:min(int(self.maxChanges), len(changes))]

            if len(changes) == 0:
                if not self.silent:
                    print "No changes to import!"
            else:
                self.updatedBranches = set()

                self.importChanges(changes)

                if not self.silent:
                    print ""
                    if len(self.updatedBranches) > 0:
                        sys.stdout.write("Updated branches: ")
                        for b in self.updatedBranches:
                            sys.stdout.write("%s " % b)
                        sys.stdout.write("\n")

        if self.importLabels:
            raise NotImplementedError( "TODO implement?" )
            p4Labels = getP4Labels(self.depotPaths)
            gitTags = getGitTags()

            missingP4Labels = p4Labels - gitTags
            self.importP4Labels(self.gitStream, missingP4Labels)

        return True

class P4Rebase(Command):
    def __init__(self):
        raise NotImplementedError( "Adapt to Perforce" )
        Command.__init__(self)
        self.options = [
                optparse.make_option("--import-labels", dest="importLabels", action="store_true"),
        ]
        self.importLabels = False
        self.description = ("Fetches the latest revision from perforce and "
                            + "rebases the current work (branch) against it")

    def run(self, args):
        sync = P4Sync()
        sync.importLabels = self.importLabels
        sync.run([])

        return self.rebase()

    def rebase(self):
        raise NotImplementedError( "Adapt to Perforce" )
        if os.system("git update-index --refresh") != 0:
            die("Some files in your working directory are modified and different than what is in your index. You can use git update-index <filename> to bring the index up-to-date or stash away all your changes with git stash.");
        if len(read_pipe("git diff-index HEAD --")) > 0:
            die("You have uncommitted changes. Please commit them before rebasing or stash them away with git stash.");

        [upstream, settings] = findUpstreamBranchPoint()
        if len(upstream) == 0:
            die("Cannot find upstream branchpoint for rebase")

        # the branchpoint may be p4/foo~3, so strip off the parent
        upstream = re.sub("~[0-9]+$", "", upstream)

        print "Rebasing the current branch onto %s" % upstream
        oldHead = read_pipe("git rev-parse HEAD").strip()
        system("git rebase %s" % upstream)
        system("git diff-tree --stat --summary -M %s HEAD" % oldHead)
        return True

class P4Clone(P4Sync):
    def __init__(self):
        raise NotImplementedError( "Adapt to Perforce" )
        P4Sync.__init__(self)
        self.description = "Creates a new git repository and imports from Perforce into it"
        self.usage = "usage: %prog [options] //depot/path[@revRange]"
        self.options += [
            optparse.make_option("--destination", dest="cloneDestination",
                                 action='store', default=None,
                                 help="where to leave result of the clone"),
            optparse.make_option("--bare", dest="cloneBare",
                                 action="store_true", default=False),
        ]
        self.cloneDestination = None
        self.cloneBare = False

    def defaultDestination(self, args):
        ## TODO: use common prefix of args?
        depotPath = args[0]
        depotDir = re.sub("(@[^@]*)$", "", depotPath)
        depotDir = re.sub("(#[^#]*)$", "", depotDir)
        depotDir = re.sub(r"\.\.\.$", "", depotDir)
        depotDir = re.sub(r"/$", "", depotDir)
        return os.path.split(depotDir)[1]

    def run(self, args):
        raise NotImplementedError( "Adapt to Perforce" )
        if len(args) < 1:
            return False

        depotPaths = args

        if not self.cloneDestination and len(depotPaths) > 1:
            self.cloneDestination = depotPaths[-1]
            depotPaths = depotPaths[:-1]

        for p in depotPaths:
            if not p.startswith("//"):
                sys.stderr.write('Depot paths must start with "//": %s\n' % p)
                return False

        if not self.cloneDestination:
            self.cloneDestination = self.defaultDestination(args)

        print "Importing from %s into %s" % (', '.join(depotPaths), self.cloneDestination)

        if not os.path.exists(self.cloneDestination):
            os.makedirs(self.cloneDestination)
        chdir(self.cloneDestination)

        init_cmd = [ "git", "init" ]
        if self.cloneBare:
            init_cmd.append("--bare")
        retcode = subprocess.call(init_cmd)
        if retcode:
            raise CalledProcessError(retcode, init_cmd)

        if not P4Sync.run(self, depotPaths):
            return False

        return True

class P4Branches(Command):
    def __init__(self):
        raise NotImplementedError( "Adapt to Perforce" )
        Command.__init__(self)
        self.options = [ ]
        self.description = ("Shows the git branches that hold imports and their "
                            + "corresponding perforce depot paths")
        self.verbose = False

    def run(self, args):
        raise NotImplementedError( "Adapt to Perforce" )
        if originP4BranchesExist():
            createOrUpdateBranchesFromOrigin()

        cmdline = "git rev-parse --symbolic "
        cmdline += " --remotes"

        for line in read_pipe_lines(cmdline):
            line = line.strip()

            if not line.startswith('p4/') or line == "p4/HEAD":
                continue
            branch = line

            log = extractLogMessageFromGitCommit("refs/remotes/%s" % branch)
            settings = extractSettingsGitLog(log)

            print "%s <= %s (%s)" % (branch, ",".join(settings["depot-paths"]), settings["change"])
        return True

class HelpFormatter(optparse.IndentedHelpFormatter):
    def __init__(self):
        optparse.IndentedHelpFormatter.__init__(self)

    def format_description(self, description):
        if description:
            return description + "\n"
        else:
            return ""

def printUsage(commands):
    print "usage: %s <command> [options]" % sys.argv[0]
    print ""
    print "valid commands: %s" % ", ".join(commands)
    print ""
    print "Try %s <command> --help for command specific help." % sys.argv[0]
    print ""

commands = {
    "debug" : P4Debug,
    "submit" : P4Submit,
    "commit" : P4Submit,
    "sync" : P4Sync,
    "rebase" : P4Rebase,
    "clone" : P4Clone,
    "rollback" : P4RollBack,
    "branches" : P4Branches
}


def main():
    if len(sys.argv[1:]) == 0:
        printUsage(commands.keys())
        sys.exit(2)

    cmdName = sys.argv[1]
    try:
        klass = commands[cmdName]
        cmd = klass()
    except KeyError:
        print "unknown command %s" % cmdName
        print ""
        printUsage(commands.keys())
        sys.exit(2)

    options = cmd.options
    args = sys.argv[2:]

    options.append(optparse.make_option("--verbose", "-v", dest="verbose", action="store_true"))
    parser = optparse.OptionParser(cmd.usage.replace("%prog", "%prog " + cmdName),
                                   options,
                                   description = cmd.description,
                                   formatter = HelpFormatter())

    (cmd, args) = parser.parse_args(sys.argv[2:], cmd);
    global verbose
    verbose = cmd.verbose

    if not cmd.run(args):
        parser.print_help()
        sys.exit(2)

if __name__ == '__main__':
    main()
