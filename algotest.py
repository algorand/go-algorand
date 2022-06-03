import algod_go as _go

PY_VERSION  = _go.PY_VERSION

print('''
==========================================================
        %s
==========================================================
''' % (PY_VERSION, ))

class Algod:
    '''Their demo put this class in a separate module, but I had
    trouble getting a module to import'''
    def __init__(self, bindir, datadir):
        self._v, self._libVers = _go.Algod_new(bindir, datadir)

    def Start(self):
        return self._v.start()

    def Stop(self):
        return self._v.stop()

    def Status(self):
        return self._v.status()


def main():
    node = Algod("/home/will/go/bin", "/home/will/nodes/testdir")
    node.Start()
    node.Status()
    node.Stop()

if __name__=="__main__":
    main()
