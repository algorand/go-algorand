[![Build Status](https://travis-ci.com/algorand/go-algorand.svg?token=25XP72ADqbCQJ3TJVC9S&branch=master)](https://travis-ci.com/algorand/go-algorand)

buildhost
====================

## Installing the build host ##

run the following on a fresh image:

```bash
git clone https://github.com/algorand/go-algorand
cd go-algorand/scripts/buildhost
sudo ./configure.sh
```

following that, configure the environment variables by typing
```bash
nano service_env.sh
```

and start the service
```bash
sudo systemctl start buildhost
```


