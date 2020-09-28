1. Download and install `MSYS2` package from [here](https://www.msys2.org/)

2. Run `MSYS2 MingW 64-bit` application to open the MSYS2 terminal.

3. Update MSYS2 package and dependency manager by running the following commands:

	```
	pacman -Syu --disable-download-timeout
	```

	NOTE: It is very likely MSYS2 will ask to close the window and repeat the command for furter updates. Check `MSYS2` web page for additional support.

4. Install GIT on MSYS2 by executing the following command:

	```
	pacman -S --disable-download-timeout --noconfirm git
	```

5. Clone repository with `git clone https://github.com/algorand/go-algorand`.

6. Switch to source code directory with `cd go-algorand`.

7. Run `./scripts/configure_dev.sh` to install required dependencies.

8. Run `make`.
